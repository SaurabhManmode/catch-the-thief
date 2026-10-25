"""Signals that a request is being made by software rather than a person.

None of these is proof on its own. Each signal carries a weight; the verdict
adds them up. The philosophy of catch-the-thief is that detection will never
be perfect, so the *policy* (what an unverified session may do) matters more
than any single signal.
"""
from __future__ import annotations

import re
import statistics
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Mapping, Optional


@dataclass(frozen=True)
class Signal:
    code: str        # stable identifier, e.g. "ua.automation"
    weight: int      # contribution to the 0-100 agent score
    charge: str      # human-readable "charge sheet" line
    detail: str = ""

    def as_dict(self) -> dict:
        return {"code": self.code, "weight": self.weight, "charge": self.charge, "detail": self.detail}


# --------------------------------------------------------------- user agents
AUTOMATION_UA = re.compile(r"HeadlessChrome|Playwright|Puppeteer|Selenium|PhantomJS|webdriver|Electron/.*Headless", re.I)
SCRIPT_UA = re.compile(
    r"^(python-requests|python-httpx|python-urllib|aiohttp|curl|wget|Go-http-client|node-fetch|undici|axios|"
    r"okhttp|Java/|libwww-perl|Ruby|PostmanRuntime|insomnia|httpie|Scrapy)", re.I)
AI_AGENT_UA = re.compile(
    r"ChatGPT-User|ChatGPT Agent|OAI-SearchBot|GPTBot|ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai|"
    r"Perplexity-User|PerplexityBot|Google-Extended|Amazonbot|Bytespider|Applebot-Extended|MistralAI-User|"
    r"cohere-ai|DuckAssistBot|Meta-ExternalAgent|YouBot", re.I)


def header_signals(headers: Mapping, method: str) -> list:
    """Signals visible in a single request's headers."""
    h = {k.lower(): v for k, v in headers.items()}
    ua = h.get("user-agent", "")
    out = []
    if not ua.strip():
        out.append(Signal("ua.missing", 35, "No user agent at all"))
    else:
        m = AI_AGENT_UA.search(ua)
        if m:
            out.append(Signal("ua.ai_agent", 60, "Declares itself an AI agent", m.group(0)))
        m = AUTOMATION_UA.search(ua)
        if m:
            out.append(Signal("ua.automation", 45, "Browser automation in user agent", m.group(0)))
        m = SCRIPT_UA.search(ua)
        if m:
            out.append(Signal("ua.script", 50, "Scripted HTTP client, not a browser", m.group(0)))

    looks_chromium = "Chrome/" in ua
    browserish = any(t in ua for t in ("Mozilla/", "Chrome/", "Safari/", "Firefox/"))
    ch = h.get("sec-ch-ua", "")
    if "Headless" in ch:
        out.append(Signal("hints.headless", 40, "Client hints reveal a headless browser", ch[:80]))
    elif looks_chromium and not ch and h.get("sec-fetch-site"):
        out.append(Signal("hints.missing", 15, "Claims Chrome but sends no client hints"))
    if browserish:
        if not h.get("accept-language"):
            out.append(Signal("hdr.no_lang", 15, "Browser without Accept-Language"))
        if not h.get("sec-fetch-mode") and ("Chrome/" in ua or "Firefox/" in ua):
            out.append(Signal("hdr.no_fetch_meta", 10, "Modern browser without Fetch Metadata"))
    return out


# --------------------------------------------------------------- beacon (in-page JS)
def beacon_signals(data: Mapping) -> tuple:
    """Turn a beacon payload into (environment signals, interaction signals)."""
    env = data.get("env") if isinstance(data.get("env"), Mapping) else {}
    envs, inter = [], []
    if env.get("webdriver"):
        envs.append(Signal("js.webdriver", 45, "navigator.webdriver is true"))
    if env.get("headlessUA"):
        envs.append(Signal("js.headless_ua", 35, "Page JS sees a headless browser"))
    if env.get("cdp"):
        envs.append(Signal("js.cdp", 25, "DevTools protocol is driving the page"))
    if env.get("zeroOuter"):
        envs.append(Signal("js.zero_window", 15, "Browser window has no size"))
    if env.get("langs") == 0:
        envs.append(Signal("js.no_langs", 10, "navigator.languages is empty"))

    if data.get("k") == "submit":
        keys, fills = int(data.get("keys") or 0), int(data.get("fills") or 0)
        moves, untrusted = int(data.get("moves") or 0), int(data.get("untrusted") or 0)
        dt = int(data.get("dt") or 0)
        if fills and not keys:
            inter.append(Signal("ix.no_keys", 30, "Form filled without a single keystroke",
                                f"{fills} field(s) filled"))
        if dt and dt < 2500:
            inter.append(Signal("ix.too_fast", 20, "Form completed inhumanly fast", f"{dt} ms after page load"))
        if moves < 3 and not data.get("touch"):
            inter.append(Signal("ix.no_mouse", 15, "Clicked without moving the mouse",
                                f"{moves} mouse event(s)"))
        if untrusted:
            inter.append(Signal("ix.synthetic", 35, "Synthetic (script-dispatched) input events",
                                f"{untrusted} event(s)"))
    return envs, inter


# --------------------------------------------------------------- per-session behaviour
@dataclass
class SessionState:
    sid: str
    first_seen: float = field(default_factory=time.time)
    times: deque = field(default_factory=lambda: deque(maxlen=40))
    env: list = field(default_factory=list)
    interaction: list = field(default_factory=list)
    beacon_seen: bool = False
    pages_seen: int = 0
    last_ua: str = ""

    def behaviour_signals(self, state_changing: bool) -> list:
        out = []
        t = list(self.times)
        if len(t) >= 6:
            gaps = [b - a for a, b in zip(t, t[1:])]
            mean = statistics.mean(gaps)
            if mean > 0 and statistics.pstdev(gaps) / mean < 0.15:
                out.append(Signal("bh.metronome", 20, "Machine-regular timing between requests",
                                  f"{len(gaps)} gaps, ~{mean * 1000:.0f} ms apart"))
            window = [x for x in t if x > t[-1] - 1.0]
            if len(window) > 6:
                out.append(Signal("bh.burst", 15, "Request burst faster than a person can click",
                                  f"{len(window)} requests in 1 s"))
        if state_changing and not self.beacon_seen:
            out.append(Signal("bh.no_js", 25, "Acted without ever running the page's JavaScript"))
        return out


class SessionStore:
    """Bounded in-memory LRU of session states. Swap for Redis in production."""

    def __init__(self, capacity: int = 10_000):
        self.capacity = capacity
        self._d: "OrderedDict[str, SessionState]" = OrderedDict()

    def get(self, sid: str) -> SessionState:
        st = self._d.get(sid)
        if st is None:
            st = SessionState(sid)
            self._d[sid] = st
            if len(self._d) > self.capacity:
                self._d.popitem(last=False)
        else:
            self._d.move_to_end(sid)
        return st

    def peek(self, sid: str) -> Optional[SessionState]:
        return self._d.get(sid)
