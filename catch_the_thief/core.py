"""The warden: classify every session, then decide what it may do."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Optional, Union

from . import consent
from .jaillog import JailLog
from .signals import SessionStore, Signal, beacon_signals, header_signals
from .webbotauth import Identity, KeyDirectory, verify_request

HUMAN, UNCERTAIN, SUSPECT, VERIFIED, PAROLED = "human", "uncertain", "suspect", "verified", "paroled"
ACTIONS = ("read", "write", "money", "human_only")

#: What each kind of session may do. "scope" = decided by the agent's parole papers.
DEFAULT_POLICY = {
    HUMAN:     {"read": "allow", "write": "allow", "money": "allow", "human_only": "allow"},
    UNCERTAIN: {"read": "allow", "write": "allow", "money": "hold",  "human_only": "deny"},
    SUSPECT:   {"read": "allow", "write": "deny",  "money": "hold",  "human_only": "deny"},
    VERIFIED:  {"read": "allow", "write": "deny",  "money": "hold",  "human_only": "deny"},
    PAROLED:   {"read": "scope", "write": "scope", "money": "scope", "human_only": "deny"},
}

LABELS = {
    HUMAN: "Human", UNCERTAIN: "Unverified (possibly automated)", SUSPECT: "Suspected AI agent",
    VERIFIED: "Verified agent, no customer consent", PAROLED: "Verified agent on parole",
}

STATIC = os.path.join(os.path.dirname(__file__), "static")


@dataclass
class Verdict:
    cls: str
    score: int
    signals: list
    sid: str
    identity: Optional[Identity] = None
    parole: Optional[consent.Parole] = None

    @property
    def label(self) -> str:
        if self.cls in (VERIFIED, PAROLED) and self.identity:
            return f"{LABELS[self.cls]}: {self.identity.agent}"
        return LABELS[self.cls]

    @property
    def agent(self) -> str:
        return self.identity.agent if self.identity and self.identity.ok else ""

    @property
    def customer(self) -> Optional[str]:
        """The customer an agent on parole acts for (None otherwise)."""
        return self.parole.customer if self.parole else None

    def as_dict(self) -> dict:
        return {"class": self.cls, "label": self.label, "score": self.score, "agent": self.agent,
                "customer": self.customer, "signals": [s.as_dict() for s in self.signals]}


@dataclass
class Decision:
    outcome: str          # allow | hold | deny
    action: str
    reason: str
    verdict: Verdict
    amount: Optional[float] = None
    parole_url: str = ""
    extra: dict = field(default_factory=dict)

    allowed = property(lambda self: self.outcome == "allow")
    held = property(lambda self: self.outcome == "hold")
    denied = property(lambda self: self.outcome == "deny")

    @property
    def status_code(self) -> int:
        return {"allow": 200, "hold": 202, "deny": 403}[self.outcome]

    def headers(self) -> dict:
        """Tell the agent, in machine-readable form, what happened and how to get out."""
        if self.allowed and self.verdict.cls == HUMAN:
            return {}
        val = f'{self.outcome}; class={self.verdict.cls}; reason="{self.reason}"'
        if self.parole_url and not self.allowed:
            val += f'; parole="{self.parole_url}"'
        return {"Agent-Jail": val}

    def as_dict(self) -> dict:
        return {"outcome": self.outcome, "action": self.action, "reason": self.reason, "amount": self.amount,
                "verdict": self.verdict.as_dict(), "parole": self.parole_url or None}


class Thief:
    """catch-the-thief. One instance per app.

        ctt = Thief(secret=..., agents=KeyDirectory())
        app = ctt.wrap(app)                        # or app.add_middleware(ctt.Middleware)
        decision = ctt.decide(request, "money", amount=500)
    """

    def __init__(self, secret: Union[str, bytes], agents: Optional[KeyDirectory] = None,
                 db: str = ":memory:", tarpit: float = 0.6, parole_url: str = "",
                 suspect_at: int = 50, uncertain_at: int = 25, policy: Optional[dict] = None,
                 confirm_over: Optional[float] = None, exempt: tuple = (),
                 cookie: str = "ctt_sid", secure_cookie: bool = False):
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.agents = agents or KeyDirectory()
        self.log = JailLog(db)
        self.sessions = SessionStore()
        self.tarpit = tarpit
        self.parole_url = parole_url
        self.suspect_at, self.uncertain_at = suspect_at, uncertain_at
        self.policy = {k: dict(v) for k, v in DEFAULT_POLICY.items()}
        for cls, rules in (policy or {}).items():
            self.policy.setdefault(cls, {}).update(rules)
        self.cookie, self.secure_cookie = cookie, secure_cookie
        # Step-up backstop: detection can be fooled, so money above this amount from any
        # session that hasn't *proved* who it is gets held for out-of-band confirmation.
        self.confirm_over = confirm_over
        self.exempt = tuple(exempt)
        self.revoked: set = set()
        self._booked: set = set()
        thief = self

        class Middleware(_Middleware):
            def __init__(self, app):
                super().__init__(app, thief)

        self.Middleware = Middleware

    # ----------------------------------------------------------- public API
    def wrap(self, app):
        return _Middleware(app, self)

    def issue_parole(self, *, customer: str, agent_keyid: str, scopes=("read",), limit: Optional[float] = None,
                     ttl: int = 30 * 24 * 3600) -> str:
        entry = self.agents.get(agent_keyid)
        name = entry[1] if entry else ""
        return consent.issue(self.secret, customer=customer, agent_keyid=agent_keyid, scopes=scopes,
                             limit=limit, ttl=ttl, agent_name=name)

    def revoke_parole(self, token: str) -> None:
        self.revoked.add(_token_id(token))

    def verdict(self, request) -> Verdict:
        v = _state(request.scope).get("ctt")
        if v is None:  # middleware not installed: classify statelessly
            v = self._classify(request.scope, None)
        return v

    def decide(self, request, action: str, amount: Optional[float] = None) -> Decision:
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        v = self.verdict(request)
        rule = self.policy.get(v.cls, {}).get(action, "deny")
        if rule == "scope":
            outcome, reason = self._parole_rule(v, action, amount)
        else:
            outcome, reason = rule, _reason(v, action, rule)
        if (action == "money" and outcome == "allow" and v.cls in (HUMAN, UNCERTAIN)
                and self.confirm_over is not None and (amount or 0) > self.confirm_over):
            outcome = "hold"
            reason = (f"Transfers over {self.confirm_over:,.0f} from an unverified session need confirmation "
                      f"on a second device")
        d = Decision(outcome, action, reason, v, amount, self.parole_url)
        if v.cls == HUMAN and outcome == "allow":
            self.log.humans_waved_through += 1
        else:
            scope = request.scope
            self.log.record(sid=v.sid, cls=v.cls, score=v.score, outcome=outcome, action=action,
                            method=scope.get("method", ""), path=scope.get("path", ""), amount=amount,
                            reason=reason, agent=v.agent, operator=v.identity.operator if v.identity else "",
                            ua=_header(scope, "user-agent"), signals=[s.as_dict() for s in v.signals])
        return d

    # ----------------------------------------------------------- internals
    def _parole_rule(self, v: Verdict, action: str, amount: Optional[float]) -> tuple:
        p = v.parole
        name = v.agent or "agent"
        if action == "read":
            return ("allow", f"{name} may read on parole") if p.allows("read") else \
                ("deny", f"{name}'s parole does not include reading")
        if action == "write":
            return ("allow", f"{name} may write on parole") if p.allows("write") else \
                ("deny", f"{name}'s parole does not include changes")
        if not p.allows("transfer"):
            return "hold", f"{name}'s parole does not include moving money: held for the customer"
        if p.limit is not None and (amount or 0) > p.limit:
            return "hold", f"{amount:,.2f} is over {name}'s parole limit of {p.limit:,.2f}: held for the customer"
        return "allow", f"{name} is on parole for transfers up to {p.limit:,.2f}" if p.limit is not None \
            else f"{name} is on parole for transfers"

    def _classify(self, scope: dict, st) -> Verdict:
        headers = _headers(scope)
        method = scope.get("method", "GET")
        path = scope.get("path", "/") + (("?" + scope["query_string"].decode()) if scope.get("query_string") else "")
        authority = headers.get("host", "")
        signals: list = []

        identity = verify_request(headers, method=method, path=path, authority=authority, directory=self.agents)
        if identity.declared and not identity.ok:
            signals.append(Signal("wba.invalid", 40, "Agent signature failed verification", identity.reason))

        parole = None
        token = headers.get("agent-consent")
        if token:
            try:
                p = consent.verify(self.secret, token)
                if _token_id(token) in self.revoked:
                    signals.append(Signal("consent.revoked", 45, "Presented revoked parole papers"))
                elif identity.ok and p.agent_keyid == identity.keyid:
                    parole = p
                else:
                    signals.append(Signal("consent.unbound", 50, "Parole papers belong to a different agent",
                                          "token not bound to the presenting key"))
            except consent.ConsentError as e:
                signals.append(Signal("consent.forged", 50, "Forged or expired parole papers", str(e)))

        signals += header_signals(headers, method)
        if st is not None:
            state_changing = method not in ("GET", "HEAD", "OPTIONS")
            signals += st.behaviour_signals(state_changing) + st.env + st.interaction

        # de-duplicate by code, keep the heaviest
        best: dict = {}
        for s in signals:
            if s.code not in best or s.weight > best[s.code].weight:
                best[s.code] = s
        signals = sorted(best.values(), key=lambda s: -s.weight)
        score = min(100, sum(s.weight for s in signals))

        if identity.ok:
            cls = PAROLED if parole else VERIFIED
        elif score >= self.suspect_at:
            cls = SUSPECT
        elif score >= self.uncertain_at:
            cls = UNCERTAIN
        else:
            cls = HUMAN
        return Verdict(cls, score, signals, st.sid if st else "-", identity, parole)

    def _maybe_book(self, v: Verdict, scope: dict, page: str = "") -> None:
        if v.cls == SUSPECT and v.sid not in self._booked and v.sid != "-":
            self._booked.add(v.sid)
            self.log.record(sid=v.sid, cls=v.cls, score=v.score, outcome="booked",
                            method="PAGE" if page else scope.get("method", ""),
                            path=page or scope.get("path", ""), reason="booked on arrival",
                            ua=_header(scope, "user-agent"), signals=[s.as_dict() for s in v.signals])

    def dashboard(self):
        from .dashboard import build_dashboard
        return build_dashboard(self)


def _reason(v: Verdict, action: str, outcome: str) -> str:
    who = {HUMAN: "Human session", UNCERTAIN: "Unverified session", SUSPECT: "Suspected AI agent",
           VERIFIED: f"Verified agent {v.agent} has no customer consent"}.get(v.cls, v.cls)
    if outcome == "allow":
        return f"{who}: {action} allowed" + (" (read-only jail, slowed down)" if v.cls == SUSPECT else "")
    if outcome == "hold":
        return f"{who}: money movement held until the account holder approves"
    if action == "human_only":
        return f"{who}: only a verified human can do this"
    return f"{who}: {action} blocked"


def _token_id(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()[:24]


def _headers(scope: dict) -> dict:
    out: dict = {}
    for k, v in scope.get("headers", []):
        k = k.decode("latin-1").lower()
        v = v.decode("latin-1")
        if k in out:
            out[k] += ("; " if k == "cookie" else ", ") + v
        else:
            out[k] = v
    return out


def _header(scope: dict, name: str) -> str:
    return _headers(scope).get(name, "")


def _state(scope: dict) -> dict:
    st = scope.get("state")
    if st is None:
        st = scope["state"] = {}
    return st


def _cookie(scope: dict, name: str) -> Optional[str]:
    raw = _header(scope, "cookie")
    if not raw:
        return None
    c = SimpleCookie()
    try:
        c.load(raw)
    except Exception:
        return None
    return c[name].value if name in c else None


class _Middleware:
    """Pure ASGI middleware: classifies every request, serves the beacon, tarpits suspects."""

    def __init__(self, app, thief: Thief):
        self.app, self.thief = app, thief
        with open(os.path.join(STATIC, "beacon.js"), "rb") as fh:
            self._beacon = fh.read()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        t = self.thief
        path, method = scope.get("path", ""), scope.get("method", "GET")

        if t.exempt and path.startswith(t.exempt):
            return await self.app(scope, receive, send)

        if path == "/_ctt/beacon.js":
            return await _respond(send, 200, self._beacon, "application/javascript",
                                  [(b"cache-control", b"public, max-age=300")])

        sid = _cookie(scope, t.cookie)
        new_sid = sid is None or len(sid) > 64
        if new_sid:
            sid = secrets.token_urlsafe(16)
        st = t.sessions.get(sid)
        cookie_hdr = []
        if new_sid:
            c = f"{t.cookie}={sid}; Path=/; HttpOnly; SameSite=Lax" + ("; Secure" if t.secure_cookie else "")
            cookie_hdr = [(b"set-cookie", c.encode())]

        if path == "/_ctt/b" and method == "POST":
            body = await _read_body(receive, 16_384)
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                envs, inter = beacon_signals(data)
                st.beacon_seen = True
                st.env = envs
                if data.get("k") == "submit":
                    st.interaction = inter
                t._maybe_book(t._classify(scope, st), scope, page=str(data.get("path") or "")[:200])
            return await _respond(send, 204, b"", "text/plain", cookie_hdr)

        st.times.append(time.time())
        st.last_ua = _header(scope, "user-agent")
        v = t._classify(scope, st)
        _state(scope)["ctt"] = v
        t._maybe_book(v, scope)
        if v.cls == SUSPECT and t.tarpit:
            await asyncio.sleep(t.tarpit)

        if not cookie_hdr:
            return await self.app(scope, receive, send)

        async def send_with_cookie(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + cookie_hdr
            await send(message)

        await self.app(scope, receive, send_with_cookie)


async def _read_body(receive, limit: int) -> bytes:
    chunks, size = [], 0
    while True:
        msg = await receive()
        if msg["type"] != "http.request":
            break
        chunk = msg.get("body", b"")
        size += len(chunk)
        if size <= limit:
            chunks.append(chunk)
        if not msg.get("more_body"):
            break
    return b"".join(chunks)


async def _respond(send, status: int, body: bytes, ctype: str, extra=()):
    headers = [(b"content-type", ctype.encode()), (b"content-length", str(len(body)).encode())] + list(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
