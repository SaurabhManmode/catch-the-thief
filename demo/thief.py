"""The thief: an AI-style browser agent that logs in with the customer's own
password and tries to move money. Exactly the pattern banks reported in
October 2026.

    python -m demo.thief                     # plain headless agent
    python -m demo.thief --disguise 1        # spoofed user agent, webdriver flag hidden
    python -m demo.thief --disguise 2        # ...and types slowly, moves the mouse like a person

Requires: pip install playwright && playwright install chromium
"""
from __future__ import annotations

import argparse
import random
import re
import sys

from playwright.sync_api import sync_playwright

REAL_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/141.0.0.0 Safari/537.36")
HINTS = '"Google Chrome";v="141", "Chromium";v="141", "Not?A_Brand";v="24"'


def say(msg: str) -> None:
    print(msg, flush=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--to", default="Totally Legit Ltd")
    ap.add_argument("--amount", default="4900")
    ap.add_argument("--disguise", type=int, choices=[0, 1, 2], default=0)
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--slow", type=int, default=0, help="slow-mo ms, for recording")
    ap.add_argument("--video", help="record a video into this folder")
    ap.add_argument("--executable", help="path to a Chromium binary")
    a = ap.parse_args(argv)

    jail = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not a.headed, slow_mo=a.slow or None,
                                    executable_path=a.executable or None)
        kw = {"viewport": {"width": 760, "height": 820}}
        if a.video:
            kw.update(record_video_dir=a.video, record_video_size={"width": 760, "height": 820})
        if a.disguise:
            kw.update(user_agent=REAL_UA, locale="en-US",
                      extra_http_headers={"sec-ch-ua": HINTS, "Accept-Language": "en-US,en;q=0.9"})
        ctx = browser.new_context(**kw)
        if a.disguise:
            ctx.add_init_script("Object.defineProperty(Navigator.prototype,'webdriver',{get:()=>undefined})")
        page = ctx.new_page()
        page.on("response", lambda r: jail.update(last=r.headers.get("agent-jail")) if r.headers.get("agent-jail") else None)

        def enter(selector: str, text: str) -> None:
            if a.disguise >= 2:
                box = page.locator(selector).bounding_box()
                for _ in range(6):
                    page.mouse.move(box["x"] + random.uniform(5, box["width"] - 5),
                                    box["y"] + random.uniform(3, box["height"] - 3), steps=8)
                page.click(selector)
                page.keyboard.type(text, delay=random.randint(90, 160))
            else:
                page.fill(selector, text)

        def press(selector: str) -> None:
            if a.disguise >= 2:
                page.wait_for_timeout(1200)
                box = page.locator(selector).bounding_box()
                page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=15)
            page.click(selector)

        say(f"🕵️  thief agent (disguise level {a.disguise}) heading to {a.url}")
        page.goto(a.url + "/login")
        say("🔑 logging in with the customer's own password…")
        enter("#u", "alice")
        enter("#p", "wonderland")
        press("#signin")
        page.wait_for_url(re.compile(r".*/account"))
        bal = page.text_content("#balance")
        say(f"👀 got in. balance is {bal}")

        say(f"💸 trying to send ${a.amount} to {a.to}…")
        enter("#to", a.to)
        enter("#amount", a.amount)
        press("#send")
        page.wait_for_selector("#result")
        title = page.text_content("#result h2").strip()
        say(f"📄 bank says: {title}")
        verdict = jail.get("last") or "no jail header (treated as a human)"
        say(f"🚨 Agent-Jail: {verdict}")
        if a.slow:
            page.wait_for_timeout(2500)
        ctx.close()
        browser.close()
    header = jail.get("last") or ""
    detected = "class=suspect" in header or "class=uncertain" in header
    held = "on hold" in title
    if detected and held:
        say("⛓️  CAUGHT: identified as an agent, money did not move.")
    elif held:
        say("🛑 NOT DETECTED, but the step-up rule held the money for confirmation on a second device.")
    else:
        say("😬 got through: this disguise beat every layer.")
    return 0 if held else 2


if __name__ == "__main__":
    sys.exit(main())
