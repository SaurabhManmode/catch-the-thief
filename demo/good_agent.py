"""The good agent: "Budget Buddy" signs every request with its own key
(Web Bot Auth) and carries Alice's parole papers instead of her password.

    python -m demo.good_agent
    python -m demo.good_agent --stolen      # an impostor with stolen papers but the wrong key
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

import httpx

from catch_the_thief.webbotauth import generate_keypair, load_private_key, sign_request

HERE = os.path.dirname(__file__)


class SignedClient:
    def __init__(self, base: str, key, papers: str, name: str = "https://budgetbuddy.example"):
        self.base, self.key, self.papers, self.name = base.rstrip("/"), key, papers, name
        self.authority = urlparse(base).netloc
        self.http = httpx.Client(timeout=15)

    def request(self, method: str, path: str, **kw) -> httpx.Response:
        headers = sign_request(self.key, authority=self.authority, signature_agent=self.name,
                               method=method, path=path)
        headers.update({"Agent-Consent": self.papers, "User-Agent": "BudgetBuddy/1.0 (+https://budgetbuddy.example)"})
        return self.http.request(method, self.base + path, headers=headers, **kw)


def show(label: str, r: httpx.Response) -> None:
    body = r.json()
    d = body.get("decision", {})
    print(f"{label:<34} HTTP {r.status_code}  →  {d.get('outcome', body.get('status', '?')).upper():<5}  "
          f"{d.get('reason', body.get('error', ''))}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--stolen", action="store_true", help="use the papers with a different (unregistered) key")
    a = ap.parse_args(argv)

    with open(os.path.join(HERE, "agents", "budget-buddy.parole")) as fh:
        papers = fh.read().strip()
    if a.stolen:
        key = generate_keypair()
        print("🦹 impostor: Budget Buddy's parole papers, but signing with its own key\n")
    else:
        with open(os.path.join(HERE, "agents", "budget-buddy.key"), "rb") as fh:
            key = load_private_key(fh.read())
        print("🤖 Budget Buddy: signed requests + Alice's parole (read, transfer ≤ $100)\n")

    c = SignedClient(a.url, key, papers)
    r = c.request("GET", "/api/balance")
    show("check balance", r)
    if r.status_code == 200:
        print(f"{'':<34} balance: ${r.json()['balance']:,.2f}")
    show("pay $40 to Electric Co", c.request("POST", "/api/transfers", json={"to": "Electric Co", "amount": 40}))
    show("send $4,900 to Totally Legit Ltd",
         c.request("POST", "/api/transfers", json={"to": "Totally Legit Ltd", "amount": 4900}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
