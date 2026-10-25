"""Parole papers: a customer's signed, scoped permission for one specific agent.

The point: an agent should never need the customer's password. Instead the
customer (logged in as a human) grants a token that

* names the customer it acts for,
* is bound to the agent's signing key (a stolen token is useless without it),
* lists what it may do ("read", "transfer") and a per-transfer limit,
* expires.

Format: ``ctt1.<base64url(json)>.<base64url(hmac-sha256)>``
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from .webbotauth import b64url, b64url_decode

PREFIX = "ctt1"


class ConsentError(ValueError):
    pass


@dataclass
class Parole:
    customer: str
    agent_keyid: str
    scopes: list = field(default_factory=list)
    limit: Optional[float] = None       # max amount per money action
    expires: int = 0
    agent_name: str = ""
    issued: int = 0

    def allows(self, scope: str) -> bool:
        return scope in self.scopes

    def to_dict(self) -> dict:
        return {"sub": self.customer, "kid": self.agent_keyid, "scp": self.scopes, "lim": self.limit,
                "exp": self.expires, "name": self.agent_name, "iat": self.issued}


def _mac(secret: bytes, body: str) -> str:
    return b64url(hmac.new(secret, f"{PREFIX}.{body}".encode(), hashlib.sha256).digest())


def issue(secret: bytes, *, customer: str, agent_keyid: str, scopes=("read",), limit: Optional[float] = None,
          ttl: int = 30 * 24 * 3600, agent_name: str = "") -> str:
    now = int(time.time())
    p = Parole(customer, agent_keyid, list(scopes), limit, now + ttl, agent_name, now)
    body = b64url(json.dumps(p.to_dict(), separators=(",", ":")).encode())
    return f"{PREFIX}.{body}.{_mac(secret, body)}"


def verify(secret: bytes, token: str, now: Optional[float] = None) -> Parole:
    try:
        prefix, body, mac = token.strip().split(".")
    except ValueError:
        raise ConsentError("malformed consent token")
    if prefix != PREFIX:
        raise ConsentError("unknown consent token version")
    if not hmac.compare_digest(mac, _mac(secret, body)):
        raise ConsentError("consent token signature invalid")
    try:
        d = json.loads(b64url_decode(body))
    except (ValueError, json.JSONDecodeError):
        raise ConsentError("consent token unreadable")
    now = time.time() if now is None else now
    if d.get("exp", 0) < now:
        raise ConsentError("consent token expired")
    return Parole(d["sub"], d["kid"], list(d.get("scp", [])), d.get("lim"), d["exp"], d.get("name", ""),
                  d.get("iat", 0))
