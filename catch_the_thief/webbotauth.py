"""Web Bot Auth: cryptographic identity for AI agents.

Implements the subset of HTTP Message Signatures (RFC 9421) used by the
Web Bot Auth drafts (draft-meunier-web-bot-auth-architecture):

    Signature-Agent: "https://agent.example"
    Signature-Input: sig1=("@authority" "signature-agent");created=1700000000;
                     expires=1700000060;keyid="<JWK thumbprint>";alg="ed25519";
                     tag="web-bot-auth"
    Signature:       sig1=:<base64 Ed25519 signature>:

An agent that signs its requests this way can be *identified*. Whether it is
*allowed* to do anything is a separate question (see consent.py).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_VALIDITY = 24 * 3600   # reject signatures valid for longer than a day
CLOCK_SKEW = 30            # seconds of tolerated clock drift

_LABEL = re.compile(r'([a-z*][a-z0-9_.*-]*)=(\([^)]*\)[^,]*)')
_SIG = re.compile(r'([a-z*][a-z0-9_.*-]*)=:([A-Za-z0-9+/=]+):')
_PARAM = re.compile(r';([a-z][a-z0-9_.*-]*)=("(?:[^"\\]|\\.)*"|[^;]*)')


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ------------------------------------------------------------------ keys
def public_jwk(pub: Ed25519PublicKey) -> dict:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def thumbprint(pub: Ed25519PublicKey) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url). This is the keyid."""
    jwk = public_jwk(pub)
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x")}, separators=(",", ":"))
    return b64url(hashlib.sha256(canon.encode()).digest())


def key_from_jwk(jwk: Mapping) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 OKP keys are supported")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


class KeyDirectory:
    """Trusted agent keys, indexed by thumbprint.

    Load from a JWKS document (the format agents publish at
    /.well-known/http-message-signatures-directory) or add keys directly.
    """

    def __init__(self):
        self._keys: dict = {}

    def add(self, pub: Ed25519PublicKey, name: str, operator: str = "") -> str:
        kid = thumbprint(pub)
        self._keys[kid] = (pub, name, operator)
        return kid

    def add_jwks(self, jwks: Mapping, name: Optional[str] = None) -> list:
        kids = []
        for jwk in jwks.get("keys", []):
            kids.append(self.add(key_from_jwk(jwk), name or jwk.get("name") or jwks.get("name", "agent"),
                                 jwk.get("operator") or jwks.get("operator", "")))
        return kids

    def load_file(self, path: str) -> list:
        with open(path, encoding="utf-8") as fh:
            return self.add_jwks(json.load(fh))

    def get(self, kid: str):
        return self._keys.get(kid)

    def __len__(self):
        return len(self._keys)


# ------------------------------------------------------------------ signing (agent side)
def _component_value(name: str, method: str, path: str, authority: str, headers: Mapping) -> str:
    if name == "@authority":
        return authority.lower()
    if name == "@method":
        return method.upper()
    if name == "@path":
        return path.split("?", 1)[0] or "/"
    if name == "@query":
        return "?" + path.split("?", 1)[1] if "?" in path else "?"
    if name.startswith("@"):
        raise ValueError(f"unsupported derived component {name}")
    value = headers.get(name)
    if value is None:
        raise ValueError(f"covered header '{name}' missing")
    return " ".join(str(value).strip().split())


def signature_base(components: list, params: str, method: str, path: str, authority: str, headers: Mapping) -> str:
    lines = [f'"{c}": {_component_value(c, method, path, authority, headers)}' for c in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def sign_request(private_key: Ed25519PrivateKey, *, authority: str, signature_agent: str,
                 method: str = "GET", path: str = "/", components=("@authority", "signature-agent"),
                 created: Optional[int] = None, ttl: int = 60, label: str = "sig1",
                 extra_headers: Optional[Mapping] = None) -> dict:
    """Return the three headers an agent adds to a signed request."""
    created = int(created if created is not None else time.time())
    kid = thumbprint(private_key.public_key())
    comp_list = " ".join(f'"{c}"' for c in components)
    params = (f'({comp_list});created={created};expires={created + ttl};keyid="{kid}";'
              f'alg="ed25519";tag="web-bot-auth"')
    sa = f'"{signature_agent}"'
    headers = {k.lower(): v for k, v in (extra_headers or {}).items()}
    headers["signature-agent"] = sa
    base = signature_base(list(components), params, method, path, authority, headers)
    sig = base64.b64encode(private_key.sign(base.encode())).decode()
    return {"Signature-Agent": sa, "Signature-Input": f"{label}={params}", "Signature": f"{label}=:{sig}:"}


# ------------------------------------------------------------------ verification (server side)
@dataclass
class Identity:
    ok: bool
    reason: str
    keyid: str = ""
    agent: str = ""            # display name from the key directory
    operator: str = ""
    signature_agent: str = ""  # what the agent *claims* to be
    declared: bool = False     # did the request carry Web Bot Auth headers at all?


def _params(raw: str) -> tuple:
    m = re.match(r'\(([^)]*)\)(.*)$', raw.strip())
    if not m:
        raise ValueError("malformed Signature-Input")
    comps = re.findall(r'"([^"]+)"', m.group(1))
    params = {}
    for key, val in _PARAM.findall(m.group(2)):
        val = val.strip()
        params[key] = val[1:-1] if val.startswith('"') else val
    return comps, params


def verify_request(headers: Mapping, *, method: str, path: str, authority: str,
                   directory: KeyDirectory, now: Optional[float] = None) -> Identity:
    h = {k.lower(): v for k, v in headers.items()}
    sig_input, sig_header = h.get("signature-input"), h.get("signature")
    sa = (h.get("signature-agent") or "").strip().strip('"')
    if not sig_input or not sig_header:
        return Identity(False, "no signature", signature_agent=sa, declared=bool(sa))

    sigs = dict(_SIG.findall(sig_header))
    labels = _LABEL.findall(sig_input)
    # prefer a label explicitly tagged for web bot auth
    labels.sort(key=lambda kv: 'tag="web-bot-auth"' not in kv[1])
    now = time.time() if now is None else now
    last = Identity(False, "no usable signature", signature_agent=sa, declared=True)

    for label, raw in labels:
        if label not in sigs:
            continue
        try:
            comps, p = _params(raw)
        except ValueError as e:
            last = Identity(False, str(e), signature_agent=sa, declared=True)
            continue
        kid = p.get("keyid", "")
        ident = Identity(False, "", keyid=kid, signature_agent=sa, declared=True)
        if p.get("alg", "ed25519") != "ed25519":
            ident.reason = f"unsupported alg {p.get('alg')}"
            last = ident
            continue
        try:
            created, expires = int(p.get("created", "0")), int(p.get("expires", "0"))
        except ValueError:
            ident.reason = "bad created/expires"
            last = ident
            continue
        if not expires or expires < now - CLOCK_SKEW:
            ident.reason = "signature expired"
        elif created > now + CLOCK_SKEW:
            ident.reason = "signature from the future"
        elif expires - created > MAX_VALIDITY:
            ident.reason = "signature validity window too long"
        if ident.reason:
            last = ident
            continue
        entry = directory.get(kid)
        if entry is None:
            ident.reason = "unknown signing key"
            last = ident
            continue
        pub, name, operator = entry
        try:
            base = signature_base(comps, raw[raw.index("("):], method, path, authority, h)
            pub.verify(base64.b64decode(sigs[label]), base.encode())
        except (ValueError, InvalidSignature) as e:
            ident.reason = "bad signature" if isinstance(e, InvalidSignature) else str(e)
            last = ident
            continue
        return Identity(True, "verified", keyid=kid, agent=name, operator=operator,
                        signature_agent=sa, declared=True)
    return last


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key
