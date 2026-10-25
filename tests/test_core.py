import time
import unittest

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from catch_the_thief import KeyDirectory, Thief, consent, generate_keypair, sign_request, verify_request
from catch_the_thief.signals import beacon_signals, header_signals

CHROME = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/141.0.0.0 Safari/537.36")
HUMAN_HEADERS = {"User-Agent": CHROME, "Accept-Language": "en-US", "sec-ch-ua": '"Google Chrome";v="141"',
                 "sec-fetch-mode": "navigate", "sec-fetch-site": "same-origin"}


def codes(signals):
    return {s.code for s in signals}


class WebBotAuth(unittest.TestCase):
    def setUp(self):
        self.key = generate_keypair()
        self.dir = KeyDirectory()
        self.kid = self.dir.add(self.key.public_key(), "Buddy", "buddy.example")

    def verify(self, headers, authority="bank.test", method="GET", path="/"):
        return verify_request(headers, method=method, path=path, authority=authority, directory=self.dir)

    def test_roundtrip(self):
        h = sign_request(self.key, authority="bank.test", signature_agent="https://buddy.example")
        r = self.verify(h)
        self.assertTrue(r.ok)
        self.assertEqual((r.agent, r.keyid), ("Buddy", self.kid))

    def test_wrong_host_is_rejected(self):
        h = sign_request(self.key, authority="bank.test", signature_agent="https://buddy.example")
        self.assertEqual(self.verify(h, authority="evil.test").reason, "bad signature")

    def test_tampered_agent_header(self):
        h = sign_request(self.key, authority="bank.test", signature_agent="https://buddy.example")
        h["Signature-Agent"] = '"https://someone-else.example"'
        self.assertFalse(self.verify(h).ok)

    def test_method_and_path_components(self):
        h = sign_request(self.key, authority="bank.test", signature_agent="x", method="POST", path="/pay",
                         components=("@authority", "@method", "@path", "signature-agent"))
        self.assertTrue(self.verify(h, method="POST", path="/pay").ok)
        self.assertFalse(self.verify(h, method="POST", path="/steal").ok)

    def test_time_checks(self):
        old = sign_request(self.key, authority="bank.test", signature_agent="x", created=int(time.time()) - 900)
        self.assertEqual(self.verify(old).reason, "signature expired")
        future = sign_request(self.key, authority="bank.test", signature_agent="x", created=int(time.time()) + 900)
        self.assertEqual(self.verify(future).reason, "signature from the future")
        long = sign_request(self.key, authority="bank.test", signature_agent="x", ttl=7 * 86400)
        self.assertEqual(self.verify(long).reason, "signature validity window too long")

    def test_unknown_key_and_missing(self):
        other = generate_keypair()
        h = sign_request(other, authority="bank.test", signature_agent="x")
        self.assertEqual(self.verify(h).reason, "unknown signing key")
        r = self.verify({"Signature-Agent": '"x"'})
        self.assertFalse(r.ok)
        self.assertTrue(r.declared)

    def test_jwks_loading(self):
        from catch_the_thief.webbotauth import public_jwk
        d = KeyDirectory()
        kids = d.add_jwks({"name": "J", "keys": [public_jwk(self.key.public_key())]})
        self.assertEqual(kids, [self.kid])


class Consent(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        t = consent.issue(b"k", customer="alice", agent_keyid="kid", scopes=["read", "transfer"], limit=50)
        p = consent.verify(b"k", t)
        self.assertEqual((p.customer, p.limit), ("alice", 50))
        self.assertTrue(p.allows("transfer"))
        with self.assertRaises(consent.ConsentError):
            consent.verify(b"other", t)
        head, body, mac = t.split(".")
        with self.assertRaises(consent.ConsentError):
            consent.verify(b"k", f"{head}.{body}x.{mac}")

    def test_expired(self):
        t = consent.issue(b"k", customer="a", agent_keyid="kid", ttl=-5)
        with self.assertRaises(consent.ConsentError):
            consent.verify(b"k", t)


class Signals(unittest.TestCase):
    def test_header_signals(self):
        self.assertIn("ua.script", codes(header_signals({"User-Agent": "curl/8.5.0"}, "GET")))
        self.assertIn("ua.automation", codes(header_signals({"User-Agent": CHROME.replace("Chrome", "HeadlessChrome")}, "GET")))
        self.assertIn("ua.ai_agent", codes(header_signals({"User-Agent": "Mozilla/5.0 ChatGPT-User/1.0"}, "GET")))
        self.assertIn("ua.missing", codes(header_signals({}, "GET")))
        self.assertEqual(header_signals(HUMAN_HEADERS, "GET"), [])

    def test_beacon_signals(self):
        env, inter = beacon_signals({"k": "submit", "env": {"webdriver": True}, "keys": 0, "fills": 2,
                                     "moves": 0, "dt": 900})
        self.assertEqual(codes(env), {"js.webdriver"})
        self.assertEqual(codes(inter), {"ix.no_keys", "ix.too_fast", "ix.no_mouse"})
        env, inter = beacon_signals({"k": "submit", "env": {}, "keys": 14, "fills": 0, "moves": 80, "dt": 9000})
        self.assertEqual((env, inter), ([], []))
        _, inter = beacon_signals({"k": "submit", "env": {}, "keys": 5, "moves": 0, "touch": 3, "dt": 9000})
        self.assertEqual(inter, [])  # touch devices don't need a mouse


def make_app(thief: Thief):
    def handler(action):
        async def h(request: Request):
            amount = float(request.query_params.get("amount", 0)) or None
            d = thief.decide(request, action, amount)
            return JSONResponse(d.as_dict(), d.status_code, headers=d.headers())
        return h
    routes = [Route(f"/{a}", handler(a), methods=["GET", "POST"]) for a in ("read", "write", "money", "human_only")]
    return thief.wrap(Starlette(routes=routes))


class Policy(unittest.TestCase):
    def setUp(self):
        self.key = generate_keypair()
        self.agents = KeyDirectory()
        self.kid = self.agents.add(self.key.public_key(), "Buddy", "buddy.example")
        self.t = Thief(secret="s3cret", agents=self.agents, tarpit=0, parole_url="/agents", confirm_over=1000)
        self.c = TestClient(make_app(self.t), base_url="http://bank.test")

    def signed(self, method="GET", papers=None, key=None):
        h = sign_request(key or self.key, authority="bank.test", signature_agent="https://buddy.example")
        if papers:
            h["Agent-Consent"] = papers
        return h

    def outcome(self, path, headers=None, method="POST", **params):
        r = self.c.request(method, path, headers=headers or HUMAN_HEADERS, params=params)
        return r.json()["outcome"], r.json()["verdict"]["class"], r

    def test_human_allowed_and_step_up(self):
        self.c.get("/read", headers=HUMAN_HEADERS)  # page view runs no JS in tests: mark beacon seen
        self.c.post("/_ctt/b", json={"k": "load", "env": {}}, headers=HUMAN_HEADERS)
        self.assertEqual(self.outcome("/money", amount=200)[:2], ("allow", "human"))
        self.assertEqual(self.outcome("/money", amount=5000)[:2], ("hold", "human"))

    def test_scripted_client_is_jailed(self):
        h = {"User-Agent": "python-requests/2.32"}
        self.assertEqual(self.outcome("/read", h, "GET")[:2], ("allow", "suspect"))
        self.assertEqual(self.outcome("/write", h)[:2], ("deny", "suspect"))
        o, cls, r = self.outcome("/money", h, amount=10)
        self.assertEqual((o, cls, r.status_code), ("hold", "suspect", 202))
        self.assertIn('parole="/agents"', r.headers["agent-jail"])
        self.assertEqual(self.outcome("/human_only", h)[0], "deny")

    def test_webdriver_beacon_jails_a_browser(self):
        self.c.post("/_ctt/b", json={"k": "load", "env": {"webdriver": True, "headlessUA": True}},
                    headers=HUMAN_HEADERS)
        self.assertEqual(self.outcome("/money", amount=5)[:2], ("hold", "suspect"))
        summary = self.t.log.summary()
        self.assertEqual(summary["stats"]["inmates"], 1)
        self.assertIn("js.webdriver", {c["code"] for c in summary["inmates"][0]["charges"]})

    def test_verified_without_consent(self):
        self.assertEqual(self.outcome("/read", self.signed(), "GET")[:2], ("allow", "verified"))
        self.assertEqual(self.outcome("/money", self.signed(), amount=5)[:2], ("hold", "verified"))

    def test_parole_scopes_and_limit(self):
        papers = self.t.issue_parole(customer="alice", agent_keyid=self.kid, scopes=["read", "transfer"], limit=100)
        self.assertEqual(self.outcome("/money", self.signed(papers=papers), amount=40)[:2], ("allow", "paroled"))
        self.assertEqual(self.outcome("/money", self.signed(papers=papers), amount=400)[:2], ("hold", "paroled"))
        self.assertEqual(self.outcome("/write", self.signed(papers=papers))[0], "deny")
        self.assertEqual(self.outcome("/human_only", self.signed(papers=papers))[0], "deny")

    def test_stolen_and_revoked_papers(self):
        papers = self.t.issue_parole(customer="alice", agent_keyid=self.kid, scopes=["transfer"], limit=100)
        thief_key = generate_keypair()
        o, cls, r = self.outcome("/money", self.signed(papers=papers, key=thief_key), amount=40)
        self.assertEqual((o, cls), ("hold", "suspect"))
        self.t.revoke_parole(papers)
        o, cls, _ = self.outcome("/money", self.signed(papers=papers), amount=40)
        self.assertNotEqual(cls, "paroled")
        self.assertEqual(o, "hold")

    def test_forged_papers(self):
        forged = consent.issue(b"not-the-bank", customer="alice", agent_keyid=self.kid, scopes=["transfer"])
        self.assertEqual(self.outcome("/money", self.signed(papers=forged), amount=40)[0], "hold")

    def test_metronome_and_no_js(self):
        h = dict(HUMAN_HEADERS)
        for _ in range(7):
            self.c.get("/read", headers=h)
            time.sleep(0.05)
        o, cls, r = self.outcome("/write", h)
        self.assertIn("bh.no_js", {s["code"] for s in r.json()["verdict"]["signals"]})

    def test_custom_policy(self):
        t = Thief(secret="x", tarpit=0, policy={"suspect": {"read": "deny"}})
        c = TestClient(make_app(t))
        self.assertEqual(c.get("/read", headers={"User-Agent": "curl/8"}).status_code, 403)

    def test_beacon_js_served(self):
        r = self.c.get("/_ctt/beacon.js")
        self.assertEqual(r.status_code, 200)
        self.assertIn("webdriver", r.text)


if __name__ == "__main__":
    unittest.main()
