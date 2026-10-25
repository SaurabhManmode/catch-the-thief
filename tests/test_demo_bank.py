"""End-to-end tests against the Bank of Nowhere demo (no browser needed)."""
import importlib
import os
import unittest

from starlette.testclient import TestClient

from catch_the_thief.webbotauth import generate_keypair, load_private_key, sign_request

os.environ["CTT_TARPIT"] = "0"
HERE = os.path.join(os.path.dirname(__file__), "..", "demo", "agents")
CHROME = {"User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
          "Accept-Language": "en", "sec-ch-ua": '"Google Chrome";v="141"', "sec-fetch-mode": "navigate",
          "sec-fetch-site": "same-origin"}


class Bank(unittest.TestCase):
    def setUp(self):
        import demo.bank
        self.bank = importlib.reload(demo.bank)
        self.c = TestClient(self.bank.app, base_url="http://testserver", follow_redirects=False)
        with open(os.path.join(HERE, "budget-buddy.key"), "rb") as fh:
            self.key = load_private_key(fh.read())
        with open(os.path.join(HERE, "budget-buddy.parole")) as fh:
            self.papers = fh.read().strip()

    def login(self, headers):
        self.c.get("/login", headers=headers)
        r = self.c.post("/login", data={"username": "alice", "password": "wonderland"}, headers=headers)
        self.assertEqual(r.status_code, 303)
        return r

    def human_beacon(self, headers):
        self.c.post("/_ctt/b", json={"k": "submit", "env": {}, "keys": 12, "moves": 40, "dt": 8000},
                    headers=headers)

    def balance(self):
        return self.bank.CUSTOMERS["alice"]["balance"]

    def test_human_sends_money(self):
        self.login(CHROME)
        self.human_beacon(CHROME)
        r = self.c.post("/transfer", data={"to": "Mum", "amount": "50"}, headers=CHROME)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Sent $50.00", r.text)
        self.assertEqual(self.balance(), 12430.0)

    def test_large_human_transfer_needs_step_up(self):
        self.login(CHROME)
        self.human_beacon(CHROME)
        r = self.c.post("/transfer", data={"to": "Car dealer", "amount": "9000"}, headers=CHROME)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(self.balance(), 12480.0)
        held = self.bank.CUSTOMERS["alice"]["held"][0]
        r = self.c.post(f"/held/{held['id']}/approve", headers=CHROME)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.balance(), 3480.0)

    def test_headless_thief_is_jailed(self):
        ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/141.0.0.0 Safari/537.36"}
        self.login(ua)
        self.c.post("/_ctt/b", json={"k": "submit", "env": {"webdriver": True}, "fills": 2, "dt": 600}, headers=ua)
        r = self.c.post("/transfer", data={"to": "Totally Legit Ltd", "amount": "4900"}, headers=ua)
        self.assertEqual(r.status_code, 202)
        self.assertIn("class=suspect", r.headers["agent-jail"])
        self.assertEqual(self.balance(), 12480.0)
        held = self.bank.CUSTOMERS["alice"]["held"][0]
        self.assertEqual(self.c.post(f"/held/{held['id']}/approve", headers=ua).status_code, 403)
        self.assertEqual(self.c.post("/agents/grant", data={"kid": "x"}, headers=ua).status_code, 403)
        dash = self.c.get("/jail/api").json()
        self.assertEqual(dash["stats"]["inmates"], 1)
        self.assertEqual(dash["stats"]["held_total"], 4900)

    def test_signed_agent_on_parole(self):
        def call(method, path, **kw):
            h = sign_request(self.key, authority="testserver", signature_agent="https://budgetbuddy.example")
            h["Agent-Consent"] = self.papers
            return self.c.request(method, path, headers=h, **kw)

        r = call("GET", "/api/balance")
        self.assertEqual((r.status_code, r.json()["customer"]), (200, "alice"))
        r = call("POST", "/api/transfers", json={"to": "Electric Co", "amount": 40})
        self.assertEqual(r.json()["status"], "sent")
        r = call("POST", "/api/transfers", json={"to": "Totally Legit Ltd", "amount": 4900})
        self.assertEqual((r.status_code, r.json()["status"]), (202, "hold"))
        self.assertEqual(self.balance(), 12440.0)
        self.assertEqual(self.c.get("/jail/api").json()["visitors"][0]["agent"], "Budget Buddy")

    def test_impostor_with_stolen_papers(self):
        h = sign_request(generate_keypair(), authority="testserver", signature_agent="https://budgetbuddy.example")
        h["Agent-Consent"] = self.papers
        r = self.c.get("/api/balance", headers=h)
        self.assertEqual(r.status_code, 401)
        charges = {c["code"] for c in self.c.get("/jail/api").json()["inmates"][0]["charges"]}
        self.assertIn("consent.unbound", charges)

    def test_human_can_grant_parole(self):
        self.login(CHROME)
        self.human_beacon(CHROME)
        kid = next(iter(self.bank.agents._keys))
        r = self.c.post("/agents/grant", data={"kid": kid, "scopes": ["read"], "limit": "20"}, headers=CHROME)
        self.assertEqual(r.status_code, 200)
        self.assertIn("ctt1.", r.text)

    def test_dashboard_page(self):
        r = self.c.get("/jail/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("CATCH", r.text)


if __name__ == "__main__":
    unittest.main()
