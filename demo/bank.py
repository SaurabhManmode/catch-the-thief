"""Bank of Nowhere: a deliberately fictional demo bank protected by catch-the-thief.

    pip install -e ".[demo]"
    uvicorn demo.bank:app --port 8000
    open http://localhost:8000        (login: alice / wonderland)
    open http://localhost:8000/jail   (the jail dashboard)
"""
from __future__ import annotations

import glob
import itertools
import os
import secrets
import time

from jinja2 import DictLoader, Environment, select_autoescape
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

from catch_the_thief import KeyDirectory, Thief

HERE = os.path.dirname(__file__)

# ------------------------------------------------------------------ the warden
agents = KeyDirectory()
for path in glob.glob(os.path.join(HERE, "agents", "*.jwks.json")):
    agents.load_file(path)

ctt = Thief(secret=os.environ.get("CTT_SECRET", secrets.token_hex(32)), agents=agents,
            db=os.environ.get("CTT_DB", ":memory:"), parole_url="/agents",
            confirm_over=2500, exempt=("/jail",),
            tarpit=float(os.environ.get("CTT_TARPIT", "0.6")))

# ------------------------------------------------------------------ fake data
ids = itertools.count(1)
CUSTOMERS = {
    "alice": {"password": "wonderland", "name": "Alice Example", "balance": 12480.00, "held": [], "paroles": [],
              "tx": [{"ts": time.time() - 86400 * d, "desc": desc, "amount": amt} for d, desc, amt in
                     [(1, "Coffee Republic", -4.60), (2, "Salary · Nowhere Corp", 5200.00),
                      (3, "Rent · Flat 4B", -1650.00), (5, "Grocer & Sons", -82.35)]]},
}
SESSIONS: dict = {}


def demo_parole() -> str:
    """Issue Alice's demo parole for Budget Buddy (in real life she grants it on /agents)."""
    kid = next(iter(agents._keys), None)
    if not kid:
        return ""
    token = ctt.issue_parole(customer="alice", agent_keyid=kid, scopes=["read", "transfer"], limit=100)
    CUSTOMERS["alice"]["paroles"].append({"agent": agents.get(kid)[1], "scopes": ["read", "transfer"],
                                          "limit": 100, "token": token, "ts": time.time()})
    with open(os.path.join(HERE, "agents", "budget-buddy.parole"), "w") as fh:
        fh.write(token)
    return token


demo_parole()

# ------------------------------------------------------------------ templates
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · Bank of Nowhere</title>
<style>
:root{--ink:#14213d;--mute:#6b7280;--bg:#f4f1ea;--card:#fff;--brand:#2f5d50;--brand2:#e9f2ee;--line:#e5e1d8;--amber:#b45309;--amberbg:#fff7e6;--red:#b91c1c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.demo{background:var(--ink);color:#f4f1ea;text-align:center;font-size:12px;padding:5px;letter-spacing:.04em}
nav{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;background:var(--card);border-bottom:1px solid var(--line)}
.logo{font-weight:800;font-size:18px;color:var(--brand);display:flex;gap:8px;align-items:center}
.logo i{width:26px;height:26px;border-radius:7px;background:var(--brand);display:inline-block;position:relative}
.logo i:after{content:"";position:absolute;inset:7px;border:2px solid #fff;border-radius:50%}
nav a{color:var(--mute);text-decoration:none;margin-left:16px;font-size:14px}
main{max-width:860px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0 0 12px}
.bal{font-size:38px;font-weight:800;letter-spacing:-.02em}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
label{display:block;font-size:13px;color:var(--mute);margin:10px 0 4px}
input,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;font:inherit;background:#fff}
button{margin-top:14px;background:var(--brand);color:#fff;border:0;border-radius:9px;padding:10px 16px;font:inherit;font-weight:700;cursor:pointer}
button.ghost{background:#fff;color:var(--ink);border:1px solid var(--line)}
button.small{margin:0;padding:6px 10px;font-size:13px}
.tx{display:flex;justify-content:space-between;padding:8px 0;border-top:1px solid var(--line)}.tx:first-child{border-top:0}
.neg{color:var(--ink)}.pos{color:var(--brand)}.mute{color:var(--mute);font-size:13px}
.alert{border-radius:14px;padding:18px 20px;margin-bottom:16px;border:1px solid}
.alert.hold{background:var(--amberbg);border-color:#f5c26b;color:#5b3200}
.alert.ok{background:var(--brand2);border-color:#b7d6ca}
.alert.deny{background:#fef2f2;border-color:#fecaca;color:var(--red)}
.alert h2{margin-bottom:6px;font-size:18px}
.held{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-top:1px solid var(--line)}
.held:first-of-type{border-top:0}
code{background:#f3f0e8;padding:2px 6px;border-radius:6px;font-size:12px;word-break:break-all}
@media (max-width:700px){.grid{grid-template-columns:1fr}}
</style><script src="/_ctt/beacon.js" defer></script></head><body>
<div class="demo">DEMO · Bank of Nowhere is fictional · protected by catch-the-thief</div>
<nav><div class="logo"><i></i>Bank of Nowhere</div><div>{% if user %}<a href="/account">Account</a><a href="/agents">Connected agents</a><a href="/logout">Log out</a>{% endif %}</div></nav>
<main>{% block body %}{% endblock %}</main></body></html>"""

LOGIN = """{% extends "base" %}{% block body %}
<div class="card" style="max-width:420px;margin:40px auto">
<h1>Sign in</h1><p class="mute">Demo login: <b>alice</b> / <b>wonderland</b></p>
{% if error %}<div class="alert deny">{{ error }}</div>{% endif %}
<form method="post" action="/login">
<label for="u">Username</label><input id="u" name="username" autocomplete="username">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<button id="signin">Sign in</button></form></div>{% endblock %}"""

ACCOUNT = """{% extends "base" %}{% block body %}
{% if result %}
<div class="alert {{ result.kind }}" id="result"><h2>{{ result.title }}</h2><div>{{ result.text }}</div>
{% if result.kind == 'hold' %}<div class="mute" style="margin-top:6px">If this was you, approve it below. If an AI agent is acting for you, connect it properly under <a href="/agents">Connected agents</a>.</div>{% endif %}</div>
{% endif %}
<div class="grid">
<div class="card"><div class="mute">Everyday account · {{ user.name }}</div><div class="bal" id="balance">${{ "{:,.2f}".format(user.balance) }}</div></div>
<div class="card"><h2>Send money</h2><form method="post" action="/transfer">
<label for="to">To</label><input id="to" name="to" placeholder="Name or account">
<label for="amount">Amount</label><input id="amount" name="amount" inputmode="decimal" placeholder="0.00">
<button id="send">Send</button></form></div></div>
{% if user.held %}<div class="card"><h2>Waiting for your approval</h2>
{% for h in user.held %}<div class="held"><div><b>${{ "{:,.2f}".format(h.amount) }}</b> to {{ h.to }}<div class="mute">{{ h.reason }}</div></div>
<div style="display:flex;gap:6px"><form method="post" action="/held/{{ h.id }}/approve"><button class="small">Approve</button></form>
<form method="post" action="/held/{{ h.id }}/reject"><button class="small ghost">Reject</button></form></div></div>{% endfor %}</div>{% endif %}
<div class="card"><h2>Recent activity</h2>{% for t in user.tx[:8] %}<div class="tx"><span>{{ t.desc }}</span>
<span class="{{ 'pos' if t.amount > 0 else 'neg' }}">{{ "+" if t.amount > 0 else "" }}{{ "{:,.2f}".format(t.amount) }}</span></div>{% endfor %}</div>
{% endblock %}"""

AGENTS = """{% extends "base" %}{% block body %}
<div class="card"><h1>Connected agents</h1>
<p class="mute">Let an AI agent act for you <b>without giving it your password</b>. It gets signed parole papers: only the
things you tick, only up to your limit, and only for that agent's key.</p>
{% if token %}<div class="alert ok"><h2>Parole granted</h2><div>Give this to {{ granted }}:</div><code>{{ token }}</code></div>{% endif %}
<form method="post" action="/agents/grant">
<label for="agent">Agent</label><select id="agent" name="kid">{% for kid, name, op in known %}<option value="{{ kid }}">{{ name }} ({{ op }})</option>{% endfor %}</select>
<label><input type="checkbox" name="scopes" value="read" checked style="width:auto"> See balances and activity</label>
<label><input type="checkbox" name="scopes" value="transfer" style="width:auto"> Send money</label>
<label for="limit">Max per transfer ($)</label><input id="limit" name="limit" value="100">
<button>Grant parole</button></form></div>
<div class="card"><h2>Active paroles</h2>{% for p in user.paroles %}<div class="tx"><span><b>{{ p.agent }}</b> · {{ p.scopes|join(", ") }}</span><span class="mute">limit ${{ p.limit }}</span></div>
{% else %}<div class="mute">None yet.</div>{% endfor %}</div>{% endblock %}"""

DENIED = """{% extends "base" %}{% block body %}<div class="alert deny"><h2>Not allowed</h2><div>{{ reason }}</div></div>{% endblock %}"""

env = Environment(loader=DictLoader({"base": BASE, "login": LOGIN, "account": ACCOUNT, "agents": AGENTS,
                                     "denied": DENIED}), autoescape=select_autoescape(default=True))


def render(name: str, status: int = 200, headers=None, **ctx) -> HTMLResponse:
    return HTMLResponse(env.get_template(name).render(title=name.title(), **ctx), status_code=status,
                        headers=headers or {})


def current_user(request: Request):
    v = ctt.verdict(request)
    if v.customer:                      # an agent on parole acts for its customer
        return v.customer, CUSTOMERS.get(v.customer)
    name = SESSIONS.get(request.cookies.get("bank_session", ""))
    return name, CUSTOMERS.get(name) if name else None


def execute_transfer(user: dict, to: str, amount: float) -> None:
    user["balance"] -= amount
    user["tx"].insert(0, {"ts": time.time(), "desc": f"Transfer to {to}", "amount": -amount})


def hold_transfer(user: dict, to: str, amount: float, decision) -> dict:
    item = {"id": next(ids), "to": to, "amount": amount, "by": decision.verdict.label, "reason": decision.reason,
            "ts": time.time()}
    user["held"].append(item)
    return item


def parse_amount(raw) -> float:
    try:
        amount = round(float(str(raw).replace(",", "").replace("$", "")), 2)
    except ValueError:
        raise ValueError("Enter an amount like 25.00")
    if amount <= 0 or amount > 1_000_000:
        raise ValueError("Amount out of range")
    return amount


# ------------------------------------------------------------------ pages
async def home(request: Request):
    return RedirectResponse("/account" if current_user(request)[1] else "/login", 303)


async def login_page(request: Request):
    return render("login", user=None)


async def login(request: Request):
    form = await request.form()
    d = ctt.decide(request, "read")      # let them in: unverified sessions stay read-only
    user = CUSTOMERS.get(form.get("username", ""))
    if not user or user["password"] != form.get("password"):
        return render("login", 401, user=None, error="Wrong username or password.")
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = form["username"]
    r = RedirectResponse("/account", 303, headers=d.headers())
    r.set_cookie("bank_session", token, httponly=True, samesite="lax")
    return r


async def logout(request: Request):
    SESSIONS.pop(request.cookies.get("bank_session", ""), None)
    r = RedirectResponse("/login", 303)
    r.delete_cookie("bank_session")
    return r


async def account(request: Request):
    name, user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    d = ctt.decide(request, "read")
    return render("account", headers=d.headers(), user=user)


async def transfer(request: Request):
    name, user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    form = await request.form()
    to = (form.get("to") or "").strip()[:60] or "unknown"
    try:
        amount = parse_amount(form.get("amount"))
    except ValueError as e:
        return render("account", 400, user=user, result={"kind": "deny", "title": "Check the amount", "text": str(e)})
    d = ctt.decide(request, "money", amount)
    if d.allowed:
        execute_transfer(user, to, amount)
        res = {"kind": "ok", "title": f"Sent ${amount:,.2f} to {to}", "text": "Done."}
    elif d.held:
        hold_transfer(user, to, amount, d)
        why = ("We couldn't confirm a person made this request" if d.verdict.cls != "human"
               else "Large transfers need a quick confirmation on your phone")
        res = {"kind": "hold", "title": f"${amount:,.2f} to {to} is on hold",
               "text": f"{why}, so the money hasn't moved."}
    else:
        res = {"kind": "deny", "title": "Blocked", "text": d.reason}
    return render("account", d.status_code, headers=d.headers(), user=user, result=res)


async def held_action(request: Request):
    name, user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    d = ctt.decide(request, "human_only")
    if not d.allowed:
        return render("denied", 403, headers=d.headers(), user=user, reason=d.reason)
    hid, verb = int(request.path_params["hid"]), request.path_params["verb"]
    item = next((h for h in user["held"] if h["id"] == hid), None)
    if item:
        user["held"].remove(item)
        if verb == "approve":
            execute_transfer(user, item["to"], item["amount"])
    return RedirectResponse("/account", 303)


async def agents_page(request: Request):
    name, user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    known = [(kid, n, op) for kid, (_, n, op) in agents._keys.items()]
    return render("agents", user=user, known=known)


async def grant(request: Request):
    name, user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    d = ctt.decide(request, "human_only")     # only a person may hand out parole
    if not d.allowed:
        return render("denied", 403, headers=d.headers(), user=user, reason=d.reason)
    form = await request.form()
    kid = form.get("kid", "")
    if not agents.get(kid):
        return render("denied", 400, user=user, reason="Unknown agent.")
    scopes = form.getlist("scopes") or ["read"]
    try:
        limit = parse_amount(form.get("limit") or "100")
    except ValueError:
        limit = 100.0
    token = ctt.issue_parole(customer=name, agent_keyid=kid, scopes=scopes, limit=limit)
    agent_name = agents.get(kid)[1]
    user["paroles"].append({"agent": agent_name, "scopes": scopes, "limit": limit, "token": token, "ts": time.time()})
    known = [(k, n, op) for k, (_, n, op) in agents._keys.items()]
    return render("agents", user=user, known=known, token=token, granted=agent_name)


# ------------------------------------------------------------------ API (for agents)
async def api_balance(request: Request):
    name, user = current_user(request)
    if not user:
        return JSONResponse({"error": "not signed in and no parole papers"}, 401)
    d = ctt.decide(request, "read")
    if not d.allowed:
        return JSONResponse({"decision": d.as_dict()}, d.status_code, headers=d.headers())
    return JSONResponse({"customer": name, "balance": user["balance"], "recent": user["tx"][:5],
                         "decision": d.as_dict()}, headers=d.headers())


async def api_transfer(request: Request):
    name, user = current_user(request)
    if not user:
        return JSONResponse({"error": "not signed in and no parole papers"}, 401)
    try:
        body = await request.json()
        to, amount = str(body.get("to", ""))[:60] or "unknown", parse_amount(body.get("amount"))
    except Exception as e:
        return JSONResponse({"error": f"bad request: {e}"}, 400)
    d = ctt.decide(request, "money", amount)
    status = "sent" if d.allowed else d.outcome
    if d.allowed:
        execute_transfer(user, to, amount)
    elif d.held:
        hold_transfer(user, to, amount, d)
    return JSONResponse({"status": status, "to": to, "amount": amount, "decision": d.as_dict()},
                        d.status_code, headers=d.headers())


routes = [
    Route("/", home), Route("/login", login_page), Route("/login", login, methods=["POST"]),
    Route("/logout", logout), Route("/account", account), Route("/transfer", transfer, methods=["POST"]),
    Route("/held/{hid:int}/{verb:str}", held_action, methods=["POST"]),
    Route("/agents", agents_page), Route("/agents/grant", grant, methods=["POST"]),
    Route("/api/balance", api_balance), Route("/api/transfers", api_transfer, methods=["POST"]),
    Mount("/jail", ctt.dashboard()),
]

app = ctt.wrap(Starlette(routes=routes))
