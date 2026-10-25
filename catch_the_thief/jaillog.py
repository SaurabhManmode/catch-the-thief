"""The jail log: an append-only SQLite record of every booking and decision."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  sid TEXT NOT NULL,
  cls TEXT NOT NULL,
  score INTEGER NOT NULL,
  outcome TEXT NOT NULL,      -- booked | allow | hold | deny
  action TEXT,
  method TEXT,
  path TEXT,
  amount REAL,
  reason TEXT,
  agent TEXT,
  operator TEXT,
  ua TEXT,
  signals TEXT
);
CREATE INDEX IF NOT EXISTS events_sid ON events(sid);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""


class JailLog:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
        self.humans_waved_through = 0

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:
            pass

    def __del__(self):
        self.close()

    def record(self, *, sid: str, cls: str, score: int, outcome: str, action: str = "", method: str = "",
               path: str = "", amount: Optional[float] = None, reason: str = "", agent: str = "",
               operator: str = "", ua: str = "", signals: Optional[list] = None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO events (ts,sid,cls,score,outcome,action,method,path,amount,reason,agent,operator,ua,signals)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), sid, cls, score, outcome, action, method, path, amount, reason, agent, operator,
                 ua[:300], json.dumps(signals or [])))
            return cur.lastrowid

    def events(self, limit: int = 200, since_id: int = 0) -> list:
        with self._lock:
            rows = self._db.execute("SELECT * FROM events WHERE id > ? ORDER BY id DESC LIMIT ?",
                                    (since_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["signals"] = json.loads(d["signals"] or "[]")
            out.append(d)
        return out

    def summary(self, limit: int = 500) -> dict:
        """Dashboard view: inmates (unverified sessions held/denied/booked) and verified visitors."""
        events = list(reversed(self.events(limit)))
        inmates, visitors = {}, {}
        stats = {"inmates": 0, "held_count": 0, "held_total": 0.0, "denied": 0, "verified_actions": 0,
                 "paroled_actions": 0, "humans": self.humans_waved_through}
        for e in events:
            if e["outcome"] == "hold":
                stats["held_count"] += 1
                stats["held_total"] += e["amount"] or 0
            if e["outcome"] == "deny":
                stats["denied"] += 1
            if e["cls"] in ("verified", "paroled"):
                stats["verified_actions" if e["cls"] == "verified" else "paroled_actions"] += 1
                v = visitors.setdefault(e["agent"] or "unknown agent", {
                    "agent": e["agent"], "operator": e["operator"], "cls": e["cls"], "actions": [], "last": 0})
                v["cls"], v["last"] = e["cls"], e["ts"]
                v["actions"].append(_brief(e))
                v["actions"] = v["actions"][-6:]
                continue
            if e["cls"] in ("suspect", "uncertain") or e["outcome"] in ("hold", "deny"):
                m = inmates.get(e["sid"])
                if m is None:
                    m = inmates[e["sid"]] = {"sid": e["sid"], "no": len(inmates) + 1, "booked": e["ts"],
                                             "charges": {}, "sentences": [], "ua": e["ua"]}
                m.update(cls=e["cls"], score=max(m.get("score", 0), e["score"]), last=e["ts"])
                for s in e["signals"]:
                    prev = m["charges"].get(s["code"])
                    if prev is None or s["weight"] > prev["weight"]:
                        m["charges"][s["code"]] = s
                if e["outcome"] != "booked":
                    m["sentences"].append(_brief(e))
                    m["sentences"] = m["sentences"][-6:]
        for m in inmates.values():
            m["charges"] = sorted(m["charges"].values(), key=lambda s: -s["weight"])
        stats["inmates"] = len(inmates)
        return {"stats": stats,
                "inmates": sorted(inmates.values(), key=lambda m: -m["last"]),
                "visitors": sorted(visitors.values(), key=lambda v: -v["last"]),
                "feed": [_brief(e) | {"cls": e["cls"], "sid": e["sid"]} for e in reversed(events[-25:])]}


def _brief(e: dict) -> dict:
    return {"ts": e["ts"], "outcome": e["outcome"], "action": e["action"], "method": e["method"],
            "path": e["path"], "amount": e["amount"], "reason": e["reason"], "agent": e["agent"]}
