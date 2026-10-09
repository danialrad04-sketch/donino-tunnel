"""Bounded event history and persistent operator choices."""
import json
import sqlite3
import time
from pathlib import Path


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time REAL, kind TEXT, detail TEXT);
        """)
        self.db.commit()

    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, json.dumps(value)))
        self.db.commit()

    def event(self, kind, detail):
        self.db.execute("INSERT INTO events(time,kind,detail) VALUES (?,?,?)", (time.time(), kind, json.dumps(detail)))
        self.db.execute("DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)")
        self.db.commit()

    def events(self, limit=50):
        return [dict(id=i, time=t, kind=k, detail=json.loads(d)) for i,t,k,d in
                self.db.execute("SELECT id,time,kind,detail FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def close(self):
        self.db.close()
