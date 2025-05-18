import asyncio, sqlite3, datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Optional

_QUEUE: 'asyncio.Queue[Task]' = asyncio.Queue()

def get_rt_queue() -> asyncio.Queue:
    return _QUEUE

@dataclass
class Task:
    op: Literal[
        "set", "add", "get", "is_revoked",
        "revoke", "purge", "rotate",
        "get_user_tokens", "revoke_all",
        "validate", "cleanup"
    ]
    payload: Dict[str, Any]
    fut: asyncio.Future

class RTProducer:
    def __init__(self):
        self._q = _QUEUE
        self._loop = asyncio.get_event_loop()

    async def _call(self, op: str, **kw):
        fut = self._loop.create_future()
        await self._q.put(Task(op, kw, fut))
        return await fut

    async def set_user_token(self, token_id: str, user_id: int,
                             expires_at: str, is_revoked: bool = False):
        return await self._call("set", token_id=token_id, user_id=user_id,
                                expires_at=expires_at, is_revoked=is_revoked)

    async def add_refresh_token(self, user_id: int, token_id: str,
                                expires_at: str):
        return await self._call("add", user_id=user_id,
                                token_id=token_id, expires_at=expires_at)

    async def get_refresh_token(self, token_id: str):
        return await self._call("get", token_id=token_id)

    async def is_token_revoked(self, token_id: str) -> bool:
        return await self._call("is_revoked", token_id=token_id)

    async def revoke_refresh_token(self, token_id: str):
        return await self._call("revoke", token_id=token_id)

    async def purge_expired_tokens(self):
        return await self._call("purge")

    async def rotate_refresh_token(self, old_token_id: str,
                                   new_token_id: str,
                                   new_expires_at: str):
        return await self._call("rotate", old=old_token_id,
                                new=new_token_id,
                                exp=new_expires_at)

    async def get_user_tokens(self, user_id: int):
        return await self._call("get_user_tokens", user_id=user_id)

    async def revoke_all_user_tokens(self, user_id: int):
        return await self._call("revoke_all", user_id=user_id)

    async def validate_refresh_token(self, token_id: str,
                                     user_id: int) -> bool:
        return await self._call("validate", token_id=token_id,
                                user_id=user_id)

    async def cleanup_revoked_tokens(self, retention_period: int):
        return await self._call("cleanup", retention=retention_period)

class RTWorker:
    def __init__(self, db_path: str = "users.db"):
        self._q = _QUEUE
        self._db_path = Path(db_path)

    # ---------- sync helpers ----------
    def _sync_open(self):
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("""CREATE TABLE IF NOT EXISTS refresh_tokens(
            token_id TEXT PRIMARY KEY,
            user_id  INTEGER,
            expires_at TEXT,
            is_revoked INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(uuid)
        );""")
        conn.commit()
        return conn

    # ---------- worker loop ----------
    async def run(self):
        conn = await asyncio.to_thread(self._sync_open)
        while True:
            t: Task = await self._q.get()
            try:
                await getattr(self, f"_op_{t.op}")(conn, t)
            except Exception as e:
                t.fut.set_exception(e)
            finally:
                self._q.task_done()

    # ---------- operations ----------
    async def _op_set(self, c, t):
        await asyncio.to_thread(c.execute,
            """INSERT INTO refresh_tokens(token_id,user_id,expires_at,is_revoked)
               VALUES(?,?,?,?)
               ON CONFLICT(token_id) DO UPDATE SET
               user_id=excluded.user_id,
               expires_at=excluded.expires_at,
               is_revoked=excluded.is_revoked;""",
            (t.payload["token_id"], t.payload["user_id"],
             t.payload["expires_at"], int(t.payload["is_revoked"])))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_add(self, c, t):
        await asyncio.to_thread(c.execute,
            "INSERT INTO refresh_tokens(token_id,user_id,expires_at) "
            "VALUES(?,?,?)",
            (t.payload["token_id"], t.payload["user_id"],
             t.payload["expires_at"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_get(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT * FROM refresh_tokens WHERE token_id=?",
            (t.payload["token_id"],))
        t.fut.set_result(cur.fetchone())

    async def _op_is_revoked(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT is_revoked FROM refresh_tokens WHERE token_id=?",
            (t.payload["token_id"],))
        row = cur.fetchone()
        t.fut.set_result(bool(row[0]) if row else True)

    async def _op_revoke(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE refresh_tokens SET is_revoked=1 "
            "WHERE token_id=?", (t.payload["token_id"],))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_purge(self, c, t):
        now = datetime.datetime.utcnow().isoformat(sep=" ",
                                                  timespec="seconds")
        await asyncio.to_thread(c.execute,
            "DELETE FROM refresh_tokens WHERE expires_at<?", (now,))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_rotate(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE refresh_tokens SET is_revoked=1 "
            "WHERE token_id=?", (t.payload["old"],))
        await asyncio.to_thread(c.execute,
            "INSERT INTO refresh_tokens(token_id,user_id,expires_at) "
            "VALUES(?,?,?)",
            (t.payload["new"], None, t.payload["exp"]))
        # узнаём user_id старого токена и проставляем в новом
        await asyncio.to_thread(c.execute,
            "UPDATE refresh_tokens SET user_id=(SELECT user_id "
            "FROM refresh_tokens WHERE token_id=?) "
            "WHERE token_id=?", (t.payload["old"], t.payload["new"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_get_user_tokens(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT * FROM refresh_tokens WHERE user_id=?",
            (t.payload["user_id"],))
        t.fut.set_result(cur.fetchall())

    async def _op_revoke_all(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE refresh_tokens SET is_revoked=1 "
            "WHERE user_id=?", (t.payload["user_id"],))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_validate(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT user_id, expires_at, is_revoked "
            "FROM refresh_tokens WHERE token_id=?", (t.payload["token_id"],))
        row = cur.fetchone()
        if not row:
            t.fut.set_result(False); return
        uid, exp, revoked = row
        now = datetime.datetime.utcnow().isoformat(sep=" ",
                                                  timespec="seconds")
        ok = (uid == t.payload["user_id"]
              and not revoked
              and exp > now)
        t.fut.set_result(ok)

    async def _op_cleanup(self, c, t):
        cutoff = (datetime.datetime.utcnow() -
                  datetime.timedelta(seconds=t.payload["retention"])
                  ).isoformat(sep=" ", timespec="seconds")
        await asyncio.to_thread(c.execute,
            "DELETE FROM refresh_tokens "
            "WHERE is_revoked=1 AND expires_at<?", (cutoff,))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)
