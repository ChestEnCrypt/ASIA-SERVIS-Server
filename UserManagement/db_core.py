# db_core.py  (2025-05-15)
import asyncio, sqlite3, bcrypt, secrets, datetime, shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Optional

MAX_FAILED = 5
TOKEN_LIFETIME = datetime.timedelta(minutes=30)

_QUEUE: 'asyncio.Queue[Task]' = asyncio.Queue()


def get_queue() -> asyncio.Queue:
	return _QUEUE


@dataclass
class Task:
	op: Literal[
		"add", "get", "del", "set_role", "upd_pwd", "upd_contacts",
		"check", "auth", "backup", "confirm_email", "confirm_phone",
		"request_pwd_reset", "reset_password", "unblock", "get_uuid",
		"set_login"
	]
	payload: Dict[str, Any]
	fut: asyncio.Future


# ───── продюсер ─────────────────────────────────────────────────────
class DBProducer:
	def __init__(self):
		self._q = _QUEUE
		self._loop = asyncio.get_event_loop()

	async def _call(self, op: str, **kw):
		fut = self._loop.create_future()
		await self._q.put(Task(op, kw, fut))
		return await fut

	async def add_user(self, login: str, password: str, full_name: str,
					   phone: str, role: str = "", iin: str = "") -> int:
		pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
		return await self._call("add", login=login, pwd=pw_hash,
								full_name=full_name, phone=phone,
								role=role, iin=iin)

	async def get_user(self, login: str):
		return await self._call("get", login=login)

	async def del_user(self, login: str):
		return await self._call("del", login=login)

	async def set_role(self, login: str, role: str):
		return await self._call("set_role", login=login, role=role)
	
	async def set_login(self, login: str, new_login: str):
		return self._call("set_login", login=login, new_login=new_login)

	async def update_password(self, login: str, new_password: str):
		pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
		return await self._call("upd_pwd", login=login, pwd=pw_hash)

	async def update_contacts(self, login: str, *,
							  phone: Optional[str] = None,
							  iin: Optional[str] = None,
							  full_name: Optional[str] = None):
		return await self._call("upd_contacts", login=login,
								phone=phone, iin=iin, full_name=full_name)

	async def check_free(self, *, login=None, phone=None, iin=None):
		return await self._call("check", login=login, phone=phone, iin=iin)

	async def auth(self, login: str, password: str) -> Optional[int]:
		return await self._call("auth", login=login, password=password)

	async def confirm_email(self, login: str):
		return await self._call("confirm_email", login=login)

	async def confirm_phone(self, login: str):
		return await self._call("confirm_phone", login=login)

	async def request_pwd_reset(self, login: str):
		return await self._call("request_pwd_reset", login=login)

	async def reset_password(self, token: str, new_password: str):
		pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
		return await self._call("reset_password", token=token, pwd=pw_hash)

	async def unblock(self, login: str):
		return await self._call("unblock", login=login)

	async def get_uuid(self, login: str) -> Optional[int]:
		return await self._call("get_uuid", login=login)

	async def backup(self, note: str = ""):
		return await self._call("backup", note=note)


# ───── воркер ────────────────────────────────────────────────────────
class DBWorker:
	def __init__(self, db_path="users.db", backup_dir="backups"):
		self._q = _QUEUE
		self._db_path = Path(db_path)
		self._backup_dir = Path(backup_dir)

	# синхронное открытие и инициализация
	def _sync_open(self):
		self._db_path.parent.mkdir(parents=True, exist_ok=True)
		self._backup_dir.mkdir(parents=True, exist_ok=True)
		conn = sqlite3.connect(self._db_path, check_same_thread=False)
		conn.execute("PRAGMA journal_mode=WAL")
		conn.execute("""CREATE TABLE IF NOT EXISTS users(
			uuid INTEGER UNIQUE NOT NULL,
			login TEXT PRIMARY KEY,
			full_name TEXT,
			iin TEXT UNIQUE DEFAULT '',
			pwd TEXT NOT NULL,
			phone TEXT UNIQUE,
			role TEXT,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			last_login_at TEXT,
			email_confirmed INTEGER DEFAULT 0,
			phone_confirmed INTEGER DEFAULT 0,
			failed_logins INTEGER DEFAULT 0,
			is_blocked INTEGER DEFAULT 0
		);""")
		conn.execute("""CREATE TABLE IF NOT EXISTS reset_tokens(
			token TEXT PRIMARY KEY,
			login TEXT,
			expires_at TEXT
		);""")
		conn.commit()
		return conn

	def _sync_backup(self, note):
		t = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
		dst = self._backup_dir / f"{t}_{note or 'auto'}.db"
		shutil.copy2(self._db_path, dst)
		return dst

	# главный цикл
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

	# операции --------------------------------------------------------
	async def _next_uuid(self, c) -> int:
		cur = await asyncio.to_thread(c.execute, "SELECT COALESCE(MAX(uuid),0)+1 FROM users")
		return cur.fetchone()[0]

	async def _op_add(self, c, t):
		uid = await self._next_uuid(c)
		payload = dict(t.payload, uuid=uid)
		q = ("INSERT INTO users(uuid, login, full_name, iin, pwd, phone, role) "
			 "VALUES(:uuid, :login, :full_name, :iin, :pwd, :phone, :role);")
		await asyncio.to_thread(c.execute, q, payload)
		await asyncio.to_thread(c.commit)
		t.fut.set_result(uid)

	async def _op_get(self, c, t):
		cur = await asyncio.to_thread(c.execute,
			"SELECT * FROM users WHERE login=?", (t.payload["login"],))
		t.fut.set_result(cur.fetchone())

	async def _op_get_uuid(self, c, t):
		cur = await asyncio.to_thread(c.execute,
			"SELECT uuid FROM users WHERE login=?", (t.payload["login"],))
		row = cur.fetchone()
		t.fut.set_result(row[0] if row else None)

	async def _op_del(self, c, t):
		await asyncio.to_thread(c.execute,
			"DELETE FROM users WHERE login=?", (t.payload["login"],))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_set_role(self, c, t):
		await asyncio.to_thread(c.execute,
			"UPDATE users SET role=? WHERE login=?",
			(t.payload["role"], t.payload["login"]))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_set_login(self, c, t):
		# task.payload = {"login": old_login, "new_login": new_login}
		await asyncio.to_thread(c.execute,
			"UPDATE users SET login=? WHERE login=?",
			(t.payload["new_login"],
			t.payload["login"]))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_upd_pwd(self, c, t):
		await asyncio.to_thread(c.execute,
			"UPDATE users SET pwd=? WHERE login=?",
			(t.payload["pwd"], t.payload["login"]))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_upd_contacts(self, c, t):
		sets, params = [], []
		for k in ("phone", "iin", "full_name"):
			v = t.payload.get(k)
			if v is not None:
				sets.append(f"{k}=?"); params.append(v)
		if sets:
			params.append(t.payload["login"])
			sql = "UPDATE users SET " + ", ".join(sets) + " WHERE login=?"
			await asyncio.to_thread(c.execute, sql, params)
			await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_check(self, c, t):
		login, phone, iin = t.payload.values()
		cond, prm = [], []
		if login: cond.append("login=?"); prm.append(login)
		if phone: cond.append("phone=?"); prm.append(phone)
		if iin:   cond.append("iin=?");   prm.append(iin)
		if not cond:
			t.fut.set_result({}); return
		sql = "SELECT login, phone, iin FROM users WHERE " + " OR ".join(cond)
		cur = await asyncio.to_thread(c.execute, sql, prm)
		row = cur.fetchone()
		busy = {"login": False, "phone": False, "iin": False}
		if row:
			busy["login"] = login and row[0] == login
			busy["phone"] = phone and row[1] == phone
			busy["iin"]   = iin   and row[2] == iin
		t.fut.set_result(busy)

	async def _op_auth(self, c, t):
		cur = await asyncio.to_thread(c.execute,
			"SELECT uuid, pwd, failed_logins, is_blocked "
			"FROM users WHERE login=?", (t.payload["login"],))
		row = cur.fetchone()
		if not row:
			t.fut.set_result(None); return
		uid, pw_hash, fails, blocked = row
		if blocked:
			t.fut.set_result(None); return
		ok = bcrypt.checkpw(t.payload["password"].encode(), pw_hash.encode())
		now = datetime.datetime.utcnow().isoformat(sep=" ", timespec="seconds")
		if ok:
			await asyncio.to_thread(c.execute,
				"UPDATE users SET failed_logins=0, last_login_at=? "
				"WHERE login=?", (now, t.payload["login"]))
		else:
			fails += 1
			blocked_flag = 1 if fails >= MAX_FAILED else 0
			await asyncio.to_thread(c.execute,
				"UPDATE users SET failed_logins=?, is_blocked=? "
				"WHERE login=?", (fails, blocked_flag, t.payload["login"]))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(uid if ok else None)

	async def _op_confirm_email(self, c, t):
		await asyncio.to_thread(c.execute,
			"UPDATE users SET email_confirmed=1 WHERE login=?",
			(t.payload["login"],))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_confirm_phone(self, c, t):
		await asyncio.to_thread(c.execute,
			"UPDATE users SET phone_confirmed=1 WHERE login=?",
			(t.payload["login"],))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_request_pwd_reset(self, c, t):
		token = secrets.token_urlsafe(32)
		exp = (datetime.datetime.utcnow() + TOKEN_LIFETIME
			   ).isoformat(sep=" ", timespec="seconds")
		await asyncio.to_thread(c.execute,
			"INSERT OR REPLACE INTO reset_tokens(token,login,expires_at) "
			"VALUES(?,?,?)", (token, t.payload["login"], exp))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(token)

	async def _op_reset_password(self, c, t):
		cur = await asyncio.to_thread(c.execute,
			"SELECT login, expires_at FROM reset_tokens WHERE token=?",
			(t.payload["token"],))
		row = cur.fetchone()
		if not row:
			t.fut.set_result(False); return
		login, exp = row
		if datetime.datetime.utcnow() > datetime.datetime.fromisoformat(exp):
			t.fut.set_result(False); return
		await asyncio.to_thread(c.execute,
			"UPDATE users SET pwd=?, failed_logins=0, is_blocked=0 "
			"WHERE login=?", (t.payload["pwd"], login))
		await asyncio.to_thread(c.execute,
			"DELETE FROM reset_tokens WHERE token=?", (t.payload["token"],))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_unblock(self, c, t):
		await asyncio.to_thread(c.execute,
			"UPDATE users SET failed_logins=0, is_blocked=0 "
			"WHERE login=?", (t.payload["login"],))
		await asyncio.to_thread(c.commit)
		t.fut.set_result(True)

	async def _op_backup(self, c, t):
		dst = await asyncio.to_thread(self._sync_backup, t.payload["note"])
		t.fut.set_result(dst)
