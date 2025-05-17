# email_signup.py
import asyncio, sqlite3, secrets, datetime, aiosmtplib
from email.message import EmailMessage
from pathlib import Path
from db_core import DBProducer

DB_PATH = Path("users.db")
SIGNUP_LIFETIME = datetime.timedelta(hours=72)

class SignupManager:
    def __init__(self, smtp_host: str, smtp_port: int,
                 sender: str, base_url: str):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.base_url = base_url.rstrip("/")
        self.loop = asyncio.get_running_loop()
        self.dbp = DBProducer()            # работаем через существующий продюсер

        # инициализируем таблицу
        self._ensure_table()

    def _ensure_table(self):
        with sqlite3.connect(DB_PATH) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS pending_signups(
                           login       TEXT PRIMARY KEY,
                           pwd         TEXT,
                           full_name   TEXT,
                           phone       TEXT,
                           role        TEXT,
                           iin         TEXT,
                           token       TEXT UNIQUE,
                           expires_at  TEXT
                         );""")
            c.commit()

    async def request_signup(self, *,
                             login: str,
                             password_hash: str,
                             full_name: str,
                             phone: str,
                             role: str = "",
                             iin: str = "") -> str:
        # проверяем, что e‑mail ещё свободен в основной таблице
        busy = await self.dbp.check_free(login=login, phone=phone, iin=iin)
        if busy["login"]:
            raise ValueError("login already taken")

        token = secrets.token_urlsafe(32)
        expires = (datetime.datetime.utcnow() + SIGNUP_LIFETIME
                   ).isoformat(sep=" ", timespec="seconds")
        with sqlite3.connect(DB_PATH) as c:
            c.execute("""INSERT OR REPLACE INTO pending_signups
                         (login,pwd,full_name,phone,role,iin,token,expires_at)
                         VALUES(?,?,?,?,?,?,?,?);""",
                      (login, password_hash, full_name, phone, role,
                       iin, token, expires))
            c.commit()

        # отправляем письмо
        await self._send_email(login, token)
        return token

    async def _send_email(self, recipient: str, token: str):
        link = f"{self.base_url}/confirm?token={token}"
        msg = EmailMessage()
        msg["Subject"] = "Подтверждение регистрации"
        msg["From"] = self.sender
        msg["To"] = recipient
        msg.set_content(f"Перейдите по ссылке для подтверждения: {link}")

        await aiosmtplib.send(msg,
                              hostname=self.smtp_host,
                              port=self.smtp_port,
                              start_tls=True)

    async def confirm(self, token: str) -> bool:
        with sqlite3.connect(DB_PATH) as c:
            cur = c.execute("""SELECT login,pwd,full_name,phone,role,iin,
                                      expires_at
                               FROM pending_signups WHERE token=?""",
                             (token,))
            row = cur.fetchone()
            if not row:
                return False
            login, pwd, full_name, phone, role, iin, expires = row
            if datetime.datetime.utcnow() > datetime.datetime.fromisoformat(expires):
                c.execute("DELETE FROM pending_signups WHERE token=?", (token,))
                c.commit()
                return False
            # создаём аккаунт обычным способом
            await self.dbp.add_user(login=login,
                                    password="",
                                    full_name=full_name,
                                    phone=phone,
                                    role=role,
                                    iin=iin)
            # сразу же меняем пароль напрямую
            await self.dbp.update_password(login, pwd)
            # удаляем временную запись
            c.execute("DELETE FROM pending_signups WHERE token=?", (token,))
            c.commit()
        await self.dbp.confirm_email(login)
        return True
