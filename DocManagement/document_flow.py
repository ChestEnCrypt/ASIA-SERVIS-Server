# document_flow.py

import asyncio
import sqlite3
import shutil
import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal

from cryptography.fernet import Fernet

# ─── константы и директории ─────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "documents.db"
DIR_DOCS   = BASE_DIR / "documents"
DIR_SIGNS  = BASE_DIR / "signs"
DIR_CERTS  = BASE_DIR / "certificates"
KEY_FILE   = BASE_DIR / "encryption.key"
QUEUE: "asyncio.Queue[Task]" = asyncio.Queue()

# ─── подготовка окружения ────────────────────────────────────────────
def _ensure_dirs():
    for d in (DIR_DOCS, DIR_SIGNS, DIR_CERTS):
        d.mkdir(parents=True, exist_ok=True)

def _load_key() -> bytes:
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
    else:
        key = KEY_FILE.read_bytes()
    return key

FERNET = Fernet(_load_key())
_ensure_dirs()

# ─── описание задач ─────────────────────────────────────────────────
@dataclass
class Task:
    op: Literal[
        "add_cert", "get_certs", "upd_cert", "rm_cert",
        "sign_doc", "verify_sign",
        "create_doc", "add_u_doc", "upd_doc", "upd_u_doc",
        "rm_doc", "rm_u_doc",
        "add_comment", "upd_comment", "rm_comment",
        "get_docs", "get_u_docs", "get_signs", "get_comments",
        "set_status", "send_doc",
        "get_inbox", "archive", "unarchive",
        "get_versions",
        "add_contact", "get_contacts", "remove_contact",
        "get_content", "add_subdoc"
    ]
    payload: Dict[str, Any]
    fut: asyncio.Future

def get_queue() -> asyncio.Queue:
    return QUEUE

# ─── продюсер ───────────────────────────────────────────────────────
class DCProducer:
    def __init__(self):
        self._q = QUEUE
        self._loop = asyncio.get_event_loop()

    async def _call(self, op: str, **kw):
        fut = self._loop.create_future()
        await self._q.put(Task(op, kw, fut))
        return await fut

    # сертификаты
    async def add_user_certificate(self, login: str, cert_path: str) -> int:
        return await self._call("add_cert", login=login, cert_path=cert_path)

    async def get_user_certificates(self, login: str) -> Dict[int, Dict[str, str]]:
        return await self._call("get_certs", login=login)

    async def update_user_certificate(self, login: str, cer_id: int, new_name: str):
        return await self._call("upd_cert", login=login, cer_id=cer_id, new_name=new_name)

    async def remove_user_certificate(self, login: str, cer_id: int):
        return await self._call("rm_cert", login=login, cer_id=cer_id)

    # подпись документов
    async def sign_document(self, login: str, author: str,
                            doc_id: int, u_doc_id: int, sig_path: str):
        return await self._call("sign_doc", login=login, author=author,
                                doc_id=doc_id, u_doc_id=u_doc_id, sig_path=sig_path)

    async def verify_document_signature(self, login: str,
                                        doc_path: str, cer_id: int) -> bool:
        return await self._call("verify_sign", login=login,
                                doc_path=doc_path, cer_id=cer_id)

    # документы
    async def create_document(self, login: str) -> int:
        return await self._call("create_doc", login=login)

    async def add_document_file(self, login: str, name: str, doc_id: int, file_path: str) -> int:
        return await self._call("add_u_doc", login=login, name=name,
                                doc_id=doc_id, file_path=file_path)

    async def add_subdocument(self, login: str, doc_id: int,
                              name: str, content: str) -> int:
        return await self._call(
            "add_subdoc",
            login=login, doc_id=doc_id,
            name=name, content=content
        )

    async def update_document_contents(self, login: str, doc_id: int,
                                       new_name: str = "", new_content: str = "", new_status: str =""):
        return await self._call("upd_doc", login=login,
                                doc_id=doc_id, new_name=new_name, new_content=new_content, new_status=new_status)

    async def update_u_document_contents(self, login: str, doc_id: int,
                                         u_doc_id: int, new_name: str = ""):
        return await self._call("upd_u_doc", login=login,
                                doc_id=doc_id, u_doc_id=u_doc_id, new_name=new_name)

    async def remove_documents(self, login: str, doc_id: int):
        return await self._call("rm_doc", login=login, doc_id=doc_id)

    async def remove_u_document(self, login: str, doc_id: int, u_doc_id: int):
        return await self._call("rm_u_doc", login=login, doc_id=doc_id, u_doc_id=u_doc_id)

    async def get_document_content(self, login: str, doc_id: int) -> Dict[str, Any]:
        return await self._call("get_content", login=login, doc_id=doc_id)

    async def decrypt_file(self, enc_path: str) -> Dict[str, Any]:
        return await self._call("decrypt_file", enc_path=enc_path)

    # комментарии
    async def add_document_comment(self, login: str, author: str,
                                   doc_id: int, comment: str) -> int:
        return await self._call("add_comment", login=login,
                                author=author, doc_id=doc_id, comment=comment)

    async def update_document_comment(self, author: str, doc_id: int,
                                      com_id: int, new_comment: str):
        return await self._call("upd_comment", author=author,
                                doc_id=doc_id, com_id=com_id, new_comment=new_comment)

    async def remove_document_comment(self, author: str, doc_id: int, com_id: int):
        return await self._call("rm_comment", author=author,
                                doc_id=doc_id, com_id=com_id)

    # чтение
    async def get_documents(self, login: str) -> Dict[int, Dict[str, Any]]:
        return await self._call("get_docs", login=login)

    async def get_document_files(self, author: str, doc_id: int) -> Dict[int, Dict[str, str]]:
        return await self._call("get_u_docs", author=author, doc_id=doc_id)

    async def get_document_signs(self, author: str, doc_id: int) -> Dict[int, Dict[str, str]]:
        return await self._call("get_signs", author=author, doc_id=doc_id)

    async def get_document_comments(self, author: str, doc_id: int) -> Dict[int, Dict[str, Any]]:
        return await self._call("get_comments", author=author, doc_id=doc_id)

    async def get_document_versions(self, login: str, doc_id: int) -> Dict[int, Dict[str, Any]]:
        return await self._call("get_versions", login=login, doc_id=doc_id)

    # статус и отправка
    async def set_document_status(self, login: str, doc_id: int, status: int):
        return await self._call("set_status", login=login, doc_id=doc_id, status=status)

    async def send_document(self, send_to: str, author: str, doc_id: int):
        return await self._call("send_doc", send_to=send_to, author=author, doc_id=doc_id)

    # входящие
    async def get_inbox(self, login: str) -> Dict[int, Dict[str, Any]]:
        return await self._call("get_inbox", login=login)

    async def archive_document(self, login: str, inb_id: int):
        return await self._call("archive", login=login, inb_id=inb_id)

    async def unarchive_document(self, login: str, inb_id: int):
        return await self._call("unarchive", login=login, inb_id=inb_id)

    # контакты
    async def add_contact(self, login: str, name: str, contact: str) -> int:
        return await self._call("add_contact", login=login, name=name, contact=contact)

    async def get_contacts(self, login: str) -> Dict[int, str]:
        return await self._call("get_contacts", login=login)

    async def remove_contact(self, login: str, con_id: int):
        return await self._call("remove_contact", login=login, con_id=con_id)

# ─── воркер ─────────────────────────────────────────────────────────
class DCWorker:
    def __init__(self, db_path: Path = DB_PATH):
        self._q = QUEUE
        self._db_path = db_path

    def _sync_open(self):
        _ensure_dirs()
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates(
          cer_id INTEGER PRIMARY KEY AUTOINCREMENT,
          login TEXT,
          cer_name TEXT,
          cer_path TEXT
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS documents(
          doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
          login TEXT,
          doc_name TEXT,
          content TEXT,
          create_date TEXT,
          edited_date TEXT,
          status INTEGER DEFAULT 0
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS u_documents(
          u_doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
          doc_id INTEGER,
          u_doc_name TEXT,
          u_doc_path TEXT
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS document_versions(
          version_id INTEGER PRIMARY KEY AUTOINCREMENT,
          doc_id INTEGER,
          version_date TEXT,
          doc_name TEXT,
          content TEXT
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS signatures(
          sig_id INTEGER PRIMARY KEY AUTOINCREMENT,
          u_doc_id INTEGER,
          login TEXT,
          sign_path TEXT
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS comments(
          com_id INTEGER PRIMARY KEY AUTOINCREMENT,
          doc_id INTEGER,
          author TEXT,
          date TEXT,
          content TEXT
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS inbox(
          inb_id INTEGER PRIMARY KEY AUTOINCREMENT,
          login TEXT,
          author TEXT,
          doc_id INTEGER,
          signed INTEGER DEFAULT 0,
          archived INTEGER DEFAULT 0
        );""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts(
          con_id INTEGER PRIMARY KEY AUTOINCREMENT,
          login TEXT,
          name TEXT,
          contact TEXT
        );""")

        conn.commit()
        return conn

    async def run(self):
        conn = await asyncio.to_thread(self._sync_open)
        while True:
            task: Task = await self._q.get()
            try:
                handler = getattr(self, f"_op_{task.op}")
                await handler(conn, task)
            except Exception as e:
                task.fut.set_exception(e)
            finally:
                self._q.task_done()

    # вспомогательные методы
    def _encrypt_and_store(self, src_path: str, dst_dir: Path) -> str:
        data = Path(src_path).read_bytes()
        enc = FERNET.encrypt(data)
        dst = dst_dir / f"{datetime.datetime.utcnow().timestamp()}_{Path(src_path).name}.enc"
        Path(dst_dir).mkdir(parents=True, exist_ok=True)
        dst.write_bytes(enc)
        return str(dst)

    def _decrypt(self, enc_path: str) -> bytes:
        data_enc = Path(enc_path).read_bytes()
        return FERNET.decrypt(data_enc)

    async def _op_decrypt_file(self, c, t):
        # извлекаем путь из payload
        enc_path = t.payload.get('enc_path')
        # читаем зашифрованные байты
        data_enc = Path(enc_path).read_bytes()
        # расшифровываем тем же экземпляром FERNET (инициализированным из base64-ключа)
        plaintext = FERNET.decrypt(data_enc)
        # возвращаем bytes как результат задачи
        t.fut.set_result(plaintext)

    # операции
    async def _op_add_cert(self, c, t):
        name = Path(t.payload["cert_path"]).name
        cur = await asyncio.to_thread(c.execute,
            "INSERT INTO certificates(login,cer_name,cer_path) VALUES(?,?,?)",
            (t.payload["login"], name, t.payload["cert_path"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_get_certs(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT cer_id,cer_name,cer_path FROM certificates WHERE login=?",
            (t.payload["login"],))
        rows = cur.fetchall()
        res = {r[0]: {"cer_name": r[1], "cer_path": r[2]} for r in rows}
        t.fut.set_result(res)

    async def _op_upd_cert(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE certificates SET cer_name=? WHERE login=? AND cer_id=?",
            (t.payload["new_name"], t.payload["login"], t.payload["cer_id"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_rm_cert(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT cer_path FROM certificates WHERE login=? AND cer_id=?",
            (t.payload["login"], t.payload["cer_id"]))
        row = cur.fetchone()
        if row:
            try: Path(row[0]).unlink()
            except: pass
        await asyncio.to_thread(c.execute,
            "DELETE FROM certificates WHERE login=? AND cer_id=?",
            (t.payload["login"], t.payload["cer_id"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_create_doc(self, c, t):
        now = datetime.datetime.utcnow().isoformat()
        cur = await asyncio.to_thread(c.execute,
            "INSERT INTO documents(login,doc_name,content,create_date,edited_date) VALUES(?,?,?,?,?)",
            (t.payload["login"], f"new_document_{int(datetime.datetime.utcnow().timestamp())}", "", now, now))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_add_u_doc(self, c, t):
        dst = self._encrypt_and_store(t.payload["file_path"],
                                      DIR_DOCS / t.payload["login"] / str(t.payload["doc_id"]))
        name = Path(t.payload["file_path"]).name
        cur = await asyncio.to_thread(c.execute,
            "INSERT INTO u_documents(doc_id,u_doc_name,u_doc_path) VALUES(?,?,?)",
            (t.payload["doc_id"], name, dst))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_add_subdoc(self, conn, task):
        # подготовить директорию
        dst_dir = DIR_DOCS / task.payload["login"] / str(task.payload["doc_id"])
        dst_dir.mkdir(parents=True, exist_ok=True)

        # сохранить содержимое subdocument как текстовый файл
        ts = datetime.datetime.utcnow().timestamp()
        filename = f"{ts}_{task.payload['name']}.txt"
        path = dst_dir / filename
        path.write_text(task.payload["content"], encoding="utf-8")

        # добавить запись в таблицу u_documents
        cur = await asyncio.to_thread(conn.execute,
            "INSERT INTO u_documents(doc_id, u_doc_name, u_doc_path) VALUES (?,?,?)",
            (task.payload["doc_id"], task.payload["name"], str(path))
        )
        await asyncio.to_thread(conn.commit)
        task.fut.set_result(cur.lastrowid)

    async def _op_upd_doc(self, c, t):
        login   = t.payload.get("login")
        doc_id  = t.payload.get("doc_id")
        new_name    = t.payload.get("new_name")      # вместо new_name
        new_content = t.payload.get("new_content")   # вместо new_content
        new_status  = t.payload.get("new_status")

        # 1) сохраняем предыдущую версию
        row = await asyncio.to_thread(
            lambda: c.execute(
                "SELECT doc_name, content, edited_date "
                "FROM documents WHERE login=? AND doc_id=?",
                (login, doc_id)
            ).fetchone()
        )
        if row:
            prev_name, prev_content, prev_date = row
            await asyncio.to_thread(c.execute,
                "INSERT INTO document_versions(doc_id, version_date, doc_name, content) "
                "VALUES(?,?,?,?)",
                (doc_id, prev_date, prev_name, prev_content)
            )

        # 2) готовим UPDATE
        sets, params = [], []
        if new_name is not None:
            sets.append("doc_name=?")
            params.append(new_name)
        if new_content is not None:
            sets.append("content=?")
            params.append(new_content)
        if new_status is not None:
            sets.append("status=?")
            params.append(new_status)

        if sets:
            # добавляем edited_date
            sets.append("edited_date=?")
            params.append(datetime.datetime.utcnow().isoformat())
            # WHERE
            params.extend((login, doc_id))

            sql = (
                "UPDATE documents "
                "SET " + ", ".join(sets) + " "
                "WHERE login=? AND doc_id=?"
            )
            await asyncio.to_thread(c.execute, sql, params)
            await asyncio.to_thread(c.commit)

        t.fut.set_result(True)

    async def _op_upd_u_doc(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE u_documents SET u_doc_name=? WHERE u_doc_id=?",
            (t.payload["new_name"], t.payload["u_doc_id"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_rm_doc(self, c, t):
        doc_dir = DIR_DOCS / t.payload["login"] / str(t.payload["doc_id"])
        if doc_dir.exists():
            shutil.rmtree(doc_dir)
        await asyncio.to_thread(c.execute,
            "DELETE FROM documents WHERE login=? AND doc_id=?",
            (t.payload["login"], t.payload["doc_id"]))
        await asyncio.to_thread(c.execute,
            "DELETE FROM u_documents WHERE doc_id=?",
            (t.payload["doc_id"],))
        await asyncio.to_thread(c.execute,
            "DELETE FROM comments WHERE doc_id=?",
            (t.payload["doc_id"],))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_rm_u_doc(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT u_doc_path FROM u_documents WHERE u_doc_id=?",
            (t.payload["u_doc_id"],))
        row = cur.fetchone()
        if row:
            try: Path(row[0]).unlink()
            except: pass
        await asyncio.to_thread(c.execute,
            "DELETE FROM u_documents WHERE u_doc_id=?",
            (t.payload["u_doc_id"],))
        await asyncio.to_thread(c.execute,
            "DELETE FROM signatures WHERE u_doc_id=?",
            (t.payload["u_doc_id"],))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_get_content(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT doc_id,doc_name,content,create_date,edited_date,status FROM documents WHERE login=?",
            (t.payload["login"],))
        rows = cur.fetchall()
        res = {r[0]: {"doc_name": r[1], "content": r[2], "create_date": r[3], "edited_date": r[4], "status": r[5]} for r in rows}
        t.fut.set_result(res)

    async def _op_add_comment(self, c, t):
        now = datetime.datetime.utcnow().isoformat()
        cur = await asyncio.to_thread(c.execute,
            "INSERT INTO comments(doc_id,author,date,content) VALUES(?,?,?,?)",
            (t.payload["doc_id"], t.payload["author"], now, t.payload["comment"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_upd_comment(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE comments SET content=? WHERE com_id=? AND author=?",
            (t.payload["new_comment"], t.payload["com_id"], t.payload["author"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_rm_comment(self, c, t):
        await asyncio.to_thread(c.execute,
            "DELETE FROM comments WHERE com_id=? AND author=?",
            (t.payload["com_id"], t.payload["author"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_get_docs(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT doc_id,doc_name,content,create_date,edited_date,status FROM documents WHERE login=?",
            (t.payload["login"],))
        rows = cur.fetchall()
        res = {r[0]: {"doc_name": r[1], "content": r[2], "create_date": r[3], "edited_date": r[4], "status": r[5]} for r in rows}
        t.fut.set_result(res)

    async def _op_get_u_docs(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT u_doc_id,u_doc_name,u_doc_path FROM u_documents WHERE doc_id=?", 
            (t.payload["doc_id"],))
        rows = cur.fetchall()
        res = {r[0]: {"u_doc_name": r[1], "u_doc_path": r[2]} for r in rows}
        t.fut.set_result(res)

    async def _op_get_versions(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT version_id,version_date,doc_name,content FROM document_versions WHERE doc_id=? ORDER BY version_id",
            (t.payload["doc_id"],))
        rows = cur.fetchall()
        res = {r[0]: {"version_date": r[1], "doc_name": r[2], "content": r[3]} for r in rows}
        t.fut.set_result(res)

    async def _op_sign_doc(self, c, t):
        dst = self._encrypt_and_store(t.payload["sig_path"], DIR_SIGNS)
        cur = await asyncio.to_thread(c.execute,
            "INSERT INTO signatures(u_doc_id,login,sign_path) VALUES(?,?,?)",
            (t.payload["u_doc_id"], t.payload["login"], dst))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_get_signs(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT sig_id,login,sign_path FROM signatures WHERE u_doc_id IN "
            "(SELECT u_doc_id FROM u_documents WHERE doc_id=? AND login=?)",
            (t.payload["doc_id"], t.payload["author"]))
        rows = cur.fetchall()
        res = {r[0]: {"login": r[1], "sign_path": r[2]} for r in rows}
        t.fut.set_result(res)

    async def _op_verify_sign(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT cer_path FROM certificates WHERE login=? AND cer_id=?",
            (t.payload["login"], t.payload["cer_id"]))
        row = cur.fetchone()
        ok = False
        if row and Path(t.payload["doc_path"]).exists():
            ok = True
        t.fut.set_result(ok)

    async def _op_get_comments(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "SELECT com_id,author,date,content FROM comments WHERE doc_id=?",
            (t.payload["doc_id"],))
        rows = cur.fetchall()
        res = {r[0]: {"author": r[1], "date": r[2], "content": r[3]} for r in rows}
        t.fut.set_result(res)

    async def _op_set_status(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE documents SET status=? WHERE login=? AND doc_id=?", 
            (t.payload["status"], t.payload["login"], t.payload["doc_id"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_send_doc(self, c, t):
        cur = await asyncio.to_thread(c.execute,
            "INSERT INTO inbox(login,author,doc_id) VALUES(?,?,?)",
            (t.payload["send_to"], t.payload["author"], t.payload["doc_id"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_get_inbox(self, c, t):
        login = t.payload.get('login', '')

        # Сначала загружаем все документы пользователя
        cur_docs = await asyncio.to_thread(
            c.execute,
            "SELECT doc_id, doc_name, content, create_date, edited_date, status "
            "FROM documents WHERE login=?",
            (login,)
        )
        doc_rows = await asyncio.to_thread(cur_docs.fetchall)
        # Формируем словарь документов: {doc_id: {…}}
        documents = {
            r[0]: {
                "doc_name":    r[1],
                "content":     r[2],
                "create_date": r[3],
                "edited_date": r[4],
                "status":      r[5],
            }
            for r in doc_rows
        }

        # Теперь получаем входящие
        cur = await asyncio.to_thread(
            c.execute,
            "SELECT inb_id, author, doc_id, signed, archived FROM inbox WHERE login=?",
            (login,)
        )
        rows = await asyncio.to_thread(cur.fetchall)

        # Собираем окончательный результат, включая вложенный документ
        res = {
            r[0]: {
                "author":   r[1],
                "doc_id":   r[2],
                "signed":   bool(r[3]),
                "archived": bool(r[4]),
                "doc":      documents.get(r[2], {})
            }
            for r in rows
        }

        t.fut.set_result(res)

    async def _op_archive(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE inbox SET archived=1 WHERE inb_id=?", (t.payload["inb_id"],))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    async def _op_unarchive(self, c, t):
        await asyncio.to_thread(c.execute,
            "UPDATE inbox SET archived=0 WHERE inb_id=?", (t.payload["inb_id"],))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)

    # операции контактов
    async def _op_add_contact(self, c, t):
        cur = await asyncio.to_thread(c.execute, # "INSERT INTO u_documents(doc_id, u_doc_name, u_doc_path) VALUES (?,?,?)",
            "INSERT INTO contacts(login, name, contact) VALUES (?,?,?)",
            (t.payload["login"], t.payload["name"], t.payload["contact"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(cur.lastrowid)

    async def _op_get_contacts(self, c, t):
        login = t.payload.get('login')
        # выполняем запрос
        cur = await asyncio.to_thread(
            c.execute,
            "SELECT con_id, name, contact FROM contacts WHERE login=?",
            (login,)
        )
        # получаем все строки
        rows = await asyncio.to_thread(cur.fetchall)
        # строим результат
        res = {r[0]: {'name': r[1], 'contact': r[2]} for r in rows}
        t.fut.set_result(res)

    async def _op_remove_contact(self, c, t):
        await asyncio.to_thread(c.execute,
            "DELETE FROM contacts WHERE login=? AND con_id=?",
            (t.payload["login"], t.payload["con_id"]))
        await asyncio.to_thread(c.commit)
        t.fut.set_result(True)
