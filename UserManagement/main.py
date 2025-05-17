import asyncio, datetime, secrets
from db_core import DBWorker, DBProducer
from refresh_token_core import RTWorker, RTProducer

async def main():
    # поднимаем воркера‑потребителя очереди
    asyncio.create_task(DBWorker().run())
    db = DBProducer()

    # проверяем, свободны ли логин и телефон
    busy = await db.check_free(login="alice@example.com",
                               phone="+77000000001")
    print("занятость:", busy)
    if any(busy.values()):
        print("данные заняты, выходим")
        return

    # создаём пользователя
    await db.add_user(
        login="alice@example.com",
        password="secret123",
        full_name="Alice Ivanova",
        phone="+77000000001",
        role="admin"
    )
    print("аккаунт создан")

    # успешный вход
    ok = await db.auth(login="alice@example.com", password="secret123")
    print("успешный вход:", ok)

    # пять неправильных попыток — аккаунт будет заблокирован
    for n in range(5):
        res = await db.auth(login="alice@example.com", password="wrong")
        print(f"попытка {n+1} неверный пароль ->", res)

    # теперь даже правильный пароль не пройдёт
    blocked = await db.auth(login="alice@example.com", password="secret123")
    print("после блокировки вход невозможен:", blocked)

    # запрашиваем токен для сброса пароля
    token = await db.request_pwd_reset("alice@example.com")
    print("токен сброса:", token)

    # применяем новый пароль
    success = await db.reset_password(token, "newpass456")
    print("сброс пароля выполнен:", success)

    # снимаем блокировку (хотя reset_password уже обнулил счётчик)
    await db.unblock("alice@example.com")

    # подтверждаем e‑mail и телефон
    await db.confirm_email("alice@example.com")
    await db.confirm_phone("alice@example.com")

    # проверяем вход с новым паролем
    ok2 = await db.auth(login="alice@example.com", password="newpass456")
    print("вход с новым паролем:", ok2)

    # делаем резервную копию базы
    backup_path = await db.backup("after_flow")
    print("бэкап сохранён в:", backup_path)

    # немного ждём, чтобы воркер успел завершить транзакции
    await asyncio.sleep(0.1)

async def refresh_token_main():
    # запускаем оба воркера
    asyncio.create_task(DBWorker().run())
    asyncio.create_task(RTWorker().run())

    db = DBProducer()
    rt = RTProducer()

    # создаём пользователя
    uid = await db.add_user(
        login="alice@example.com",
        password="secret",
        full_name="Alice",
        phone="+77000000001"
    )

    # выдаём токен
    tok = secrets.token_urlsafe(32)
    exp = (datetime.datetime.utcnow() +
           datetime.timedelta(days=30)).isoformat(sep=" ", timespec="seconds")
    await rt.add_refresh_token(uid, tok, exp)

    ok = await rt.validate_refresh_token(tok, uid)
    print("validate:", ok)                   # True

    await rt.revoke_refresh_token(tok)
    print("revoked?", await rt.is_token_revoked(tok))  # True

    await asyncio.sleep(0.1)

if __name__ == "__main__":
    asyncio.run(refresh_token_main())
