import asyncio
from document_flow import DCWorker, DCProducer

async def main():
    asyncio.create_task(DCWorker().run())
    dc = DCProducer()

    # добавить контакт
    con_id = await dc.add_contact("alice@example.com", "bob@example.com")

    print(con_id)

    # создать документ
    doc_id = await dc.create_document("alice@example.com")

    print(doc_id)

    # обновить содержимое и сохранить предыдущую версию
    await dc.update_document_contents(
      login="alice@example.com",
      doc_id=doc_id,
      new_name="проект 1",
      new_content="текст документа"
    )

    doc = await dc.get_document_content("alice@example.com", doc_id)

    print(doc)

    # получить историю версий
    versions = await dc.get_document_versions("alice@example.com", doc_id)

    print(versions)

    # добавить файл к документу
    u_id = await dc.add_document_file("alice@example.com", doc_id, "main.py")

    print(u_id)

    # подписать файл
    sig_id = await dc.sign_document("alice@example.com", "alice@example.com", doc_id, u_id, "main.py")

    print(sig_id)

    # получить список контактов
    contacts = await dc.get_contacts("alice@example.com")

    print(contacts)

    await asyncio.sleep(0.1)

asyncio.run(main())
