# Документация модуля document_flow
Версия: 2025-05-16

Назначение
Модуль document_flow управляет всеми аспектами работы с документами в системе: хранением файлов, версионированием, подписями, комментариями, входящими сообщениями и контактами пользователей. Все операции выполняются асинхронно через одну общую очередь задач и одного воркера, что исключает гонки данных и упрощает масштабирование.

Схема базы данных

```sql
CREATE TABLE certificates(
  cer_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  login        TEXT,
  cer_name     TEXT,
  cer_path     TEXT
);

CREATE TABLE documents(
  doc_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  login        TEXT,
  doc_name     TEXT,
  content      TEXT,
  create_date  TEXT,
  edited_date  TEXT,
  status       INTEGER DEFAULT 0
);

CREATE TABLE u_documents(
  u_doc_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id       INTEGER,
  u_doc_name   TEXT,
  u_doc_path   TEXT
);

CREATE TABLE document_versions(
  version_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id       INTEGER,
  version_date TEXT,
  doc_name     TEXT,
  content      TEXT
);

CREATE TABLE signatures(
  sig_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  u_doc_id     INTEGER,
  login        TEXT,
  sign_path    TEXT
);

CREATE TABLE comments(
  com_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id       INTEGER,
  author       TEXT,
  date         TEXT,
  content      TEXT
);

CREATE TABLE inbox(
  inb_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  login        TEXT,
  author       TEXT,
  doc_id       INTEGER,
  signed       INTEGER DEFAULT 0,
  archived     INTEGER DEFAULT 0
);

CREATE TABLE contacts(
  con_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  login        TEXT,
  contact      TEXT
);
```

Архитектура
каждая операция описывается объектом Task и публикуется в общую asyncio.Queue
один экземпляр DCWorker постоянно извлекает задачи из очереди и выполняет их в пуле потоков через asyncio.to_thread, возвращая результаты в Future

Публичные методы DCProducer

| метод                         | что делает                                    | аргументы                                     | возвращает         |
| ----------------------------- | --------------------------------------------- | --------------------------------------------- | ------------------ |
| add_user_certificate          | добавить сертификат пользователя              | login, cert_path                              | cer_id (int)       |
| get_user_certificates         | получить все сертификаты                      | login                                         | {cer_id: {…}}      |
| update_user_certificate       | переименовать сертификат                      | login, cer_id, new_name                       | True               |
| remove_user_certificate       | удалить сертификат                            | login, cer_id                                 | True               |
| create_document               | создать запись документа                      | login                                         | doc_id (int)       |
| get_documents                 | получить список документов                    | login                                         | {doc_id: {…}}      |
| get_document_content          | получить конкретный документ                  | login, doc_id                                 | {doc_name, content, create_date, edited_date, status} |
| update_document_contents      | обновить имя или содержимое документа         | login, doc_id, new_name, new_content          | True               |
| get_document_versions         | получить все версии указанного документа      | login, doc_id                                 | {version_id: {…}}  |
| add_document_file             | добавить файл к документу                     | login, doc_id, file_path                      | u_doc_id (int)     |
| get_document_files            | получить файлы документа                      | author, doc_id                                | {u_doc_id: {…}}    |
| update_u_document_contents    | переименовать файл внутри документа           | login, doc_id, u_doc_id, new_name             | True               |
| remove_documents              | удалить документ и все связанные данные       | login, doc_id                                 | True               |
| remove_u_document             | удалить один файл из документа                | login, doc_id, u_doc_id                       | True               |
| add_document_comment          | добавить комментарий к документу              | login, author, doc_id, comment                | com_id (int)       |
| get_document_comments         | получить список комментариев                  | author, doc_id                                | {com_id: {…}}      |
| update_document_comment       | изменить текст своего комментария             | author, doc_id, com_id, new_comment           | True               |
| remove_document_comment       | удалить свой комментарий                      | author, doc_id, com_id                        | True               |
| sign_document                 | подписать файл документа                      | login, author, doc_id, u_doc_id, sig_path     | sig_id (int)       |
| get_document_signs            | получить список подписей по документу         | author, doc_id                                | {sig_id: {…}}      |
| verify_document_signature     | проверить наличие подписи и сертификата       | login, doc_path, cer_id                       | bool               |
| set_document_status           | изменить статус документа                     | login, doc_id, status                         | True               |
| send_document                 | отправить документ другому пользователю       | send_to, author, doc_id                       | inb_id (int)       |
| get_inbox                     | получить входящие документы                   | login                                         | {inb_id: {…}}      |
| archive_document              | пометить входящее как архивированное          | login, inb_id                                 | True               |
| unarchive_document            | разархивировать входящее                      | login, inb_id                                 | True               |
| add_contact                   | добавить контакт (login другого пользователя) | login, contact                                | con_id (int)       |
| get_contacts                  | получить список контактов                     | login                                         | {con_id: contact}  |
| remove_contact                | удалить контакт                               | login, con_id                                 | True               |

Шифрование и хранение файлов
модуль хранит ключ в файле encryption.key и использует Fernet для симметричного шифрования при сохранении сертификатов, документов и подписей
исходные данные читаются из переданных путей, шифруются, сохраняются в директории documents, signs или certificates с уникальным именем

Пример использования

```python
import asyncio
from document_flow import DCWorker, DCProducer

async def main():
    asyncio.create_task(DCWorker().run())
    dc = DCProducer()

    # добавить контакт
    con_id = await dc.add_contact("alice@example.com", "bob@example.com")

    # создать документ
    doc_id = await dc.create_document("alice@example.com")

    # обновить содержимое и сохранить предыдущую версию
    await dc.update_document_contents(
      login="alice@example.com",
      doc_id=doc_id,
      new_name="проект 1",
      new_content="текст документа"
    )

    # получить историю версий
    versions = await dc.get_document_versions("alice@example.com", doc_id)

    # добавить файл к документу
    u_id = await dc.add_document_file("alice@example.com", doc_id, "report.pdf")

    # подписать файл
    sig_id = await dc.sign_document("alice@example.com", "alice@example.com", doc_id, u_id, "report.sig")

    # получить список контактов
    contacts = await dc.get_contacts("alice@example.com")

    await asyncio.sleep(0.1)

asyncio.run(main())
```
