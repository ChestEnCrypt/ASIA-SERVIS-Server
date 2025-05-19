Документация модуля main.py
версия: 2025-05-19

обзор
файл main.py реализует HTTP-API на Flask для управления пользователями, токенами, документами, контактами и подтверждениями. все долгие операции выполняются в фоне через единый asyncio-loop и очередь задач.

зависимости
pip install flask flask_jwt_extended cryptography

конфигурация
в app.config задаются
JWT_SECRET_KEY
JWT_ACCESS_TOKEN_EXPIRES
JWT_REFRESH_TOKEN_EXPIRES

архитектура фоновых воркеров
при старте создаётся отдельный asyncio-loop, на котором запускаются воркеры
DBWorker, RTWorker, DCWorker, MailWorker
из Flask-обработчиков для них вызываются продюсеры через run_async(coro)

api эндпоинты

| Endpoint                                         | Method | JSON Body or params                                               | Описание                                                      |
| ------------------------------------------------ | ------ | ----------------------------------------------------------------- | ------------------------------------------------------------- |
| /signup/checkavailable/login                     | GET    | value в query (`?value=<login>`)                                  | проверить, занят ли e-mail                                    |
| /signup/checkavailable/phone                     | GET    | value в query (`?value=<phone>`)                                  | проверить, занят ли телефон                                   |
| /signup/checkavailable/iin                       | GET    | value в query (`?value=<iin>`)                                    | проверить, занят ли ИИН                                       |
| /signup                                          | POST   | { login, password, full_name, phone, iin?, role? }                | регистрация, сохранение и отправка access+refresh             |
| /signup/verify                                   | POST   | { login }                                                         | отправить e-mail для подтверждения                            |
| /signup/verify/check                             | POST   | { login }                                                         | проверить статус подтверждения e-mail                         |
| /signup/verify/confirm                           | GET    | token в query (`?token=<token>`)                                  | подтвердить e-mail по ссылке                                  |
| /login                                           | POST   | { login, password }                                               | вход по паролю, выдача JWT                                    |
| /refresh                                         | POST   | JWT refresh-токен в заголовке                                     | обновить access-токен                                         |
| /update/login                                    | PATCH  | { login, new_login }                                              | сменить e-mail                                                |
| /update/password                                 | PATCH  | { login, new_password }                                           | сменить пароль                                                |
| /update/phone                                    | PATCH  | { login, new_phone }                                              | сменить телефон                                               |
| /update/role                                     | PATCH  | { login, new_role }                                               | сменить роль                                                  |
| /update/iin                                      | PATCH  | { login, new_iin }                                                | сменить ИИН                                                   |
| /update/verify                                   | POST   | { token }                                                         | подтверждение e-mail через токен                              |
| /update/delete                                   | DELETE | { login }                                                         | удалить аккаунт                                               |
| /contacts                                        | POST   | { login, contact }                                                | добавить контакт (e-mail другого пользователя)                |
| /contacts                                        | GET    | { login } или query (`?login=<login>`)                            | получить список контактов                                     |
| /contacts/<con_id>                               | DELETE | { login }                                                         | удалить контакт по con_id                                     |
| /documents                                       | GET    | query (`?login=<login>`)                                          | список документов                                             |
| /documents                                       | POST   | { login, doc_name?, content?, status? }                           | создать документ                                              |
| /documents/<doc_id>                              | GET    | query (`?login=<login>`)                                          | получить содержимое и метаданные документа                    |
| /documents/<doc_id>                              | PATCH  | { login, new_name?, new_content?, status? }                       | обновить документ (сохранить предыдущую версию автоматически) |
| /documents/<doc_id>                              | DELETE | { login }                                                         | удалить документ и все связанные данные                       |
| /documents/<doc_id>/files                        | POST   | multipart form-data (login, file)                                 | загрузить файл (subdocument)                                  |
| /documents/<doc_id>/files                        | GET    | { login } или query (`?login=<login>`)                            | список файлов документа                                       |
| /documents/<doc_id>/subdocuments                 | POST   | multipart form-data (login, file)                                 | загрузить вложенный файл                                      |
| /documents/<doc_id>/subdocuments/<u_doc_id>      | PATCH  | { login, new_name }                                               | переименовать вложенный файл                                  |
| /documents/<doc_id>/subdocuments/<u_doc_id>      | DELETE | { login }                                                         | удалить вложенный файл                                        |
| /sign/send/sigfile                               | POST   | multipart form-data (login, author, doc_id, u_doc_id, sigfile)    | подписать файл                                                |
| /sign/send/certificate                           | POST   | multipart form-data (login, certificate)                          | загрузить сертификат                                          |
| /sign/verify                                     | POST   | { login, doc_path, cer_id }                                       | проверить подпись (наличие файла и сертификата)               |
| /sign/doc_signs                                  | GET    | query (`?login=<login>&doc_id=<doc_id>`)                          | список подписей по документу                                  |
| /certificate                                     | GET    | query (`?login=<login>`)                                          | список сертификатов                                           |
| /inbox                                           | GET    | { login } или query (`?login=<login>`)                            | входящие документы                                            |
| /inbox/<inb_id>/archive                          | POST   | { login }                                                         | архивировать входящий документ                                |
| /inbox/<inb_id>/unarchive                        | POST   | { login }                                                         | разархивировать входящий документ                             |
| /comment                                         | POST   | { login, author, doc_id, content }                                | добавить комментарий                                          |
| /comment                                         | GET    | query (`?login=<login>&doc_id=<doc_id>`)                          | список комментариев по документу                              |
| /comment/<com_id>                                | PATCH  | { login, content }                                                | обновить свой комментарий                                     |
| /comment/<com_id>                                | DELETE | { login }                                                         | удалить свой комментарий                                      |
