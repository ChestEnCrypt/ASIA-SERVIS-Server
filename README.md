| ASIA SERVIS - Server

в main.py нужно реализовать методы для работы с клиентом

| метод               | вид метода |  что оно делает                                        | client -> server                                   | server -> client
| ------------------- | ---------- | ------------------------------------------------------ | -------------------------------------------------- | -------------------------------
| /signup             |            | запрос на регистрацию                                  |                                                    | 
|   /checkavailable   |            | проверка на доступность полей                          |                                                    | 
|     /login          | GET        | проверка login                                         | {"login"}                                          | {bool} # True - занято, False - свободный
|     /phone          | GET        | проверка phone                                         | {"phone"}                                          | {bool} # True - занято, False - свободный
|     /iin            | GET        | проверка iin                                           | {"iin"}                                            | {bool} # True - занято, False - свободный
|   /signup           | POST       | зарегистрирует пользователя                            | {"login", "phone", "iin"}                          | {"error_type", bool, bool, bool} | {"success", access_tocen, refresh_token}
|   /verify           | POST       | подтверждает эл. почту через отправку подтверждение    | {"login"}                                          | {bool} # True - подтверждено, False - неподтверждено
|                     |            |                                                        |                                                    | 
| /login              |            | вход в личный кобинет                                  |                                                    | 
|   /once             | POST       | вход на один раз                                       | {"login", "password", "once"}                      | {false, "error_type"} | {true, access_tocen, refresh_token} # оштбка | успех
|   /longtime         | POST       | долгосрочный вход                                      | {"login", "password", "longtime"} | {access_tocen} | {false, "error_type"} | {true, access_tocen, refresh_token} # оштбка | успех
|                     |            |                                                        |                                                    | 
| /update             |            | обновить свои данные о пользователе                    |                                                    | 
|   /login            | POST       | обновить login                                         | {"login", "new_login"}                             | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /password         | POST       | обновить password                                      | {"login", "new_password"}                          | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /phone            | POST       | обновить phone                                         | {"login", "new_phone"}                             | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /role             | POST       | обновить role                                          | {"login", "new_role"}                              | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /iin              | POST       | обновить iin                                           | {"login", "new_iin"}                               | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /verify           | POST       | подтверждает эл. почту через отправку подтверждение    | {"login"}                                          | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /delete           | POST       | удаляет аккаунт                                        | {"login"}                                          | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|                     |            |                                                        |                                                    | 
| /contacts           |            | управление контактами                                  |                                                    | 
|   /add              | POST       | добавление нового контакта                             | {"login", "contact"}                               | {con_id} # возвращает id только что созданного контакта
|   /getall           | GET        | получить все контакты                                  | {"login"}                                          | {con_id: contact} # возвращает словарь со всеми контактами
|   /remove           | POST       | удалить контакт                                        | {"login", "con_id"}                                | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|                     |            |                                                        |                                                    | 
| /documents          |            | управление своими документами                          |                                                    | 
|   /getall           | GET        | получение всех своих документов                        | {"login"}                                          | {doc_id: {...}} # возвращает словарь с ключем, внутри doc_id: {doc_name, content, create_date, edited_date, status}
|   /get              | GET        | запрос на данных конкретного документа                 | {"author", "doc_id"}                               | {doc_name, content, create_date, edited_date, status}
|     /files          | GET        | запрос на файлы конкретного документа                  | {"author", "doc_id"}                               | {u_doc_id: {...}} # возвращает поддокументы из документа, внутри u_doc_id: {u_doc_name}
|                     |            |                                                        |                                                    | 
|   /edit             |            | режим редактирование документа                         |                                                    | 
|     /new            | POST       | создание нового документа                              | {"login"}                                          | {doc_id} # возвращает id только что созданного документа
|     /set            |            | обнавление документа                                   |                                                    | 
|       /name         | POST       | обновление имени документа                             | {"login", "doc_id", "new_name"}                    | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|       /content      | POST       | обновление содержание документа                        | {"login", "doc_id", "new_content"}                 | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|       /status       | POST       | задает статус документа                                | {"login", "doc_id", "new_status"}                  | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|     /subdocument    |            | изменение поддокументом                                |                                                    | 
|       /add          | POST       | добавление поддокумента в документ                     | {"login", "doc_id", new_u_doc}                     | {u_doc_id} # возвращает id только что загруженного документа
|       /setname      | POST       | изменение название поддокумента                        | {"login", "doc_id", "u_doc_id", "new_name"}        | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|       /remove       | POST       | удаление поддокумента                                  | {"login", "doc_id", "u_doc_id"}                    | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|     /remove         | POST       | удаление документа                                     | {"login", "doc_id"}                                | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|                     |            |                                                        |                                                    | 
|   /sendto           | POST       | запрос на отправление документа на другой пользователь | {"send_to", "author", "doc_id"}                    | {inb_id} # возвращает id отправленного документа
|                     |            |                                                        |                                                    | 
| /inbox              |            | управление документами из входящего                    |                                                    | 
|   /getall           | GET        | запрос на получение всех документов из inbox           | {"login"}                                          | {inb_id: {…}} # возвращает все документы из входящих, внутри inb_id: {author, doc_id, signed, archived}_
|   /archive          | POST       | архивация документа                                    | {"login", "inb_id"}                                | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /unarchive        | POST       | разархивация документа                                 | {"login", "inb_id"}                                | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /get              | GET        | запрос на конкреный документ                           | {"login", "inb_id"}                                | {author, doc_id, doc_name, content, create_date, edited_date, status} # возвращает конкретный документ из входящих
|                     |            |                                                        |                                                    | 
| /comment            |            | управление коментариями                                |                                                    | 
|   /add              | POST       | добавление коментария к документу                      | {"login", "author", "doc_id", "content"}           | {com_id} # возвращает id коментария только что добавленного документа
|   /edit             |            | изменение коментария                                   |                                                    | 
|     /set            |            | задать                                                 |                                                    | 
|       /content      | POST       | контент коментария                                     | {"author", "doc_id", "com_id", "new_content"}      | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|     /remove         | POST       | удалить коментарий                                     | {"author", "doc_id", "com_id"}                     | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /get              |            |                                                        |                                                    | 
|     /doc_coment     | GET        | получение коментариев к документу                      | {"author", "doc_id"}                               | {com_id: {…}} # возвращает список коментариев из документа, внутри com_id: {author, date, content}
|                     |            |                                                        |                                                    | 
| /certificate        |            | управление сертификатами                               |                                                    | 
|   /send             |            | получение файлов                                       |                                                    | 
|     /sigfile        | POST       | подписанный файл                                       | {"login", "author", "doc_id", "u_doc_id", signfile}| {sig_id} # возвращает id только что загруженного файла
|     /certificate    | POST       | сертификат ключа                                       | {"login", "cer_name", certificate}                 | {cer_id} # возвращает id только что загруженного файла
|   /edit             |            |                                                        |                                                    | 
|     /set            |            |                                                        |                                                    | 
|       /name         | POST       | изменение имени сертификата                            | {"login", "cer_id", "new_name"}                    | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|   /get              |            |                                                        |                                                    | 
|     /verify         | POST       | получает сведение о подлинности подписи                | {"login", "doc_id", "u_doc_id", "sig_id"}          | {bool, "error_type"} # True - при успехе | False - при неудаче (+"error_type")
|     /doc_signs      | GET        | получение всех подписей к документу                    | {"author", "doc_id"}                               | {sig_id: {…}} # возвращает все подписи документа, внутри sig_id: {u_doc_id}
|     /certificates   | GET        | получение всех сертификатов пользователя               | {"login"}                                          | {cer_id: {…}} # возвращает все сертификаты пользователя, внутри cer_id: {cer_name}
