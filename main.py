import os
import base64
import asyncio
import threading
from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, decode_token
)
from werkzeug.utils import secure_filename

from UserManagement.db_core import DBWorker, DBProducer
from UserManagement.refresh_token_core import RTWorker, RTProducer
from DocManagement.document_flow import DCWorker, DCProducer
from EmailConfirmation.email_confirm import MailWorker, MailProducer

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# ─────────────────────────── config ───────────────────────────
app = Flask(__name__)
app.config.update(
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "change-me"),
    JWT_ACCESS_TOKEN_EXPIRES=900,        # 15 минут
    JWT_REFRESH_TOKEN_EXPIRES=604800     # 7 дней
)
jwt = JWTManager(app)

# Каталоги для загрузок
UPLOAD_DOCS = "documents"
UPLOAD_SIGS = "signs"
UPLOAD_CERTS = "certificates"
for d in (UPLOAD_DOCS, UPLOAD_SIGS, UPLOAD_CERTS):
    os.makedirs(d, exist_ok=True)

# ─────────────────────── globals ───────────────────────
worker_loop: asyncio.AbstractEventLoop | None = None

db: DBProducer | None = None
rt: RTProducer | None = None

dc: DCProducer | None = None
mail: MailProducer | None = None


# ───────────────────── background workers ─────────────────────
def start_async_workers() -> None:
    global worker_loop, db, rt, dc, mail
    worker_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(worker_loop)

    # Запуск воркеров
    worker_loop.create_task(DBWorker().run())
    worker_loop.create_task(RTWorker().run())
    worker_loop.create_task(DCWorker().run())
    worker_loop.create_task(MailWorker().run())

    # Инициализация продюсеров
    db = DBProducer()
    rt = RTProducer()
    dc = DCProducer()
    mail = MailProducer()

    worker_loop.run_forever()

# Запуск воркеров в отдельном потоке
threading.Thread(target=start_async_workers, daemon=True).start()


def run_async(coro):
    """
    Schedule coroutine on background event loop and wait for result.
    """
    future = asyncio.run_coroutine_threadsafe(coro, worker_loop)
    return future.result()


# ───────────────────────── Auth / signup ─────────────────────────
# signup check
@app.route('/signup/checkavailable/login')
def check_login():
    val = request.args.get('value', '')
    taken = run_async(db.check_free(login=val)).get('login')
    return jsonify(login=taken), 200

@app.route('/signup/checkavailable/phone')
def check_phone():
    val = request.args.get('value', '')
    taken = run_async(db.check_free(phone=val)).get('phone')
    return jsonify(phone=taken), 200

@app.route('/signup/checkavailable/iin')
def check_iin():
    val = request.args.get('value', '')
    taken = run_async(db.check_free(iin=val)).get('iin')
    return jsonify(iin=taken), 200

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    required = ('login', 'password', 'full_name', 'phone')
    if not all(k in data for k in required):
        return jsonify(error='missing_fields'), 400

    # conflict if fields taken
    status = run_async(db.check_free(
        login=data['login'], phone=data['phone'], iin=data.get('iin','')
    ))
    if any(status.values()):
        # invert: True=available, False=taken
        return jsonify({k: not v for k,v in status.items()}), 409

    if not run_async(mail.is_confirm(data['login'])):
        return jsonify(login=False, error="Логин не подтвержден")

    run_async(mail.cleanup(data['login']))

    # поля свободны — создаём пользователя
    user_id = run_async(db.add_user(
        login=data['login'], password=data['password'],
        full_name=data['full_name'], phone=data['phone'],
        role=data.get('role',''), iin=data.get('iin','')
    ))
    access = create_access_token(identity=str(user_id))
    refresh = create_refresh_token(identity=str(user_id))
    tok = decode_token(refresh)
    run_async(rt.add_refresh_token(str(user_id), tok['jti'], tok['exp']))

    return jsonify(login=True, access_token=access, refresh_token=refresh), 201

@app.route('/signup/verify', methods=['POST'])
def signup_verify():
    data = request.get_json() or {}
    login = data.get('login', '')
    if not login:
        return jsonify({"error": "login required"}), 400
    elif '@' not in login:
        return jsonify({"error": "incorrect login"}), 400

    ok = run_async(mail.email_confirm(login))
    return jsonify({'success': ok}), 200

@app.route('/signup/verify/check', methods=['POST'])
def signup_verify_check():
    data = request.get_json() or {}
    login = data.get('login', '')
    if not login:
        return jsonify({"error": "login required"}), 400

    e_con = run_async(mail.is_confirm(login))

    return jsonify(e_con), 200

@app.route('/signup/verify/confirm', methods=['GET'])  # если через ссылку
def signup_verify_confirm():
    token = request.args.get('token', '')
    if not token:
        return jsonify({"error": "Missing token"}), 400

    ok = run_async(mail.mark_confirmed(token))
    if not ok:
        return jsonify({"error": "Invalid or expired token"}), 400

    return jsonify({"message": "Email confirmed!"}), 200


# ──────────────────────── Login / refresh ─────────────────────────
# login once
@app.route('/login', methods=['POST'])
def login_once():
    data = request.get_json() or {}
    user = run_async(db.auth(data.get('login'), data.get('password')))
    if not user:
        return jsonify(login=False), 401
    # ensure identity as string
    access = create_access_token(identity=str(user))
    refresh = create_refresh_token(identity=str(user))
    tok = decode_token(refresh)
    run_async(rt.add_refresh_token(str(user), tok['jti'], tok['exp']))
    return jsonify(login=True, access_token=access, refresh_token=refresh), 200

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    uid = get_jwt_identity()
    tok_hdr = request.headers.get('Authorization','').split()[-1]
    tok = decode_token(tok_hdr)
    if run_async(rt.is_token_revoked(tok['jti'])):
        return jsonify(error='revoked'), 401
    new_access = create_access_token(identity=uid)
    return jsonify(access_token=new_access), 200


# ───────────────────── Profile / update ─────────────────────────
# update login
@app.route('/update/login', methods=['PATCH'])
def update_login():
    data = request.get_json() or {}
    taken = run_async(db.check_free(login=data.get('new_login')))['login']
    if taken:
        return jsonify(login=False, error='taken'), 409
    run_async(db.set_login(data.get('login'), data.get('new_login')))
    return jsonify(login=True), 200

# update password
@app.route('/update/password', methods=['PATCH'])
def update_password():
    data = request.get_json() or {}
    run_async(db.update_password(data.get('login'), data.get('new_password')))
    return jsonify(password=True), 200

@app.route('/update/phone', methods=['PATCH'])
def update_phone():
    data = request.get_json() or {}
    taken = run_async(db.check_free(phone=data.get('new_phone')))['phone']
    if taken:
        return jsonify(phone=False, error='taken'), 409
    run_async(db.update_info(login=data.get('login'), phone=data.get('new_phone')))
    return jsonify(phone=True), 200

@app.route('/update/role', methods=['PATCH'])
def update_role():
    data = request.get_json() or {}
    run_async(db.set_role(data.get('login'), data.get('new_role')))
    return jsonify(role=True), 200

@app.route('/update/iin', methods=['PATCH'])
def update_iin():
    data = request.get_json() or {}
    ok = run_async(db.check_free(iin=data.get('new_iin')))['iin']
    if not ok:
        return jsonify(iin=False, error='taken'), 409
    run_async(db.update_iin(data.get('login'), data.get('new_iin')))
    return jsonify(iin=True), 200

@app.route('/update/verify', methods=['POST'])
def update_verify():
    data = request.get_json() or {}
    ok = run_async(mail.mark_confirmed(data.get('token','')))
    return jsonify(confirmed=bool(ok)), 200

@app.route('/update/delete', methods=['DELETE'])
def delete_account():
    data = request.get_json() or {}
    ok = run_async(db.delete_user(data.get('login','')))
    return jsonify(deleted=bool(ok)), 200


# ───────────────────────── Contacts ─────────────────────────
@app.route('/contacts', methods=['POST'])
def add_contact():
    data = request.get_json(silent=True) or {}
    cid = run_async(dc.add_contact(login=data.get('login'), name=data.get('name'), contact=data.get('contact')))
    return jsonify(con_id=cid), 201

@app.route('/contacts', methods=['GET'])
def list_contacts():
    data = request.get_json(silent=True) or {}
    res = run_async(dc.get_contacts(data.get('login')))
    return jsonify(res), 200

@app.route('/contacts/<int:con_id>', methods=['DELETE'])
def remove_contact(con_id):
    data = request.get_json(silent=True) or {}
    ok = run_async(dc.remove_contact(data.get('login'), con_id))
    return jsonify(removed=bool(ok)), 200


# ─────────────────────── Documents ─────────────────────────
@app.route('/documents', methods=['GET'])
def list_documents():
    lg = request.args.get('login','')
    res = run_async(dc.get_documents(lg))
    return jsonify(res), 200

@app.route('/documents/<int:doc_id>', methods=['GET'])
def get_document(doc_id):
    lg = request.args.get('login','')
    res = run_async(dc.get_document_content(lg, doc_id))
    return jsonify(res), 200

@app.route('/documents/<int:doc_id>/defiles', methods=['GET'])
def documents_defiles(doc_id):
    # GET – вернуть список всех файлов для doc_id
    login = request.args.get('login','')
    # получаем первоначальный список из DCProducer
    files_list = run_async(dc.get_document_files(login, doc_id))

    result = {}
    for fid, info in files_list.items():
        name = info['u_doc_name']
        path = info['u_doc_path']
        try:
            # получаем зашифрованные байты и расшифровываем
            raw = run_async(dc.decrypt_file(path))   # ← bytes
            # кодируем в строку Base64
            b64 = base64.b64encode(raw).decode('ascii')
            result[fid] = {
                'u_doc_name': name,
                'u_doc_file': b64
            }
        except Exception as e:
            result[fid] = {
                'u_doc_name': name,
                'error': str(e)
            }

    return jsonify(result), 200

@app.route('/documents/<int:doc_id>/files', methods=['POST', 'GET'])
def documents_files(doc_id):
    # POST – загрузить файл
    if request.method == 'POST':
        login = request.form.get('login','')
        if 'file' not in request.files:
            return jsonify(error='no_file'), 400
        f = request.files['file']
        filename = secure_filename(f.filename)
        dest = os.path.join(UPLOAD_DOCS, login, str(doc_id))
        os.makedirs(dest, exist_ok=True)
        path = os.path.join(dest, filename)
        f.save(path)
        u_doc_id = run_async(dc.add_document_file(login, filename, doc_id, path))
        return jsonify(u_doc_id=u_doc_id), 201

    # GET – вернуть список всех файлов для doc_id
    login = request.args.get('login','')
    files_list = run_async(dc.get_document_files(login, doc_id))
    return jsonify(files_list), 200

@app.route('/documents', methods=['POST'])
def create_document():
    data = request.get_json() or {}
    doc_id = run_async(dc.create_document(data.get('login')))
    if any(k in data for k in ('name','content','status')):
        run_async(dc.update_document_contents(
            login=data.get('login'), doc_id=doc_id,
            new_name=data.get('name',''),
            new_content=data.get('content',''),
            new_status=data.get('status','')
        ))
    return jsonify(doc_id=doc_id), 201

@app.route('/documents/<int:doc_id>', methods=['PATCH'])
def update_document(doc_id):
    data = request.get_json() or {}
    check = run_async(dc.get_documents(data.get('login')))

    if check[doc_id]['status'] != 10:
        run_async(dc.update_document_contents(
            login=data.get('login'), doc_id=doc_id,
            new_name=data.get('name'),
            new_content=data.get('content'),
            new_status=data.get('status')
        ))
        return jsonify(updated=True), 200
    else :
        return jsonify(updated=False, error="нет разрешения"), 403

@app.route('/documents/remove/<int:doc_id>', methods=['PATCH'])
def remove_document(doc_id):
    login = request.get_json().get('login','')
    check = run_async(dc.get_documents(login))

    if check[doc_id]['status'] == 10:
        return jsonify(error='Нет разрешение'), 403

    data = request.get_json(force=True) or {}
    login = data.get('login')
    if not login:
        return jsonify(error='login required'), 400

    ok = run_async(dc.remove_documents(login=login, doc_id=doc_id))
    return jsonify(updated=bool(ok)), 200

@app.route('/documents/<int:doc_id>/subdocuments', methods=['POST'])
def add_subdocument(doc_id):
    login = request.form.get('login','')
    check = run_async(dc.get_documents(login))

    if check[doc_id]['status'] == 10:
        return jsonify(error='Нет разрешение'), 403

    # Если пришёл JSON – создаём «метадокумент»
    if request.is_json:
        data = request.get_json() or {}
        u_doc_id = run_async(dc.add_subdocument(
            login=data.get('login',''),
            doc_id=doc_id,
            name=data.get('name',''),
            content=data.get('content','')
        ))
        return jsonify(u_doc_id=u_doc_id), 201

    # Иначе – multipart upload файл-поддокумента
    if 'file' not in request.files:
        return jsonify(error='no_file'), 400
    f = request.files['file']
    lg_name = secure_filename(login)
    filename = secure_filename(f.filename)
    dest = os.path.join(UPLOAD_DOCS, login, str(doc_id))
    os.makedirs(dest, exist_ok=True)
    file_path = os.path.join(dest, lg_name + filename)
    f.save(file_path)
    u_doc_id = run_async(dc.add_document_file(login, filename, doc_id, file_path))
    try:
        os.remove(file_path)
    except FileNotFoundError:
        print('Файл на удаление не найден')
    return jsonify(u_doc_id=u_doc_id), 201

@app.route('/documents/<int:doc_id>/subdocuments/<int:u_doc_id>', methods=['PATCH'])
def update_subdocument(doc_id, u_doc_id):
    data = request.get_json() or {}
    run_async(dc.update_u_document_contents(
        login=data.get('login'), doc_id=doc_id,
        u_doc_id=u_doc_id, new_name=data.get('name','')
    ))
    return jsonify(updated=True), 200

@app.route('/documents/<int:doc_id>/subdocuments/<int:u_doc_id>', methods=['DELETE'])
def remove_subdocument(doc_id, u_doc_id):
    login = request.get_json()['login']
    check = run_async(dc.get_documents(login))

    if check[doc_id]['status'] == 10:
        return jsonify(error='Нет разрешение'), 403

    ok = run_async(dc.remove_u_document(login, doc_id, u_doc_id))
    return jsonify(deleted=bool(ok)), 200

@app.route('/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    lg = request.args.get('login','')
    ok = run_async(dc.remove_documents(lg, doc_id))
    return jsonify(deleted=bool(ok)), 200

@app.route('/documents/<int:doc_id>/sendto', methods=['POST'])
def send_document(doc_id):
    data = request.get_json() or {}
    inb_id = run_async(dc.send_document(
        author=data.get('author'), send_to=data.get('send_to'), doc_id=doc_id
    ))
    return jsonify(inbox_id=inb_id), 200


# ───────────────────────── Inbox ─────────────────────────
@app.route('/inbox', methods=['GET'])
def list_inbox():
    lg = request.get_json(silent=True)
    res = run_async(dc.get_inbox(lg.get('login')))
    return jsonify(res), 200

@app.route('/inbox/<int:inb_id>/archive', methods=['POST'])
def archive_document(inb_id):
    lg = request.get_json(silent=True) and request.get_json().get('login') or request.args.get('login','')
    ok = run_async(dc.archive_document(lg, inb_id))
    return jsonify(archived=bool(ok)), 200

@app.route('/inbox/<int:inb_id>/unarchive', methods=['POST'])
def unarchive_document(inb_id):
    lg = request.get_json(silent=True) and request.get_json().get('login') or request.args.get('login','')
    ok = run_async(dc.unarchive_document(lg, inb_id))
    return jsonify(unarchived=bool(ok)), 200

@app.route('/inbox/<int:inb_id>', methods=['GET'])
def get_inbox_document(inb_id):
    lg = request.args.get('login','')
    res = run_async(dc.get_inbox_document(lg, inb_id))
    return jsonify(res), 200


# ─────────────────────── Comments ─────────────────────────
@app.route('/comment', methods=['POST'])
def add_comment():
    data = request.get_json() or {}
    com_id = run_async(dc.add_document_comment(
        login=data.get('login'), author=data.get("author"), doc_id=data.get('doc_id'), comment=data.get('content','')
    ))
    return jsonify(comment_id=com_id), 201

@app.route('/comment', methods=['GET'])
def list_comments():
    lg = request.args.get('login','')
    doc_id = request.args.get('doc_id', type=int)
    res = run_async(dc.get_document_comments(lg, doc_id))
    return jsonify(res), 200

@app.route('/comment/<int:com_id>', methods=['PATCH'])
def update_comment(com_id):
    data = request.get_json() or {}
    ok = run_async(dc.update_document_comment(
        login=data.get('login'), comment_id=com_id, new_comment=data.get('content','')
    ))
    return jsonify(updated=bool(ok)), 200

@app.route('/comment/<int:com_id>', methods=['DELETE'])
def delete_comment(com_id):
    lg = request.args.get('login','')
    ok = run_async(dc.remove_document_comment(lg, com_id))
    return jsonify(deleted=bool(ok)), 200


# ─────── Signatures & Certificates ───────────────────────
@app.route('/sign/send/sigfile', methods=['POST'])
def upload_signature():
    login   = request.form.get('login', '')
    author   = request.form.get('author', '')
    doc_id  = request.form.get('doc_id', type=int)
    u_doc_id= request.form.get('u_doc_id', type=int)

    if 'sigfile' not in request.files:
        return jsonify(error='no_file'), 400

    sig_file = request.files['sigfile']
    signature = sig_file.read()

    # получить путь к сертификату пользователя
    cert_info = run_async(dc.get_user_certificates(login))
    if len(cert_info.values()) < 1:
        return jsonify(error='certificate_not_found'), 404
    cert_path = list(cert_info.values())[0]['cer_path']
    if not cert_path or not os.path.exists(os.getcwd() + '/' + cert_path):
        return jsonify(error='certificate_not_found'), 404

    # загрузить публичный ключ из сертификата
    cert_bytes = open(cert_path, 'rb').read()
    cert = x509.load_pem_x509_certificate(cert_bytes)
    public_key = cert.public_key()

    # получить путь к оригинальному файлу
    doc = run_async(dc.get_document_files(login, doc_id))
    doc_path = doc[u_doc_id]['u_doc_path']
    if not doc_path or not os.path.exists(doc_path):
        return jsonify(error='document_not_found'), 404
    raw = run_async(dc.decrypt_file(doc_path))

    # проверить подпись
    try:
        public_key.verify(
            signature,
            raw,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return jsonify(error='signature_verification_failed'), 400

    # сохраняем файл подписи
    lg_name = secure_filename(login)
    filename = secure_filename(sig_file.filename)
    os.makedirs(UPLOAD_SIGS, exist_ok=True)
    save_path = os.path.join(UPLOAD_SIGS, lg_name + filename)
    with open(save_path, 'wb') as f:
        f.write(signature)

    sig_id = run_async(dc.sign_document(login, author, doc_id, u_doc_id, save_path))
    return jsonify(sig_id=sig_id), 201

@app.route('/sign/send/certificate', methods=['POST'])
def upload_certificate():
    login   = request.form.get('login','')

    # 1) проверяем, есть ли уже сертификат у этого пользователя
    existing = run_async(dc.get_user_certificates(login))
    if existing:
        return jsonify(error='certificate_exists'), 409

    # 2) проверяем, что файл пришёл
    if 'certificate' not in request.files:
        return jsonify(error='no_file'), 400

    # 3) сохраняем новый сертификат
    f = request.files['certificate']
    lg_name = secure_filename(login)
    filename = secure_filename(f.filename)
    os.makedirs(UPLOAD_CERTS, exist_ok=True)
    cer_path = os.path.join(UPLOAD_CERTS, lg_name + filename)
    f.save(cer_path)

    # 4) записываем в БД
    cer_id = run_async(dc.add_user_certificate(login, cer_path))
    return jsonify(certificate_id=cer_id), 201

@app.route('/sign/verify', methods=['POST'])
def verify_signature():
    data = request.get_json() or {}
    ok = run_async(dc.verify_document_signature(
        login=data.get('login'), doc_id=data.get('doc_id'),
        u_doc_id=data.get('u_doc_id'), sig_id=data.get('sig_id')
    ))
    return jsonify(verified=bool(ok)), 200

@app.route('/sign/doc_signs', methods=['GET'])
def list_document_signs():
    lg = request.get_json('login')
    doc = request.get_json('doc_id')
    print("doc_id", doc['doc_id'])
    print('login', lg)
    res = run_async(dc.get_document_signs(lg, int(doc['doc_id'])))
    return jsonify(res), 200

@app.route('/certificate', methods=['GET'])
def list_certificates():
    lg = request.args.get('login')
    res = run_async(dc.get_user_certificates(lg))
    return jsonify(res), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
