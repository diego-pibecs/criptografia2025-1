### RECONSTRUIDO ###

from flask import Flask, render_template, request, jsonify, redirect, session
from flask_socketio import SocketIO, join_room, leave_room, send
#from flask_session import Session
from Crypto.PublicKey import RSA

from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES, PKCS1_OAEP
import hashlib
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
from uuid import uuid4
import random
import string


app = Flask(__name__)
app.secret_key = 'CriptografiaProyecto'
socketio = SocketIO(app)
#app.config['SESSION_TYPE'] = 'filesystem'

#Session(app)

rooms = {} #Salas
current_room_code = None

def generate_room_code(length: int, existing_codes: list[str]) -> str:
    while True:
        code_chars = [random.choice(string.ascii_letters) for _ in range (length)]
        code = ''.join(code_chars)

        if code not in existing_codes:
            return code

def generate_unique_session_id():
    return str(uuid4())


def sign_message(message, private_key):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_signature(message, signature, public_key):
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("---FIRMA VALIDA")
        return True
    except (ValueError, TypeError):
        print("---FIRMA !!NO!! VALIDA")
        return False


def encrypt_symmetric(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce


def encrypt_asymmetric(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data


def hash_message(message):
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    return hash_object.hexdigest()


def pbkdf(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def create_keys(secret, private_key_path, public_key_path):
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=secret)
    public_key = key.publickey().export_key()
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    print(f"---CLAVES CREADAS Y GUARDAS: \n**PRIVADA: {private_key_path} \n**PUBLICA: {public_key_path}")

#############################
@app.route("/")
def index():
    print("---VENTANA: INICIAR SESION")
    return render_template("iniSesion.html")
# def index():
#     if 'symmetric_key' in session:
#         print("---VENTANA: CHAT")
#         return redirect("/chat")
#     else:
#         print("---VENTANA: INICIAR SESION")
#         return render_template("iniSesion.html")


@app.route("/chat")
def chat():
    if 'symmetric_key' in session:
        room = session.get("room")
        username = session.get("username")
        if username is None or room is None or room not in rooms:
            return redirect("/")
        print("Chat iniciado con claves en sesión.")
        messages = rooms[room]["messages"]
        return render_template("interfazChat.html", room=room, username=username, messages=messages)
    else:
        print("No hay sesión iniciada, redirigiendo al inicio.")
        return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    global current_room_code  # Hacer referencia a la variable global

    session.clear()
    username =  request.form.get("username")
    secret = request.form.get("secret")
    initChat = request.form.get("initChat", False)
    genKeys = request.form.get("genKeys", False)
    key_directory = request.form.get("key_directory")
    print(key_directory)
    private_key_path = os.path.join(key_directory, "private.pem")
    public_key_path = os.path.join(key_directory, "public.pem")
    print("Paths llave Public: ", public_key_path)
    print("Paths llave Private: ", private_key_path)
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        create_keys(secret, private_key_path, public_key_path)

    with open(private_key_path, "rb") as f:
        private_key_data = f.read()
    private_key = RSA.import_key(private_key_data, passphrase=secret)

    with open(public_key_path, "rb") as f:
        public_key_data = f.read()
    public_key = RSA.import_key(public_key_data)

    password = bytes(secret, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf(password, salt, 32)
    # Lógica para manejar rooms
    # Generar el código de room si no existe
    if current_room_code is None:
        current_room_code = generate_room_code(6, list(rooms.keys()))
        rooms[current_room_code] = {
            'members': 0,
            'messages': [],
            'creator': username
        }
    room_code = current_room_code
    rooms[room_code]['members'] += 1

    session['room'] = room_code
    session['username'] = username
    session['unique_session_id'] = generate_unique_session_id()
    session['private_key'] = private_key.export_key().decode()
    session['public_key'] = public_key.export_key().decode()
    session['symmetric_key'] = symmetric_key.hex()
    session['messages'] = []

    print("Usuario logueado, sesión iniciada con claves cargadas.")
    # Imprimir información en la terminal
    print("Clave privada RSA:")
    print(private_key.export_key().decode())
    print("\nClave pública RSA:")
    print(public_key.export_key().decode())
    print("\nSalt generado:", salt.hex())
    print("Clave simétrica derivada:", symmetric_key.hex())

    return redirect("/chat")


@app.route("/send_message", methods=["POST"])
def send_message():
    if 'symmetric_key' not in session:
        return jsonify({"error": "Debes iniciar sesión para enviar mensajes."}), 403

    username = request.form["username"]
    message = request.form["message"]
    recipient = request.form["recipient"]
    symmetric_key = bytes.fromhex(session['symmetric_key'])
    private_key = RSA.import_key(session['private_key'].encode())

    message_hash = hash_message(message)
    signature = sign_message(message_hash, private_key)
    ciphertext, tag, nonce = encrypt_symmetric(message, symmetric_key)
    public_key = RSA.import_key(session['public_key'].encode())
    encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)

    # Codificar datos binarios a Base64 para serialización en JSON
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    tag_b64 = base64.b64encode(tag).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode()

    message_info = {
        "username": username,
        "recipient": recipient,  # Nuevo: Guardar el nombre del destinatario
        "message": message,
        "ciphertext": ciphertext_b64,
        "tag": tag_b64,
        "nonce": nonce_b64,
        "encrypted_symmetric_key": encrypted_symmetric_key_b64,
        "message_hash": message_hash,
        "signature": base64.b64encode(signature).decode()
    }
    session['messages'].append(message_info)

    print("\nMensaje cifrado RSA:", encrypted_symmetric_key_b64)
    print("Mensaje descifrado:", message)
    print("Tag:", tag_b64)
    print("Nonce (IV):", nonce_b64)
    print("Mensaje integro")
    is_signature_valid = verify_signature(message_hash, signature, public_key)
    print(f"Mensaje de {username} cifrado y enviado a {recipient}.")  # Nuevo: Imprimir el destinatario
    return jsonify({"username": username, "message": message})

@app.route("/get_messages")
def get_messages():
    print("Recuperando mensajes de la sesión...")
    messages = session.get('messages', [])
    return jsonify({"messages": messages})

@app.route("/logout", methods=['POST'])
def logout():
    print("Cerrando sesión y limpiando datos...")
    session.clear()
    return redirect("/")


@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    room = session.get('room')

    if username is None or room is None:
        return
    if room not in rooms:
        leave_room(room)
    join_room(room)
    send({
        "sender": "",
        "message": f"{username} entro al chat"
    }, to=room)
    rooms[room]["members"] += 1

@socketio.on('message')
def handle_message(payload):
    room = session.get('room')
    username = session.get('username')

    if room not in rooms:
        return
    
    message = payload.get("message")  # Obtén el mensaje desde el payload

    symmetric_key = bytes.fromhex(session['symmetric_key'])
    private_key = RSA.import_key(session['private_key'].encode())

    message_hash = hash_message(message)
    signature = sign_message(message_hash, private_key)
    
    ciphertext, tag, nonce = encrypt_symmetric(message, symmetric_key)
    
    public_key = RSA.import_key(session['public_key'].encode())
    encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)

    # Codificar datos binarios a Base64 para serialización en JSON
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    tag_b64 = base64.b64encode(tag).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode()

    
    message = {
        "sender": username,
        "message": payload["message"],
        "ciphertext": ciphertext_b64,
        "tag": tag_b64,
        "nonce": nonce_b64,
        "encrypted_symmetric_key": encrypted_symmetric_key_b64,
        "message_hash": message_hash,
        "signature": base64.b64encode(signature).decode()
    }

    send(message, to=room)
    rooms[room]["messages"].append(message)

    print("\nMensaje cifrado RSA:", encrypted_symmetric_key_b64)
    print("Mensaje descifrado:", message)
    print("Tag:", tag_b64)
    print("Nonce (IV):", nonce_b64)
    print("Mensaje integro")
    is_signature_valid = verify_signature(message_hash, signature, public_key)
    print(f"Mensaje de {username} cifrado.")  # Nuevo: Imprimir el destinatario

@socketio.on('disconnect')
def handle_disconnect():
    room = session.get('room')
    username = session.get("username")
    leave_room
    
    if room in rooms:
        rooms[room]["members"] -= 1

        if rooms[room]["members"] <= 0:
            del rooms[room]
        send({
            "message": f"{username} ha dejado el chat",
            "sender": ""
        })


if __name__ == "__main__":
    app.run(debug=True, port=8080)


