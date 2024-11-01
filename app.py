"""
Universidad Nacional Autónoma de México
Facultad de Ingeniería

Proyecto 1:  Implementación de un protocolo de comunicación segura

  Criptografia
  Profesora: Aldeco Pérez Rocío Alejandra
  Grupo: 03

Integrantes:
    Arroyo Moreno Diego Alejandro
    Ceron Maciel Eduardo Alfredo   
    Miranda Bueno Fatima Yolanda
    Ortega Gaytan Alan Eduardo
"""

    #Importacion de librerias
from flask import Flask, render_template, request, jsonify, redirect, session
from flask_socketio import SocketIO, join_room, leave_room, send
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

#Configuracion de aplicacion Flask y Socket.IO: para comunicacion en tiempo real
app = Flask(__name__)
app.secret_key = 'CriptografiaProyecto'
socketio = SocketIO(app)

# Estructuras de datos para almacenar información de las salas de chat y sus códigos
rooms = {} #Salas
current_room_code = None

#Generar codigo unico para salas de chat
def generate_room_code(length: int, existing_codes: list[str]) -> str:
    """Genera un código único para cada sala de chat basado en caracteres aleatorios.

    Args:
        length (int): longitud del código a generar.
        existing_codes (list): lista de códigos ya existentes para evitar duplicados.

    Returns:
        str: código único generado.
    """
    while True:
        code_chars = [random.choice(string.ascii_letters) for _ in range (length)]
        code = ''.join(code_chars)

        if code not in existing_codes:
            return code

#Genera un identificador de sesión único usando UUID
def generate_unique_session_id():
    return str(uuid4())

#FIRMA DIGITAL de mensaje, 
def sign_message(message, private_key):
    """Genera una firma digital para un mensaje usando SHA256 y una clave privada.

    Args:
        message (str): el mensaje a firmar.
        private_key (RSA key): clave privada para firmar el mensaje.

    Returns:
        bytes: firma digital generada.
    """
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

#Verifica la firma digital de un mensaje utilizando la clave pública.
def verify_signature(message, signature, public_key):
    """
    Args:
        message (str): el mensaje original.
        signature (bytes): la firma digital.
        public_key (RSA key): clave pública para verificar la firma.

    Returns:
        bool: True si la firma es válida, False en caso contrario.
    """
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("---FIRMA VALIDA")
        return True
    except (ValueError, TypeError):
        print("---FIRMA !!NO!! VALIDA")
        return False

#Cifra un mensaje utilizando AES en modo GCM (cifrado simétrico).
def encrypt_symmetric(message, key):
    """
    Args:
        message (str): mensaje a cifrar.
        key (bytes): clave de cifrado simétrica.

    Returns:
        tuple: mensaje cifrado, tag de autenticación y nonce.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce

#Cifra datos utilizando RSA (cifrado asimétrico).
def encrypt_asymmetric(data, public_key):
    """
    Args:
        data (bytes): datos a cifrar.
        public_key (RSA key): clave pública para cifrar.

    Returns:
        bytes: datos cifrados.
    """
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

#Calcula el hash SHA256 de un mensaje.
def hash_message(message):
    """
    Args:
        message (str): mensaje a procesar.

    Returns:
        str: hash del mensaje en hexadecimal.
    """
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    return hash_object.hexdigest()


def pbkdf(password, salt, length):
    """Deriva una clave utilizando el método PBKDF2 con HMAC-SHA256.

    Args:
        password (bytes): contraseña original.
        salt (bytes): sal para el proceso de derivación.
        length (int): longitud deseada para la clave derivada.

    Returns:
        bytes: clave derivada.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def create_keys(secret, private_key_path, public_key_path):
    """Genera y almacena un par de claves RSA en archivos.

    Args:
        secret (str): frase de contraseña para proteger la clave privada.
        private_key_path (str): ruta para almacenar la clave privada.
        public_key_path (str): ruta para almacenar la clave pública.
    """
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=secret)
    public_key = key.publickey().export_key()
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    print(f"\n---CLAVES CREADAS Y GUARDAS: \n  **PRIVADA: {private_key_path} \n  **PUBLICA: {public_key_path}")


@app.route("/")
def index():
    #Renderiza  página inicial de login
    print("\n---VENTANA: INICIAR SESION---")
    return render_template("iniSesion.html")



@app.route("/chat")
#Gestiona la visualización de la interfaz de chat verificando la sesión y el código de sala.
def chat():
    if 'symmetric_key' in session:
        room = session.get("room")
        username = session.get("username")
        if username is None or room is None or room not in rooms:
            return redirect("/")
        print("\n\t CHAT INICIADO")
        messages = rooms[room]["messages"]
        return render_template("interfazChat.html", room=room, username=username, messages=messages)
    else:
        print("   NO HAY CHAT INICIADO\n   VOLVIENDO A LOGIN")
        return redirect("/")


@app.route("/login", methods=["POST"])
#Gestiona el proceso de autenticación y generación de claves para el usuario, creando claves si no existen.
def login():
    global current_room_code  # Hacer referencia a la variable global

    session.clear()
    username =  request.form.get("username")
    secret = request.form.get("secret")
    initChat = request.form.get("initChat", False)
    genKeys = request.form.get("genKeys", False)
    key_directory = request.form.get("key_directory")
    

    private_key_file = request.files['private_key']
    public_key_file = request.files['public_key']
    private_key_filename=request.form.get("private_key_filename") #Nombre de archivo ingresado por usuario
        #Verificar y ajustar el nombre del archivo .pem
    
    if private_key_file and public_key_file:
        private_key_data = private_key_file.read()
        private_key = RSA.import_key(private_key_data, passphrase=secret)
        public_key_data = public_key_file.read()
        public_key = RSA.import_key(public_key_data)
    else: 
        if private_key_filename:
            if not private_key_filename.endswith(".pem"):
                # Si el archivo no tiene extensión .pem o tiene una extensión incorrecta, se corrige
                private_key_filename = os.path.splitext(private_key_filename)[0] +".pem"
            private_key_path = os.path.join(key_directory, "private_" + private_key_filename)
            public_key_path = os.path.join(key_directory, "public_" + private_key_filename)
            
            create_keys(secret, private_key_path, public_key_path)
            
            with open(private_key_path, "rb") as f:
                private_key_data = f.read()
            private_key = RSA.import_key(private_key_data, passphrase=secret)

            with open(public_key_path, "rb") as f:
                    public_key_data = f.read()
            public_key = RSA.import_key(public_key_data)
            
        else: 
            print("***\nERROR: !!!Tienes que seleccionar un nombre para el archivo!!!: \n")
       
    # Generación de clave simétrica y configuración de sala de chat
    password = bytes(secret, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf(password, salt, 32)

            # Lógica para manejar rooms
        # Generar el código de room si no existe
    # Crea una sala de chat y asocia los datos de sesión
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

    print("")
    print("\n\t\t---LOGIN DE USUARIO--- ")
    # Imprimir información en la terminal
    print("Clave privada RSA:")
    print(private_key.export_key().decode())
    print("\nClave publica RSA:")
    print(public_key.export_key().decode())
    print("\nSalt generado:", salt.hex())
    print("Clave simétrica derivada:", symmetric_key.hex())
    print("\n")
    
    return redirect("/chat")

@socketio.on('connect')
#Gestiona la conexión de un usuario al chat mediante Socket.IO, asignándolo a una sala
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
    """Procesa un mensaje recibido en tiempo real, lo cifra y lo envía a la sala correspondiente.

    Args:
        payload (dict): diccionario que contiene los datos del mensaje.
    """
    room = session.get('room')
    username = session.get('username')

    if room not in rooms:
        return
    
    message = payload.get("message")  # Obtén el mensaje desde el payload

    symmetric_key = bytes.fromhex(session['symmetric_key'])
    private_key = RSA.import_key(session['private_key'].encode())

    # Cifra y firma el mensaje antes de enviarlo
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

    # Codificación para envío en JSON
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
        #TEST E INFO EN TERMINAL
    print("\n-/-/-/-/-/-/-/ mensaje enviado /-/-/-/-/-/-/-")
    print("***EMISOR:  ", message["sender"])
    print("**MENSAJE:  ", message["message"])
    print("")
    print("\n****MENSAJE CIFRADO -RSA:  ", encrypted_symmetric_key_b64)
    print("****TAG:  ", tag_b64)
    print("****NONCE (IV):  ", nonce_b64)
    print("****MENSAJE HASH:  ", message_hash)
    print("****FIRMA DIGITAL:  ", base64.b64encode(signature).decode())

    is_signature_valid = verify_signature(message_hash, signature, public_key)
    print("")


@socketio.on('disconnect')
#Gestiona la desconexión de un usuario, eliminándolo de la sala y limpiando los datos si es necesario
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


