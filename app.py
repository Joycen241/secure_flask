# ======================
# app.py — VERSION COMPLÈTE AVEC TLS + AUTH
# ======================

from flask import Flask, request, send_file, render_template, redirect, url_for, session
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import ssl
from functools import wraps

app = Flask(__name__)

# 🔑 Clé secrète pour signer les sessions Flask (change-la !)
app.secret_key = os.urandom(32)

# ======================
# UTILISATEURS AUTORISÉS
# (En prod → utilise une vraie base de données + bcrypt)
# ======================
USERS = {
    "admin": hashlib.sha256("motdepasse123".encode()).hexdigest(),
    "user1": hashlib.sha256("secret456".encode()).hexdigest(),
}

# ======================
# DOSSIERS
# ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENC_FOLDER    = os.path.join(BASE_DIR, "encrypted")
DEC_FOLDER    = os.path.join(BASE_DIR, "decrypted")
KEYS_FOLDER   = os.path.join(BASE_DIR, "keys")
CERTS_FOLDER  = os.path.join(BASE_DIR, "certs")   # 🆕 Dossier certificats TLS

for folder in [UPLOAD_FOLDER, ENC_FOLDER, DEC_FOLDER, KEYS_FOLDER, CERTS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# ======================
# CERTIFICATS TLS
# ======================
CERT_PATH = os.path.join(CERTS_FOLDER, "cert.pem")
KEY_PATH  = os.path.join(CERTS_FOLDER, "key.pem")

if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):
    print("Certificats TLS manquants. Génère-les avec :")
    print("openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes")
    exit()

# ======================
# CLÉS RSA
# ======================
PUBLIC_KEY_PATH  = os.path.join(KEYS_FOLDER, "public.pem")
PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, "private.pem")

if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
    print("Clés RSA manquantes.")
    exit()

with open(PUBLIC_KEY_PATH,  "rb") as f: public_key  = RSA.import_key(f.read())
with open(PRIVATE_KEY_PATH, "rb") as f: private_key = RSA.import_key(f.read())

# ======================
# DÉCORATEUR : PROTECTION DES ROUTES
# ======================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:          # Pas de session active ?
            return redirect(url_for("login"))  # → Redirige vers /login
        return f(*args, **kwargs)              # Sinon → accès autorisé
    return decorated

# ======================
# AES FUNCTIONS
# ======================
def aes_encrypt(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, 16))

def aes_decrypt(data, key):
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]), 16)

# ======================
# ROUTE : LOGIN
# ======================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # Hash le mot de passe entré et compare
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if username in USERS and USERS[username] == password_hash:
            session["username"] = username   # Crée la session
            return redirect(url_for("upload"))
        else:
            error = "Identifiants incorrects"
    
    return render_template("login.html", error=error)

# ======================
# ROUTE : LOGOUT
# ======================
@app.route("/logout")
def logout():
    session.clear()                      # Supprime la session
    return redirect(url_for("login"))

# ======================
# ROUTE : UPLOAD (protégée)
# ======================
@app.route("/upload", methods=["GET", "POST"])
@login_required   # 🔒 Auth obligatoire
def upload():
    if request.method == "POST":
        file = request.files["file"]
        data = file.read()

        file_hash = hashlib.sha256(data).hexdigest()
        aes_key   = get_random_bytes(16)

        encrypted_data = aes_encrypt(data, aes_key)
        enc_file_path  = os.path.join(ENC_FOLDER, os.path.basename(file.filename) + ".enc")

        with open(enc_file_path, "wb") as f:
            f.write(encrypted_data)

        rsa_cipher = PKCS1_OAEP.new(public_key)
        enc_key    = rsa_cipher.encrypt(aes_key)

        with open(enc_file_path + ".key",  "wb") as f: f.write(enc_key)
        with open(enc_file_path + ".hash", "w")  as f: f.write(file_hash)

        return f"Fichier chiffré par {session['username']} ✓"

    return render_template("upload.html", username=session.get("username"))

# ======================
# ROUTE : DOWNLOAD (protégée)
# ======================
@app.route("/download/<filename>")
@login_required  
def download(filename):
    filename     = os.path.basename(filename)
    enc_file_path = os.path.join(ENC_FOLDER, filename + ".enc")

    if not os.path.exists(enc_file_path):
        return "Fichier introuvable", 404

    with open(enc_file_path,          "rb") as f: enc_data = f.read()
    with open(enc_file_path + ".key", "rb") as f: enc_key  = f.read()

    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key    = rsa_cipher.decrypt(enc_key)
    data       = aes_decrypt(enc_data, aes_key)

    with open(enc_file_path + ".hash", "r") as f:
        original_hash = f.read()

    if hashlib.sha256(data).hexdigest() != original_hash:
        return "Fichier corrompu", 400

    dec_path = os.path.join(DEC_FOLDER, filename)
    with open(dec_path, "wb") as f:
        f.write(data)

    return send_file(dec_path, as_attachment=True)

# ======================
# LANCEMENT AVEC TLS
# ======================
if __name__ == "__main__":
    # Crée le contexte SSL avec le certificat et la clé
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_PATH, KEY_PATH)

    print(" Serveur HTTPS démarré sur https://localhost:5000")
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=context,   
        debug=False           
    )
