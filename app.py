from flask import Flask, request, send_file, render_template
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

app = Flask(__name__)

# ======================
# FOLDERS
# ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENC_FOLDER = os.path.join(BASE_DIR, "encrypted")
DEC_FOLDER = os.path.join(BASE_DIR, "decrypted")
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENC_FOLDER, exist_ok=True)
os.makedirs(DEC_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

# ======================
# CHECK KEYS
# ======================
PUBLIC_KEY_PATH = os.path.join(KEYS_FOLDER, "public.pem")
PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, "private.pem")

if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
    print("Clés RSA manquantes. Génère-les avant de lancer l'app.")
    exit()

with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = RSA.import_key(f.read())

with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = RSA.import_key(f.read())

# ======================
# AES FUNCTIONS (SECURE CBC)
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
# UPLOAD ROUTE
# ======================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["file"]
        data = file.read()

        # Hash SHA-256
        file_hash = hashlib.sha256(data).hexdigest()

        # AES key
        aes_key = get_random_bytes(16)

        # Encrypt file
        encrypted_data = aes_encrypt(data, aes_key)

        enc_file_path = os.path.join(ENC_FOLDER, file.filename + ".enc")

        with open(enc_file_path, "wb") as f:
            f.write(encrypted_data)

        # Encrypt AES key with RSA
        rsa_cipher = PKCS1_OAEP.new(public_key)
        enc_key = rsa_cipher.encrypt(aes_key)

        with open(enc_file_path + ".key", "wb") as f:
            f.write(enc_key)

        # Save hash
        with open(enc_file_path + ".hash", "w") as f:
            f.write(file_hash)

        return "Fichier chiffré et stocké avec succès"

    return render_template("upload.html")

# ======================
# DOWNLOAD ROUTE
# ======================
@app.route("/download/<filename>")
def download(filename):

    filename = os.path.basename(filename)

    enc_file_path = os.path.join(ENC_FOLDER, filename + ".enc")

    if not os.path.exists(enc_file_path):
        return "Fichier introuvable", 404

    # Load encrypted file
    with open(enc_file_path, "rb") as f:
        enc_data = f.read()

    # Load encrypted key
    with open(enc_file_path + ".key", "rb") as f:
        enc_key = f.read()

    # Decrypt AES key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(enc_key)

    # Decrypt file
    data = aes_decrypt(enc_data, aes_key)

    # Verify integrity
    with open(enc_file_path + ".hash", "r") as f:
        original_hash = f.read()

    new_hash = hashlib.sha256(data).hexdigest()

    if new_hash != original_hash:
        return "Fichier corrompu", 400

    # Save decrypted file
    dec_path = os.path.join(DEC_FOLDER, filename)

    with open(dec_path, "wb") as f:
        f.write(data)

    return send_file(dec_path, as_attachment=True)

# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    app.run(debug=True)