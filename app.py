from flask import Flask, request, send_file, render_template
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ENC_FOLDER = "encrypted"
DEC_FOLDER = "decrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENC_FOLDER, exist_ok=True)
os.makedirs(DEC_FOLDER, exist_ok=True)

# ======================
# LOAD KEYS
# ======================
with open("keys/public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

with open("keys/private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())


# ======================
# UTIL FUNCTIONS
# ======================

def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def aes_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data).rstrip(b"\0")


# ======================
# UPLOAD ROUTE
# ======================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["file"]
        data = file.read()

        # SHA-256 hash
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

        return "Fichier chiffré et envoyé avec succès"

    return render_template("upload.html")


# ======================
# DOWNLOAD ROUTE
# ======================
@app.route("/download/<filename>")
def download(filename):
    enc_file_path = os.path.join(ENC_FOLDER, filename + ".enc")

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