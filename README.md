# Secure File Transfer System (Flask + RSA + AES)

## Description

Ce projet est une application web développée avec Flask permettant l’envoi sécurisé de fichiers.

Les fichiers sont chiffrés avant transmission puis déchiffrés à la réception afin de garantir la confidentialité et l’intégrité des données.

---

## Technologies utilisées

- Python 3
- Flask
- PyCryptodome
- AES (chiffrement symétrique)
- RSA (chiffrement asymétrique)
- SHA-256 (intégrité)

---

## Architecture

- **Flask server** : gestion des requêtes HTTP
- **AES engine** : chiffrement des fichiers
- **RSA engine** : chiffrement de la clé AES
- **SHA-256** : vérification d’intégrité
- **Stockage local** : fichiers chiffrés et déchiffrés

---

## Génération des clés RSA

Les clés RSA sont générées une seule fois avec le script suivant :

```python
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.publickey().export_key()

with open("keys/private.pem", "wb") as f:
    f.write(private_key)

with open("keys/public.pem", "wb") as f:
    f.write(public_key)

print("Clés générées")