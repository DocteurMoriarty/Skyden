from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# 1. Génération des clés RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 2. Génération d'une clé AES aléatoire et chiffrer un message avec AES
def encrypt_aes(message):
    aes_key = get_random_bytes(32)  # 256 bits pour AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)  # Mode GCM pour authentification
    nonce = cipher_aes.nonce
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    return aes_key, nonce, ciphertext, tag

# 3. Chiffrement de la clé AES avec la clé publique RSA
def encrypt_aes_key_with_rsa(aes_key, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_aes_key)

# 4. Déchiffrement de la clé AES avec la clé privée RSA
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
    return aes_key

# 5. Déchiffrement du message avec AES
def decrypt_aes(nonce, ciphertext, tag, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode('utf-8')

# Exemple d'utilisation
message = "Bonjour, ce message est sécurisé avec AES et RSA !"

# Génération des clés RSA
private_key, public_key = generate_rsa_keys()

# Chiffrement du message avec AES
aes_key, nonce, ciphertext, tag = encrypt_aes(message)

# Chiffrement de la clé AES avec RSA
encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

# --- Simulons la réception du message et de la clé chiffrée ---

# Déchiffrement de la clé AES avec RSA
decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

# Déchiffrement du message avec AES
decrypted_message = decrypt_aes(nonce, ciphertext, tag, decrypted_aes_key)

# Affichage
print("Message chiffré:", ciphertext)
print("Clé AES chiffrée:", encrypted_aes_key)
print("Message déchiffré:", decrypted_message)
