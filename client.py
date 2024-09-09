from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from server import server


# Fonction pour dériver la clé à partir d'une clé partagée
def derive_key(shared_key):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes pour AES-256
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

# Client Alice
class ClientAlice:
    def __init__(self):
        # Génération de la paire de clés ECDH pour Alice
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.shared_key = None

    def send_public_key(self):
        # Envoie la clé publique d'Alice au serveur
        server.receive_key("Alice", self.public_key)

    def receive_public_key(self):
        # Reçoit la clé publique de Bob depuis le serveur
        bob_public_key = server.send_key("Alice")
        if bob_public_key:
            # Génération de la clé partagée
            shared_key = self.private_key.exchange(ec.ECDH(), bob_public_key)
            self.shared_key = derive_key(shared_key)

# Client Bob
class ClientBob:
    def __init__(self):
        # Génération de la paire de clés ECDH pour Bob
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.shared_key = None

    def send_public_key(self):
        # Envoie la clé publique de Bob au serveur
        server.receive_key("Bob", self.public_key)

    def receive_public_key(self):
        # Reçoit la clé publique d'Alice depuis le serveur
        alice_public_key = server.send_key("Bob")
        if alice_public_key:
            # Génération de la clé partagée
            shared_key = self.private_key.exchange(ec.ECDH(), alice_public_key)
            self.shared_key = derive_key(shared_key)
