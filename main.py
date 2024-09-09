# Création des clients Alice et Bob
from client import ClientAlice, ClientBob

alice = ClientAlice()
bob = ClientBob()

# Alice et Bob envoient leurs clés publiques au serveur
alice.send_public_key()
bob.send_public_key()

# Alice et Bob reçoivent les clés publiques de l'autre via le serveur
alice.receive_public_key()
bob.receive_public_key()

# Affichage des clés partagées
print(f"Clé partagée par Alice: {alice.shared_key}")
print(f"Clé partagée par Bob: {bob.shared_key}")

# Vérification que les clés partagées sont identiques
print(f"Les clés partagées sont identiques : {alice.shared_key == bob.shared_key}")
