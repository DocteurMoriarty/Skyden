# Simulons un serveur qui relaye les clés publiques
class Server:
    def __init__(self):
        self.alice_public_key = None
        self.bob_public_key = None

    def receive_key(self, client_name, public_key):
        if client_name == "Alice":
            self.alice_public_key = public_key
        elif client_name == "Bob":
            self.bob_public_key = public_key

    def send_key(self, client_name):
        if client_name == "Alice" and self.bob_public_key:
            return self.bob_public_key
        elif client_name == "Bob" and self.alice_public_key:
            return self.alice_public_key
        else:
            return None

server = Server()
