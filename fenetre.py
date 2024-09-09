import sys
import sqlite3
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QFormLayout, QMessageBox, QTextEdit

class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()

        # Configuration de la fenêtre d'inscription
        self.setWindowTitle('Page d\'Inscription')
        self.setGeometry(100, 100, 300, 200)

        # Création des widgets
        self.create_widgets()
        
        # Configuration du layout
        self.layout = QFormLayout()
        self.layout.addRow(self.username_label, self.username_input)
        self.layout.addRow(self.password_label, self.password_input)
        self.layout.addRow(self.confirm_password_label, self.confirm_password_input)
        self.layout.addWidget(self.register_button)
        
        self.setLayout(self.layout)

    def create_widgets(self):
        # Étiquette et champ de saisie pour le nom d'utilisateur
        self.username_label = QLabel('Nom d’utilisateur:')
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Entrez votre nom d’utilisateur')

        # Étiquette et champ de saisie pour le mot de passe
        self.password_label = QLabel('Mot de passe:')
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Entrez votre mot de passe')
        self.password_input.setEchoMode(QLineEdit.Password)

        # Étiquette et champ de saisie pour confirmer le mot de passe
        self.confirm_password_label = QLabel('Confirmez le mot de passe:')
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText('Confirmez votre mot de passe')
        self.confirm_password_input.setEchoMode(QLineEdit.Password)

        # Bouton d'inscription
        self.register_button = QPushButton('S\'inscrire')
        self.register_button.clicked.connect(self.handle_register)

    def hash_password_sha512(self, password):
        return hashlib.sha512(password.encode()).hexdigest()

    def hash_password_sha3_256(self, password):
        return hashlib.sha3_256(password.encode()).hexdigest()

    def handle_register(self):
        # Récupérer les valeurs des champs
        username = self.username_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if password == confirm_password:
            hashed_password_sha512 = self.hash_password_sha512(password)
            hashed_password_sha3_256 = self.hash_password_sha3_256(password)
            
            # Stocker les données dans la base de données
            self.store_in_database(username, hashed_password_sha512, hashed_password_sha3_256)
            
            QMessageBox.information(self, 'Succès', 'Inscription réussie!')
            self.close()
        else:
            QMessageBox.warning(self, 'Erreur', 'Les mots de passe ne correspondent pas')

    def store_in_database(self, username, password_sha512, password_sha3_256):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Créer la table si elle n'existe pas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_sha512 TEXT NOT NULL,
                password_sha3_256 TEXT NOT NULL
            )
        ''')

        # Insérer les données
        try:
            cursor.execute('''
                INSERT INTO users (username, password_sha512, password_sha3_256)
                VALUES (?, ?, ?)
            ''', (username, password_sha512, password_sha3_256))
            conn.commit()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, 'Erreur', 'Nom d’utilisateur déjà pris')

        conn.close()

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()

        # Configuration de la fenêtre de connexion
        self.setWindowTitle('Page de Connexion')
        self.setGeometry(100, 100, 300, 150)

        # Création des widgets
        self.create_widgets()
        
        # Configuration du layout
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.login_button)
        self.layout.addWidget(self.register_button)
        
        self.setLayout(self.layout)

    def create_widgets(self):
        # Étiquette et champ de saisie pour le nom d'utilisateur
        self.username_label = QLabel('Nom d’utilisateur:')
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Entrez votre nom d’utilisateur')

        # Étiquette et champ de saisie pour le mot de passe
        self.password_label = QLabel('Mot de passe:')
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Entrez votre mot de passe')
        self.password_input.setEchoMode(QLineEdit.Password)

        # Bouton de connexion
        self.login_button = QPushButton('Entrer')
        self.login_button.clicked.connect(self.handle_login)

        # Bouton d'inscription
        self.register_button = QPushButton('S\'inscrire')
        self.register_button.clicked.connect(self.open_register_window)

    def handle_login(self):
        # Récupérer les valeurs des champs
        username = self.username_input.text()
        password = self.password_input.text()

        # Hacher le mot de passe
        hashed_password_sha512 = hashlib.sha512(password.encode()).hexdigest()
        hashed_password_sha3_256 = hashlib.sha3_256(password.encode()).hexdigest()

        # Vérifier les informations de connexion
        if(self.verify_login(username, hashed_password_sha512, hashed_password_sha3_256)):
            self.open_chat_window()
        else:
            QMessageBox.warning(self, 'Erreur', 'Nom d’utilisateur ou mot de passe incorrect')

    def verify_login(self, username, password_sha512, password_sha3_256):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Rechercher l'utilisateur
        cursor.execute('''
            SELECT * FROM users
            WHERE username = ? AND password_sha512 = ? AND password_sha3_256 = ?
        ''', (username, password_sha512, password_sha3_256))

        user = cursor.fetchone()
        conn.close()

        if user:
            return True
        else:
            return False
    def open_register_window(self):
        self.register_window = RegisterWindow()
        self.register_window.show()

    def open_chat_window(self):
        self.chat_window = ChatWindow()
        self.chat_window.show()
        self.close()





class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Chat')
        self.setGeometry(100, 100, 600, 400)  # Ajustement de la taille de la fenêtre pour le tableau des contacts

        # Création des widgets
        self.create_widgets()

        # Configuration des layouts
        self.main_layout = QHBoxLayout()

        # Ajout du tableau des contacts et serveurs à gauche
        self.main_layout.addWidget(self.contacts_list)

        # Utilisation d'un QSplitter pour permettre le redimensionnement dynamique
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.contacts_list)
        self.splitter.addWidget(self.chat_widget)
        self.splitter.setStretchFactor(1, 2)  # Étire la fenêtre de chat plus que la liste

        self.main_layout.addWidget(self.splitter)
        self.setLayout(self.main_layout)

    def create_widgets(self):
        # Création de la zone de contacts/serveurs
        self.contacts_list = QListWidget()

        # Exemple de contacts et serveurs à ajouter
        contacts = ['Contact 1', 'Contact 2', 'Serveur A', 'Serveur B']
        for contact in contacts:
            QListWidgetItem(contact, self.contacts_list)

        # Widget contenant la zone de chat et les boutons
        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()

        # Zone d'affichage des messages
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)  # La zone d'affichage est en lecture seule

        # Zone de saisie du message
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText('Tapez votre message ici...')
        self.message_input.setMaximumHeight(100)

        # Bouton d'envoi
        self.send_button = QPushButton('Envoyer')
        self.send_button.clicked.connect(self.send_message)

        # Ajout des widgets de chat au layout
        self.chat_layout.addWidget(self.chat_display)
        self.chat_layout.addWidget(self.message_input)
        self.chat_layout.addWidget(self.send_button)

        self.chat_widget.setLayout(self.chat_layout)

    def send_message(self):
        message = self.message_input.toPlainText()
        if message:
            self.chat_display.append(f'Vous: {message}')  # Ajouter le message à la zone d'affichage
            self.message_input.clear()  # Effacer la zone de saisie

if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())
