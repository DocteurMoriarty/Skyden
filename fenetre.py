import sys
import sqlite3
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QDialog, QVBoxLayout, QListWidgetItem, QLineEdit, QPushButton, QLabel, QFormLayout, QMessageBox, QTextEdit, QListWidget, QSplitter, QHBoxLayout
from PyQt5.QtCore import Qt



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
        self.setGeometry(100, 100, 800, 600)

        # Création des widgets
        self.create_widgets()

        # Configuration des layouts
        self.main_layout = QHBoxLayout()

        # Création du QSplitter pour redimensionnement dynamique
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.contacts_list)
        self.splitter.addWidget(self.chat_widget)
        self.splitter.setSizes([200, 600])

        self.main_layout.addWidget(self.splitter)
        self.setLayout(self.main_layout)

        # Application du style
        self.apply_styles()

    def create_widgets(self):
        # Création de la zone de contacts/serveurs
        self.contacts_list = QListWidget()

        self.add_server_button = QPushButton('Ajouter Serveur')
        self.add_server_button.clicked.connect(self.open_server_dialog)


        # Ajout du bouton d'ajout de serveur
        self.contacts_layout = QVBoxLayout()
        self.contacts_layout.addWidget(self.add_server_button)
        self.contacts_layout.addWidget(self.contacts_list)

        # Création du widget pour la liste des contacts et serveurs
        self.contacts_widget = QWidget()
        self.contacts_widget.setLayout(self.contacts_layout)

        # Widget contenant la zone de chat et les boutons
        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()

        # Zone d'affichage des messages
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)

        # Zone de saisie du message et bouton d'envoi alignés
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText('Tapez votre message ici...')
        self.message_input.setMaximumHeight(100)

        self.send_button = QPushButton('Envoyer')
        self.send_button.clicked.connect(self.send_message)

        # Création d'un layout horizontal pour l'input et le bouton
        self.input_layout = QHBoxLayout()
        self.input_layout.addWidget(self.message_input)
        self.input_layout.addWidget(self.send_button)

        # Ajout des widgets de chat au layout
        self.chat_layout.addWidget(self.chat_display)
        self.chat_layout.addLayout(self.input_layout)

        self.chat_widget.setLayout(self.chat_layout)

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2e2e2e;
                color: #e0e0e0;
            }
            QTextEdit {
                background-color: #3c3c3c;
                border: 1px solid #444;
                color: #e0e0e0;
            }
            QPushButton {
                background-color: #4a90d9;
                border: none;
                color: #fff;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #357ab8;
            }
            QListWidget {
                background-color: #333;
                border: 1px solid #444;
            }
            QListWidgetItem {
                color: #e0e0e0;
            }
        """)

    def send_message(self):
        message = self.message_input.toPlainText()
        if message:
            self.chat_display.append(f'Vous: {message}')
            self.chat_display.verticalScrollBar().setValue(self.chat_display.verticalScrollBar().maximum())
            self.message_input.clear()

    def open_server_dialog(self):
        dialog = ServerDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            name, ip, port = dialog.get_server_details()
            if not name or not ip or not port:
                QMessageBox.warning(self, 'Erreur', 'Tous les champs doivent être remplis.')
                return
            # Vous pouvez ajouter la validation de l'IP et du port ici si nécessaire
            server_info = f'{name} ({ip}:{port})'
            QListWidgetItem(server_info, self.contacts_list)




class ServerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle('Ajouter un Serveur')

        # Création des widgets
        self.name_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.port_input = QLineEdit()

        self.add_button = QPushButton('Ajouter')
        self.cancel_button = QPushButton('Annuler')

        self.add_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        # Configuration du layout
        form_layout = QFormLayout()
        form_layout.addRow('Nom:', self.name_input)
        form_layout.addRow('IP:', self.ip_input)
        form_layout.addRow('Port:', self.port_input)

        button_layout = QVBoxLayout()
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.cancel_button)

        main_layout = QVBoxLayout()
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)

        self.setLayout(main_layout)

    def get_server_details(self):
        return self.name_input.text(), self.ip_input.text(), self.port_input.text()

























if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())
