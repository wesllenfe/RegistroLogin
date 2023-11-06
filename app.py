from flask import Flask, render_template, request
from flask_bcrypt import Bcrypt
import sqlite3
import time

app = Flask(__name__)
bcrypt = Bcrypt(app)

conn = sqlite3.connect('database/users.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

conn.commit()
conn.close()

login_attempts = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']

        if usuario in login_attempts and time.time() - login_attempts[usuario] < 60:
            return 'Espere um minuto antes de tentar novamente.'

        conn = sqlite3.connect('database/users.db')
        c = conn.cursor()

        c.execute('SELECT * FROM users WHERE username=?', (usuario,))
        user = c.fetchone()

        conn.close()

        if user and bcrypt.check_password_hash(user[2], senha):
            login_attempts.pop(usuario, None)  
            return f'Bem-vindo, {usuario}!'
        else:
            login_attempts[usuario] = time.time()  
            return 'Credenciais inválidas. Por favor, tente novamente mais tarde.'

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        novo_usuario = request.form['novo_usuario']
        nova_senha = request.form['nova_senha']

        hashed_senha = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

        conn = sqlite3.connect('database/users.db')
        c = conn.cursor()

        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (novo_usuario, hashed_senha))

        conn.commit()
        conn.close()

        return f'Usuário {novo_usuario} registrado com sucesso!'

    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)
