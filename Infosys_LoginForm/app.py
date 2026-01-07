from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)

# 🔐 JWT Configuration (COOKIE BASED)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable for simplicity

jwt = JWTManager(app)

# 📂 Database Connection
def get_db():
    return sqlite3.connect("database.db")

# 🗄️ Create User Table
with get_db() as con:
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

@app.route('/')
def home():
    return redirect(url_for('login'))

# 📝 REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        try:
            with get_db() as con:
                con.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password)
                )
            return redirect(url_for('login'))
        except:
            return "Username already exists!"

    return render_template('register.html')

# 🔐 LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        con = get_db()
        user = con.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user[2], password):
            access_token = create_access_token(identity=username)

            response = make_response(redirect(url_for('dashboard')))
            set_access_cookies(response, access_token)
            return response

        return "Invalid username or password!"

    return render_template('login.html')

# 🧑 DASHBOARD (PROTECTED)
@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return render_template('dashboard.html', user=current_user)

# 🚪 LOGOUT
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response

if __name__ == '__main__':
    app.run(debug=True)
