import re
import os
import psycopg2
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()

# --- APP CONFIG ---
online_users = {}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "supersecretkey")
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- DATABASE URL из Render ---
DATABASE_URL = os.environ.get("DATABASE_URL")


# --- USER MODEL ---
class User(UserMixin):
    def __init__(self, id, username, avatar="snowman.png"):
        self.id = id
        self.username = username
        self.avatar = avatar

@login_manager.user_loader
def load_user(user_id):
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, avatar FROM users WHERE id=%s", (user_id,))
        user = c.fetchone()
        if user:
            return User(user[0], user[1], user[2])
    return None

# --- FORMS ---
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=10)])
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=32)])

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired()])

# --- DATABASE INIT ---
def init_db():
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(200) NOT NULL,
            avatar VARCHAR(50) NOT NULL DEFAULT 'snowman.png'
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender INTEGER REFERENCES users(id),
            receiver INTEGER REFERENCES users(id),
            text TEXT,
            timestamp TEXT
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            username VARCHAR(50),
            ip_address VARCHAR(100),
            user_agent TEXT,
            login_time TIMESTAMP
        )
        """)

        conn.commit()
init_db()


def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "admin":
            return redirect(url_for("chats"))
        return func(*args, **kwargs)
    return wrapper

# --- ROUTES ---
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("chats"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("chats"))
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data.strip()

        if not re.match(r'^[a-z0-9_]{4,10}$', username):
            flash("Username: 4-10 символов, латиница, цифры, _")
            return render_template("register.html", form=form)
        if not re.match(r'^[a-zA-Z0-9]{6,32}$', password):
            flash("Пароль: 6-32 символа, латиница и цифры")
            return render_template("register.html", form=form)

        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
        default_avatar = "snowman.png"
        try:
            with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO users (username, password, avatar) VALUES (%s, %s, %s)",
                    (username, hashed_pw, default_avatar)
                )
                conn.commit()
            flash("Регистрация успешна. Войдите.")
            return redirect(url_for("login"))
        except psycopg2.IntegrityError:
            flash("Username уже занят.")
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("chats"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data.strip()
        with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, password, avatar FROM users WHERE username=%s", (username,))
            user = c.fetchone()
            if user and check_password_hash(user[2], password):
                login_user(User(user[0], user[1], user[3]))
                ip = request.remote_addr
                user_agent = request.headers.get("User-Agent")

                c.execute("""
                INSERT INTO login_logs (user_id, username, ip_address, user_agent, login_time)
                VALUES (%s, %s, %s, %s, %s)
                """, (user[0], user[1], ip, user_agent, datetime.now()))
                conn.commit()

                return redirect(url_for("chats"))
        flash("Неверные данные.")
    return render_template("login.html", form=form)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/chats")
@login_required
def chats():
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.id, u.username, u.avatar
            FROM users u
            JOIN messages m
            ON (u.id = m.sender AND m.receiver = %s) OR (u.id = m.receiver AND m.sender = %s)
            WHERE u.id != %s
            GROUP BY u.id
        """, (current_user.id, current_user.id, current_user.id))
        users = c.fetchall()
    return render_template("chats.html", users=users)

@app.route("/chat/<int:user_id>")
@login_required
def chat(user_id):
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("SELECT username, avatar FROM users WHERE id=%s", (user_id,))
        partner = c.fetchone()
        if not partner:
            return redirect(url_for("chats"))
        partner_name, partner_avatar = partner
        c.execute("""
            SELECT sender, text, timestamp
            FROM messages
            WHERE (sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s)
            ORDER BY id
        """, (current_user.id, user_id, user_id, current_user.id))
        messages = c.fetchall()
    room = f"{min(current_user.id, user_id)}_{max(current_user.id, user_id)}"
    return render_template("chat.html", partner=partner_name, partner_avatar=partner_avatar, user_id=user_id, messages=messages, room=room)

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    users = []
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        if username:
            with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT id, username, avatar
                    FROM users
                    WHERE username LIKE %s AND id != %s
                """, ('%' + username + '%', current_user.id))
                users = c.fetchall()
    return render_template("search.html", users=users)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    avatars = ["rabbit.png", "dog.png", "cat.png", "snowman.png", "lion.png"]
    feedback = {}
    selected_avatar = None
    current_username = None

    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("SELECT avatar, username FROM users WHERE id=%s", (current_user.id,))
        row = c.fetchone()
        selected_avatar = row[0]
        current_username = row[1]

    if request.method == "POST":
        new_username = request.form.get("username", "").strip().lower()
        new_password = request.form.get("new_password", "").strip()
        avatar_choice = request.form.get("avatar")

        with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
            c = conn.cursor()
            # Аватар
            if avatar_choice in avatars:
                c.execute("UPDATE users SET avatar=%s WHERE id=%s", (avatar_choice, current_user.id))
                feedback["avatar"] = "Аватар обновлен"
                selected_avatar = avatar_choice

            # Username
            if new_username and new_username != current_username:
                if not re.match(r'^[a-z0-9_]{4,10}$', new_username):
                    feedback["username"] = "Username: 4-10 символов, латиница, цифры и _"
                else:
                    try:
                        c.execute("UPDATE users SET username=%s WHERE id=%s", (new_username, current_user.id))
                        feedback["username"] = "Username обновлен"
                        current_username = new_username
                    except psycopg2.IntegrityError:
                        feedback["username"] = "Username уже занят"

            # Password
            if new_password:
                if not re.match(r'^[a-zA-Z0-9]{6,32}$', new_password):
                    feedback["password"] = "Пароль: 6-32 символа, латиница и цифры"
                else:
                    hashed_pw = generate_password_hash(new_password, method="pbkdf2:sha256")
                    c.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_pw, current_user.id))
                    feedback["password"] = "Пароль обновлен"
            conn.commit()

    return render_template("account.html", avatars=avatars, selected_avatar=selected_avatar, current_username=current_username, feedback=feedback)

@app.route("/check_username", methods=["POST"])
@login_required
def check_username():
    username = request.form.get("username", "").strip().lower()
    if not re.match(r'^[a-z0-9_]{4,10}$', username):
        return jsonify({"status": "invalid"})
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=%s AND id!=%s", (username, current_user.id))
        if c.fetchone():
            return jsonify({"status": "taken"})
    return jsonify({"status": "ok"})

@app.route("/admin", methods=["GET", "POST"])
@login_required
@admin_required
def admin_panel():
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()

        if request.method == "POST":
            action = request.form.get("action")
            user_id = request.form.get("user_id")

            # Удаление
            if action == "delete":
                c.execute("DELETE FROM messages WHERE sender=%s OR receiver=%s", (user_id, user_id))
                c.execute("DELETE FROM users WHERE id=%s", (user_id,))
                conn.commit()

            # Изменение username
            if action == "update_username":
                new_username = request.form.get("new_username").strip().lower()
                if re.match(r'^[a-z0-9_]{4,10}$', new_username):
                    c.execute("UPDATE users SET username=%s WHERE id=%s", (new_username, user_id))
                    conn.commit()

            # Изменение пароля
            if action == "update_password":
                new_password = request.form.get("new_password")
                if re.match(r'^[a-zA-Z0-9]{6,32}$', new_password):
                    hashed_pw = generate_password_hash(new_password)
                    c.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_pw, user_id))
                    conn.commit()

        # Статистика
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]

        c.execute("SELECT id, username FROM users ORDER BY id")
        users = c.fetchall()

        c.execute("""
            SELECT username, ip_address, user_agent, login_time
            FROM login_logs
            ORDER BY login_time DESC
            LIMIT 50
        """)
        logs = c.fetchall()

    return render_template(
        "admin.html",
        total_users=total_users,
        users=users,
        logs=logs,
        online_users=online_users
    )
# --- SOCKET.IO ---

@socketio.on("connect")
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = {
            "username": current_user.username,
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent")
        }

@socketio.on("disconnect")
def handle_disconnect():
    if current_user.id in online_users:
        online_users.pop(current_user.id)


@socketio.on("join")
def on_join(data):
    room = data["room"]
    join_room(room)

@socketio.on("send_message")
def handle_message(data):
    sender = current_user.id
    receiver = data["receiver"]
    text = data["text"]
    timestamp = datetime.now().strftime("%H:%M")
    with psycopg2.connect(DATABASE_URL, sslmode="require") as conn:
        c = conn.cursor()
        c.execute("INSERT INTO messages (sender, receiver, text, timestamp) VALUES (%s,%s,%s,%s)",
                  (sender, receiver, text, timestamp))
        conn.commit()
    room = f"{min(sender, receiver)}_{max(sender, receiver)}"
    emit("receive_message", {"sender": sender, "text": text, "timestamp": timestamp}, room=room)


@app.errorhandler(404)
def page_not_found(e):
    if current_user.is_authenticated:
        return redirect(url_for("chats"))
    else:
        return redirect(url_for("login"))

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
