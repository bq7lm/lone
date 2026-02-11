import os
import sqlite3
from datetime import datetime
import re
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_socketio import SocketIO, emit, join_room
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

# --- APP CONFIG ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "supersecretkey")
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DATABASE = "lone.db"


# --- DATABASE ---

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()

        # Таблица пользователей
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT 'snowman.png'
        )
        """)

        # Создаем уникальный индекс username без учета регистра
        c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username COLLATE NOCASE)
        """)

        # Таблица сообщений
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender INTEGER,
            receiver INTEGER,
            text TEXT,
            timestamp TEXT
        )
        """)

        conn.commit()


init_db()


# --- USER MODEL ---

class User(UserMixin):
    def __init__(self, id, username, avatar="snowman.png"):
        self.id = id
        self.username = username
        self.avatar = avatar



@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, avatar FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if user:
            return User(user[0], user[1], user[2])
    return None


# --- FORMS ---

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField(validators=[InputRequired(), Length(min=6)])


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired()])


# --- ROUTES ---

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("chats"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()  # нижний регистр
        password = form.password.data.strip()          # пароль из формы

        # Проверка формата
        import re
        if not re.match(r'^[a-z0-9_]{4,10}$', username):
            flash("Username: 4-10 символов, латиница, цифры, _")
            return render_template("register.html", form=form)
        if not re.match(r'^[a-zA-Z0-9]{6,32}$', password):
            flash("Пароль: 6-32 символа, латиница и цифры")
            return render_template("register.html", form=form)

        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
        default_avatar = "snowman.png"
        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)",
                    (username, hashed_pw, default_avatar)
                )
                conn.commit()
            flash("Регистрация успешна. Войдите.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username уже занят.")
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, password FROM users WHERE username=?",
                      (form.username.data,))
            user = c.fetchone()
            if user and check_password_hash(user[2], form.password.data):
                login_user(User(user[0], user[1]))
                return redirect(url_for("chats"))
        flash("Неверные данные.")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/chats")
@login_required
def chats():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # Получаем пользователей, с которыми есть сообщения
        c.execute("""
            SELECT u.id, u.username, u.avatar
            FROM users u
            JOIN messages m
            ON (u.id = m.sender AND m.receiver = ?) OR (u.id = m.receiver AND m.sender = ?)
            WHERE u.id != ?
            GROUP BY u.id
        """, (current_user.id, current_user.id, current_user.id))
        users = c.fetchall()
    return render_template("chats.html", users=users)



@app.route("/chat/<int:user_id>")
@login_required
def chat(user_id):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # получаем username и avatar партнёра
        c.execute("SELECT username, avatar FROM users WHERE id=?", (user_id,))
        partner = c.fetchone()
        if not partner:
            return redirect(url_for("chats"))

        partner_name = partner[0]
        partner_avatar = partner[1]

        # получаем сообщения между пользователями
        c.execute("""
            SELECT sender, text, timestamp FROM messages
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
            ORDER BY id
        """, (current_user.id, user_id, user_id, current_user.id))
        messages = c.fetchall()

    room = f"{min(current_user.id, user_id)}_{max(current_user.id, user_id)}"

    return render_template(
        "chat.html",
        partner=partner_name,
        partner_avatar=partner_avatar,
        user_id=user_id,
        messages=messages,
        room=room
    )


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    users = []
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if username:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                # Получаем id, username и avatar
                c.execute("""
                    SELECT id, username, avatar
                    FROM users
                    WHERE username LIKE ? AND id != ?
                """, ('%' + username + '%', current_user.id))
                users = c.fetchall()
    return render_template("search.html", users=users)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    avatars = ["rabbit.png", "dog.png", "cat.png", "snowman.png", "lion.png"]
    selected_avatar = None

    if request.method == "POST":
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()

            # ---- Аватар ----
            avatar_choice = request.form.get("avatar")
            if avatar_choice in avatars:
                c.execute("UPDATE users SET avatar=? WHERE id=?", (avatar_choice, current_user.id))

            # ---- Username ----
            new_username = request.form.get("username", "").strip().lower()
            if new_username:
                if not re.match(r'^[a-z0-9_]{4,10}$', new_username):
                    flash("Username: 4-10 символов, латиница, цифры и _")
                else:
                    try:
                        c.execute("UPDATE users SET username=? WHERE id=?", (new_username, current_user.id))
                    except sqlite3.IntegrityError:
                        flash("Такой username уже занят.")

            # ---- Новый пароль ----
            new_password = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            if new_password or confirm_password:  # если хоть одно поле заполнено
                if new_password != confirm_password:
                    flash("Пароли не совпадают")
                elif not re.match(r'^[a-zA-Z0-9]{6,32}$', new_password):
                    flash("Пароль: 6-32 символа, латиница и цифры")
                else:
                    hashed_pw = generate_password_hash(new_password, method="pbkdf2:sha256")

                    c.execute("UPDATE users SET password=? WHERE id=?", (hashed_pw, current_user.id))

            conn.commit()

        flash("Настройки обновлены")

    # Получаем текущий avatar
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute("SELECT avatar FROM users WHERE id=?", (current_user.id,))
        selected_avatar = c.fetchone()[0]

    return render_template("account.html", avatars=avatars, selected_avatar=selected_avatar)

    # Получаем текущий avatar
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute("SELECT avatar FROM users WHERE id=?", (current_user.id,))
        selected_avatar = c.fetchone()[0]

    return render_template("account.html", avatars=avatars, selected_avatar=selected_avatar)

@app.route("/check_username", methods=["POST"])
@login_required
def check_username():
    username = request.form.get("username", "").strip().lower()
    if not re.match(r'^[a-z0-9_]{4,10}$', username):
        return {"status": "invalid"}
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=? AND id!=?", (username, current_user.id))
        if c.fetchone():
            return {"status": "taken"}
    return {"status": "ok"}


# --- SOCKET.IO ---

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

    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO messages (sender, receiver, text, timestamp) VALUES (?, ?, ?, ?)",
                  (sender, receiver, text, timestamp))
        conn.commit()

    room = f"{min(sender, receiver)}_{max(sender, receiver)}"
    emit("receive_message", {
        "sender": sender,
        "text": text,
        "timestamp": timestamp
    }, room=room)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
