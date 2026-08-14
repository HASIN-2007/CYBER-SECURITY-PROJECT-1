from flask import Flask, render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)

DATABASE = "users.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            vulnerable_password TEXT,
            secure_password_hash TEXT
        )
    """)

    connection.commit()
    connection.close()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        mode = request.form.get("mode", "secure")

        if not username or not password:
            message = "Username and password are required."
            return render_template("register.html", message=message)

        connection = get_db_connection()

        try:

            if mode == "vulnerable":

                # INTENTIONALLY INSECURE:
                # Password is stored as plain text.
                connection.execute(
                    """
                    INSERT INTO users
                    (username, vulnerable_password, secure_password_hash)
                    VALUES (?, ?, NULL)
                    """,
                    (username, password)
                )

            else:

                # SECURE:
                # Password is stored as a one-way password hash.
                password_hash = generate_password_hash(password)

                connection.execute(
                    """
                    INSERT INTO users
                    (username, vulnerable_password, secure_password_hash)
                    VALUES (?, NULL, ?)
                    """,
                    (username, password_hash)
                )

            connection.commit()

            message = "Registration successful! You can now log in."

        except sqlite3.IntegrityError:

            message = "Username already exists."

        finally:

            connection.close()

    return render_template(
        "register.html",
        message=message
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        mode = request.form.get("mode", "secure")

        connection = get_db_connection()

        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        connection.close()

        if not user:

            message = "Invalid username or password."

        elif mode == "vulnerable":

            # INTENTIONALLY INSECURE:
            # Direct comparison with stored plain-text password.
            if user["vulnerable_password"] == password:
                message = "Vulnerable Login: Authentication successful!"
            else:
                message = "Vulnerable Login: Invalid credentials."

        else:

            # SECURE:
            # Verify the supplied password against the stored hash.
            if (
                user["secure_password_hash"]
                and check_password_hash(
                    user["secure_password_hash"],
                    password
                )
            ):
                message = "Secure Login: Authentication successful!"
            else:
                message = "Secure Login: Invalid credentials."

    return render_template(
        "login.html",
        message=message
    )


if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)