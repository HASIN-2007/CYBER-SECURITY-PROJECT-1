# 🔐 Vulnerable Login Page — Cybersecurity Lab

## 📌 Project Overview

This project demonstrates the security risks associated with insecure password storage and compares a vulnerable authentication implementation with a secure authentication implementation.

The application is built as a controlled local cybersecurity laboratory using Python, Flask, SQLite, and Werkzeug password hashing.

The project demonstrates:

- User registration
- User authentication
- Plain-text password storage (intentionally vulnerable)
- Secure password hashing
- Password verification
- SQLite database inspection
- Security comparison between vulnerable and secure implementations

> ⚠️ This application is intentionally designed for educational purposes and runs locally.

---

## 🎯 Objectives

The main objectives of this project are:

1. Understand how a basic web authentication system works.
2. Demonstrate the security risks of storing passwords in plain text.
3. Implement secure password hashing.
4. Compare vulnerable and secure authentication methods.
5. Understand why password hashes should be stored instead of original passwords.
6. Demonstrate the difference using a local SQLite database.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Application programming language |
| Flask | Web application framework |
| SQLite | Local database |
| HTML | Web page structure |
| CSS | User interface styling |
| Werkzeug | Secure password hashing and verification |
| Git & GitHub | Version control and project hosting |

---

## 📂 Project Structure

```text
02-Vulnerable-Login-Page
│
├── README.md
├── app.py
├── .gitignore
│
├── templates
│   ├── login.html
│   └── register.html
│
├── static
│   └── style.css
│
└── screenshots
    ├── registration.png
    ├── secure-login.png
    ├── vulnerable-login.png
    └── database-comparison.png