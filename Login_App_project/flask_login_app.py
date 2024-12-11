#!/usr/bin/env python3

from flask import Flask, request, render_template, redirect, url_for, flash
import sqlite3
import bcrypt
from datetime import datetime

# Initialisatie van Flask-applicatie
microweb_app = Flask(__name__)
microweb_app.secret_key = 'geheim_key'  # Vereist voor flash-meldingen

# Databasebestand
db_name = 'user.db'

# Functie om database en tabellen aan te maken
def init_db():
    db_conn = sqlite3.connect(db_name)
    c = db_conn.cursor()
    # Maak tabellen voor plaintext (test) en hashed wachtwoorden
    c.execute('''CREATE TABLE IF NOT EXISTS USER_PLAIN (
                    USERNAME TEXT PRIMARY KEY NOT NULL,
                    PASSWORD TEXT NOT NULL
                );''')
    c.execute('''CREATE TABLE IF NOT EXISTS USER_HASH (
                    USERNAME TEXT PRIMARY KEY NOT NULL,
                    HASH TEXT NOT NULL
                );''')
    db_conn.commit()
    db_conn.close()

# Route om alle testdata te verwijderen
@microweb_app.route('/delete/all', methods=['POST', 'DELETE'])
def delete_all():
    db_conn = sqlite3.connect(db_name)
    c = db_conn.cursor()
    c.execute("DELETE FROM USER_PLAIN;")
    c.execute("DELETE FROM USER_HASH;")
    db_conn.commit()
    db_conn.close()
    return "Test records deleted\n"

# Plaintext Signup (onveilig, alleen voor test)
@microweb_app.route('/signup/v1', methods=['POST'])
def signup_v1():
    db_conn = sqlite3.connect(db_name)
    c = db_conn.cursor()
    try:
        c.execute("INSERT INTO USER_PLAIN (USERNAME, PASSWORD) VALUES (?, ?)",
                  (request.form['username'], request.form['password']))
        db_conn.commit()
    except sqlite3.IntegrityError:
        return "Username already exists (plaintext)\n"
    finally:
        db_conn.close()
    return "Signup success (plaintext, insecure)\n"

# Plaintext Login
def verify_plain(username, password):
    db_conn = sqlite3.connect(db_name)
    c = db_conn.cursor()
    c.execute("SELECT PASSWORD FROM USER_PLAIN WHERE USERNAME = ?", (username,))
    record = c.fetchone()
    db_conn.close()
    return record and record[0] == password

@microweb_app.route('/login/v1', methods=['POST'])
def login_v1():
    if verify_plain(request.form['username'], request.form['password']):
        return "Login success (plaintext, insecure)\n"
    return "Invalid username/password\n"

# Hashed Signup (bcrypt)
@microweb_app.route('/signup/v2', methods=['POST'])
def signup_v2():
    db_conn = sqlite3.connect(db_name)
    c = db_conn.cursor()
    try:
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        c.execute("INSERT INTO USER_HASH (USERNAME, HASH) VALUES (?, ?)",
                  (request.form['username'], hashed))
        db_conn.commit()
    except sqlite3.IntegrityError:
        return "Username already exists (hashed)\n"
    finally:
        db_conn.close()
    return "Signup success (hashed, secure)\n"

# Hashed Login
def verify_hash(username, password):
    db_conn = sqlite3.connect(db_name)
    c = db_conn.cursor()
    c.execute("SELECT HASH FROM USER_HASH WHERE USERNAME = ?", (username,))
    record = c.fetchone()
    db_conn.close()
    return record and bcrypt.checkpw(password.encode('utf-8'), record[0])

@microweb_app.route('/login/v2', methods=['POST'])
def login_v2():
    if verify_hash(request.form['username'], request.form['password']):
        return "Login success (hashed, secure)\n"
    return "Invalid username/password\n"

# Routes voor pagina's
@microweb_app.route('/')
def home():
    datetime_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template("index.html", datetime_now=datetime_now)

@microweb_app.route('/account')
def account():
    return render_template("account.html")

@microweb_app.route('/login')
def login():
    return render_template("login.html")

@microweb_app.route('/map')
def map_page():
    return render_template("map.html")

@microweb_app.route('/time')
def time_page():
    datetime_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template("time.html", datetime_now=datetime_now)

# Initialiseer database bij het starten van de app
if __name__ == "__main__":
    init_db()
    microweb_app.run(host="0.0.0.0", port=5555, debug=True)
