from flask import Flask, request, jsonify, render_template, session, make_response
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
from datetime import datetime, timedelta
from flask_hcaptcha import hCaptcha
import requests
import os
import traceback
from dotenv import load_dotenv
import psycopg2  # For PostgreSQL
from psycopg2.extras import RealDictCursor
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
load_dotenv()

# CORS configuration
CORS(app, resources={
    r"/remixback": {
        "origins": [
            "https://remixback-git-main-sarahs-projects-d812bb6b.vercel.app",
            "https://remixback.vercel.app",
            "https://www.nextlogicai.com",
            "https://nextlogicai.com"
        ]
    },
    r"/login": {"origins": "*"},
    r"/register": {"origins": "*"},
    r"/check_session": {"origins": "*"},
    r"/update_subscription": {"origins": "*"},
    r"/logout": {"origins": "*"},
    r"/contact": {"origins": "*"}
})

# Flask configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'  # Server-side sessions
app.config['HCAPTCHA_ENABLED'] = True
app.config['HCAPTCHA_SITE_KEY'] = os.getenv('HCAPTCHA_SITE_KEY')
app.config['HCAPTCHA_SECRET'] = os.getenv('HCAPTCHA_SECRET')
Session(app)
hcaptcha = hCaptcha(app)

# API key for Gemini
API_KEY = os.getenv('GENERATIVE_API_KEY')
if not API_KEY:
    raise ValueError("GENERATIVE_API_KEY not set")

# PostgreSQL connection
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL not set")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# Initialize PostgreSQL database
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lock_until TIMESTAMP,
        is_paid BOOLEAN DEFAULT FALSE,
        uses_left INTEGER DEFAULT 3
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS logs (
        username TEXT,
        ip TEXT,
        success BOOLEAN,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    cur.close()
    conn.close()

init_db()

# IP-based rate limiter
limiter = Limiter(app, key_func=get_remote_address)
login_limiter = limiter.limit("5 per minute")  # 5 login attempts per minute per IP

# Login route
@app.route('/login', methods=['GET', 'POST'])
@login_limiter
def login():
    if request.method == 'GET':
        return render_template('login.html')  # Optional separate login page

    username = request.form.get('username')
    password = request.form.get('password')
    hcaptcha_response = request.form.get('h-captcha-response')
    ip = get_remote_address()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cur.fetchone()

    if not user:
        cur.execute('INSERT INTO logs (username, ip, success) VALUES (%s, %s, %s)', (username, ip, False))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401

    password_hash = user['password_hash']
    failed_attempts = user['failed_attempts']
    lock_until = user['lock_until']
    is_paid = user['is_paid']
    uses_left = user['uses_left']

    if lock_until and lock_until > datetime.now():
        cur.execute('INSERT INTO logs (username, ip, success) VALUES (%s, %s, %s)', (username, ip, False))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'error': 'Account locked. Try again later.'}), 429

    # Check CAPTCHA after 3 failed attempts
    cookie_attempts = int(request.cookies.get('failed_attempts', '0'))
    if failed_attempts >= 3 or cookie_attempts >= 3:
        if not hcaptcha_response or not hcaptcha.verify(hcaptcha_response):
            cur.execute('INSERT INTO logs (username, ip, success) VALUES (%s, %s, %s)', (username, ip, False))
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({'error': 'CAPTCHA required or invalid.'}), 400

    # Validate password
    if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
        session['user'] = username
        cur.execute('UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE username = %s', (username,))
        cur.execute('INSERT INTO logs (username, ip, success) VALUES (%s, %s, %s)', (username, ip, True))
        conn.commit()
        cur.close()
        conn.close()
        resp = make_response(jsonify({
            'message': 'Login successful!',
            'redirect': '/',
            'is_paid': is_paid,
            'uses_left': uses_left
        }), 200)
        resp.set_cookie('failed_attempts', '0', max_age=3600)
        return resp
    else:
        new_attempts = failed_attempts + 1
        lock_until = datetime.now() + timedelta(minutes=5) if new_attempts >= 3 else None
        cur.execute('UPDATE users SET failed_attempts = %s, lock_until = %s WHERE username = %s',
                    (new_attempts, lock_until, username))
        cur.execute('INSERT INTO logs (username, ip, success) VALUES (%s, %s, %s)', (username, ip, False))
        conn.commit()
        cur.close()
        conn.close()
        resp = make_response(jsonify({'error': 'Invalid username or password'}), 401)
        resp.set_cookie('failed_attempts', str(cookie_attempts + 1), max_age=3600)
        return resp

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form.get('username')
    password = request.form.get('password')
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username