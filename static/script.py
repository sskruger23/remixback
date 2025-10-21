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

# Configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['HCAPTCHA_ENABLED'] = True
app.config['HCAPTCHA_SITE_KEY'] = os.getenv('HCAPTCHA_SITE_KEY')
app.config['HCAPTCHA_SECRET'] = os.getenv('HCAPTCHA_SECRET')
Session(app)
hcaptcha = hCaptcha(app)

# API and Database Credentials
API_KEY = os.getenv('GENERATIVE_API_KEY')
if not API_KEY:
    raise ValueError("GENERATIVE_API_KEY not set")

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL not set")

# Database Connection
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# Database Initialization with Reset Option
def init_db(reset=False):
    conn = get_db_connection()
    cur = conn.cursor()
    
    if reset:
        # Drop tables if reset is requested (clears all data)
        cur.execute('DROP TABLE IF EXISTS contacts CASCADE')
        cur.execute('DROP TABLE IF EXISTS logs CASCADE')
        cur.execute('DROP TABLE IF EXISTS users CASCADE')
    
    # Create tables
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
    print("Database initialized" + (" with reset" if reset else ""))

# Initialize Database on Startup (set RESET_DB=True in .env to reset)
RESET_DB = os.getenv('RESET_DB', 'False').lower() == 'true'
init_db(reset=RESET_DB)

# IP-based Rate Limiter
limiter = Limiter(app, key_func=get_remote_address)
login_limiter = limiter.limit("5 per minute")

# Routes
@app.route('/login', methods=['GET', 'POST'])
@login_limiter
def login():
    if request.method == 'GET':
        return render_template('login.html')

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

    if failed_attempts >= 3 or int(request.cookies.get('failed_attempts', '0')) >= 3:
        if not hcaptcha_response or not hcaptcha.verify(hcaptcha_response):
            cur.execute('INSERT INTO logs (username, ip, success) VALUES (%s, %s, %s)', (username, ip, False))
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({'error': 'CAPTCHA required or invalid.'}), 400

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
        resp.set_cookie('failed_attempts', str(int(request.cookies.get('failed_attempts', '0')) + 1), max_age=3600)
        return resp

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
        cur.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, password_hash))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'User registered!', 'redirect': '/login'}), 201
    except psycopg2.errors.UniqueViolation:
        cur.close()
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/contact', methods=['POST'])
def contact():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    if not all([name, email, message]):
        return jsonify({'error': 'All fields are required'}), 400

    sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
    email_message = Mail(
        from_email='no-reply@nextlogicai.com',
        to_emails='your-email@domain.com',
        subject=f'Contact Form Submission from {name}',
        plain_text_content=f'Name: {name}\nEmail: {email}\nMessage: {message}'
    )
    try:
        sg.send(email_message)
        return jsonify({'message': 'Message sent successfully!'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to send email'}), 500

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'user' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT is_paid, uses_left FROM users WHERE username = %s', (session['user'],))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user:
            return jsonify({'logged_in': True, 'is_paid': user['is_paid'], 'uses_left': user['uses_left']})
    return jsonify({'logged_in': False})

@app.route('/update_subscription', methods=['POST'])
def update_subscription():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    subscription_id = request.json.get('subscriptionID')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE users SET is_paid = TRUE, uses_left = NULL WHERE username = %s', (session['user'],))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'message': 'Subscription updated!'})

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'Logged out', 'redirect': '/'})

@app.route('/reset_db', methods=['POST'])
def reset_db():
    if 'user' not in session or session['user'] != 'admin':  # Restrict to admin user
        return jsonify({'error': 'Unauthorized'}), 403
    init_db(reset=True)
    return jsonify({'message': 'Database reset successfully'})

@app.route('/remixback', methods=['POST', 'OPTIONS'])
def remix():
    if request.method == 'OPTIONS':
        return '', 200

    if 'user' not in session:
        return jsonify({'error': 'Please log in to remix content'}), 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT is_paid, uses_left FROM users WHERE username = %s', (session['user'],))
        user = cur.fetchone()
        if not user:
            cur.close()
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        is_paid = user['is_paid']
        uses_left = user['uses_left']

        if not is_paid and uses_left <= 0:
            cur.close()
            conn.close()
            return jsonify({'error': 'No free remixes left. Please upgrade.'}), 403

        data = request.json
        prompt = data.get('prompt', '')
        print(f"Received: {prompt[:50]}...")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={API_KEY}"
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }

        response = requests.post(url, json=payload)
        print(f"Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and result['candidates']:
                output = result['candidates'][0].get('content', {}).get('parts', [{}])[0].get('text', 'No output')
            else:
                output = 'No valid response from API'
            print(f"Success! Generated {len(output)} characters")

            if not is_paid:
                cur.execute('UPDATE users SET uses_left = %s WHERE username = %s', (uses_left - 1, session['user']))
                conn.commit()
                uses_left -= 1

            cur.close()
            conn.close()
            return jsonify({'output': output, 'uses_left': 'unlimited' if is_paid else uses_left})
        else:
            try:
                error_data = response.json()
                cur.close()
                conn.close()
                return jsonify({'error': error_data.get('error', {}).get('message', response.text)}), response.status_code
            except ValueError:
                cur.close()
                conn.close()
                return jsonify({'error': 'API server error'}), response.status_code

    except Exception as e:
        print(f"ERROR: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)