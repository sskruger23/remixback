from flask import Flask, request, jsonify, session, make_response
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import os
import traceback
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from flask_hcaptcha import hCaptcha
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

# CORS configuration
CORS(app, resources={r"/remixback": {"origins": [
    "https://remixback-git-main-sarahs-projects-d812bb6b.vercel.app",
    "https://remixback.vercel.app",
    "https://www.nextlogicai.com",
    "https://nextlogicai.com"
]}})

# Load API keys and secrets
API_KEY = os.getenv('GENERATIVE_API_KEY')
if not API_KEY:
    raise ValueError("GENERATIVE_API_KEY not set")

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-fallback')
app.config['SESSION_TYPE'] = 'filesystem'  # Server-side sessions
app.config['HCAPTCHA_ENABLED'] = True
app.config['HCAPTCHA_SITE_KEY'] = os.getenv('HCAPTCHA_SITE_KEY')
app.config['HCAPTCHA_SECRET'] = os.getenv('HCAPTCHA_SECRET')
Session(app)
hcaptcha = hCaptcha(app)

# Initialize SQLite database
def init_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            failed_attempts INTEGER DEFAULT 0,
            lock_until TIMESTAMP,
            is_paid BOOLEAN DEFAULT FALSE,
            uses_left INTEGER DEFAULT 3
        )''')
        conn.commit()

init_db()

# IP-based rate limiter for login
limiter = Limiter(app, key_func=get_remote_address)
login_limiter = limiter.limit("5 per minute")  # 5 login attempts per minute per IP

@app.route('/login', methods=['POST', 'OPTIONS'])
@login_limiter
def login():
    if request.method == 'OPTIONS':
        return '', 200

    username = request.form.get('username')
    password = request.form.get('password')
    hcaptcha_response = request.form.get('h-captcha-response')

    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()

        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401

        username, password_hash, failed_attempts, lock_until, is_paid, uses_left = user
        lock_until = datetime.fromisoformat(lock_until) if lock_until else None

        # Check lockout
        if lock_until and lock_until > datetime.now():
            return jsonify({'error': 'Account locked. Try again later.'}), 429

        # Check CAPTCHA after 3 failed attempts
        cookie_attempts = int(request.cookies.get('failed_attempts', '0'))
        if failed_attempts >= 3 or cookie_attempts >= 3:
            if not hcaptcha_response or not hcaptcha.verify(hcaptcha_response):
                return jsonify({'error': 'CAPTCHA required or invalid.'}), 400

        # Validate password
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            session['user'] = username
            c.execute('UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE username = ?', (username,))
            conn.commit()
            resp = make_response(jsonify({'message': 'Login successful!', 'redirect': '/', 'is_paid': is_paid, 'uses_left': uses_left}), 200)
            resp.set_cookie('failed_attempts', '0', max_age=3600)
            return resp
        else:
            new_attempts = failed_attempts + 1
            lock_until = datetime.now() + timedelta(minutes=5) if new_attempts >= 3 else None
            c.execute('UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?',
                      (new_attempts, lock_until.isoformat() if lock_until else None, username))
            conn.commit()
            resp = make_response(jsonify({'error': 'Invalid username or password'}), 401)
            resp.set_cookie('failed_attempts', str(cookie_attempts + 1), max_age=3600)
            return resp

@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200

    username = request.form.get('username')
    password = request.form.get('password')
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            return jsonify({'message': 'User registered!'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'Logged out', 'redirect': '/login'})

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'user' in session:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT is_paid, uses_left FROM users WHERE username = ?', (session['user'],))
            user = c.fetchone()
            if user:
                return jsonify({'logged_in': True, 'is_paid': user[0], 'uses_left': user[1]})
    return jsonify({'logged_in': False})

@app.route('/update_subscription', methods=['POST', 'OPTIONS'])
def update_subscription():
    if request.method == 'OPTIONS':
        return '', 200

    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    subscription_id = request.json.get('subscriptionID')
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET is_paid = TRUE WHERE username = ?', (session['user'],))
        conn.commit()
    return jsonify({'message': 'Subscription updated!'})

@app.route('/remixback', methods=['POST', 'OPTIONS'])
def remix():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        if 'user' not in session:
            return jsonify({'error': 'Please log in to remix content'}), 401

        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT is_paid, uses_left FROM users WHERE username = ?', (session['user'],))
            user = c.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            is_paid, uses_left = user

            if not is_paid and uses_left <= 0:
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
                    new_uses_left = uses_left - 1
                    c.execute('UPDATE users SET uses_left = ? WHERE username = ?', (new_uses_left, session['user']))
                    conn.commit()
                    return jsonify({'output': output, 'uses_left': new_uses_left})
                else:
                    return jsonify({'output': output, 'uses_left': 'unlimited'})

            else:
                try:
                    error_data = response.json()
                    return jsonify({'error': error_data.get('error', {}).get('message', response.text)}), response.status_code
                except ValueError:
                    return jsonify({'error': 'API server error'}), response.status_code
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)