from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_session import Session
import requests
import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from bcrypt import hashpw, gensalt, checkpw
from flask import make_response

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', '2f28a2528a8149a1333078c5985fc3f55508bba01390828e')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
app.config['SESSION_PERMANENT'] = False
load_dotenv()
CORS(app)

try:
    Session(app)
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    print(f"Session initialized, directory: {app.config['SESSION_FILE_DIR']}")
except Exception as e:
    print(f"Failed to initialize session: {str(e)}", file=sys.stderr)
    sys.exit(1)

db_url = os.getenv('DATABASE_URL')
try:
    conn = psycopg2.connect(db_url)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    print("Database connected")
except Exception as e:
    print(f"Database connection failed: {str(e)}", file=sys.stderr)
    sys.exit(1)

@app.teardown_appcontext
def close_db(error):
    if 'conn' in globals() and conn:
        conn.close()

API_KEY = os.getenv('GENERATIVE_API_KEY')
PAYPAL_PLAN = os.getenv('PAYPAL_PLAN', 'P-5LK680852J287884DNDUFRKA')

def log_error(message):
    print(f"ERROR: {message}", file=sys.stderr)

def init_db():
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            paid BOOLEAN DEFAULT FALSE,
            uses INTEGER DEFAULT 3
        )
    """)
    conn.commit()
    cur.execute("SELECT username FROM users WHERE username = 'test'")
    if not cur.fetchone():
        cur.execute("INSERT INTO users (username, password, paid, uses) VALUES (%s, %s, %s, %s)",
                    ('test', hashpw('test'.encode(), gensalt()), False, 3))
        conn.commit()
    print("Database initialized")

init_db()

# Track unpaid users with cookies
def get_user_uses(ip_address):
    cur.execute("SELECT uses FROM users WHERE username = (SELECT username FROM session WHERE session_id = %s)", (session.sid,))
    user_data = cur.fetchone()
    if user_data:
        return user_data['uses']
    # Fallback for anonymous users (IP-based)
    cookie_uses = request.cookies.get(f'uses_{ip_address}')
    return int(cookie_uses) if cookie_uses else 3

def set_user_uses(ip_address, uses):
    response = make_response(jsonify({'message': 'Uses updated'}))
    response.set_cookie(f'uses_{ip_address}', str(uses), max_age=3600)  # 1-hour expiry
    return response

@app.route('/')
def index():
    return render_template('index.html', paypal_plan=PAYPAL_PLAN)

@app.route('/check_session')
def check_session():
    user = session.get('user')
    ip_address = request.remote_addr
    if user:
        cur.execute("SELECT paid, uses FROM users WHERE username = %s", (user,))
        user_data = cur.fetchone()
        if user_data:
            return jsonify({'logged_in': True, 'is_paid': user_data['paid'], 'uses_left': user_data['uses']})
    else:
        uses_left = get_user_uses(ip_address)
        return jsonify({'logged_in': False, 'uses_left': uses_left})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        hcaptcha_response = request.form.get('h-captcha-response')
        if not hcaptcha_response:
            return jsonify({'error': 'Please complete the hCaptcha'}), 400
        secret_key = os.getenv('HCAPTCHA_SECRET_KEY')
        verify_url = 'https://hcaptcha.com/siteverify'
        response = requests.post(verify_url, data={'secret': secret_key, 'response': hcaptcha_response})
        result = response.json()
        if not result.get('success'):
            return jsonify({'error': 'Invalid hCaptcha'}), 400
        cur.execute("SELECT password, paid, uses FROM users WHERE username = %s", (username.lower(),))
        user_data = cur.fetchone()
        if user_data and checkpw(password.encode(), user_data['password']):
            session['user'] = username.lower()
            return jsonify({'message': 'Login OK', 'is_paid': user_data['paid'], 'uses_left': user_data['uses']})
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        log_error(f"Login error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        hcaptcha_response = request.form.get('h-captcha-response')
        if not hcaptcha_response:
            return jsonify({'error': 'Please complete the hCaptcha'}), 400
        secret_key = os.getenv('HCAPTCHA_SECRET_KEY')
        verify_url = 'https://hcaptcha.com/siteverify'
        response = requests.post(verify_url, data={'secret': secret_key, 'response': hcaptcha_response})
        result = response.json()
        if not result.get('success'):
            return jsonify({'error': 'Invalid hCaptcha'}), 400
        cur.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({'error': 'Username already exists'}), 400
        hashed_password = hashpw(password.encode(), gensalt())
        cur.execute("INSERT INTO users (username, password, paid, uses) VALUES (%s, %s, %s, %s)",
                    (username, hashed_password, False, 3))
        conn.commit()
        session['user'] = username
        return jsonify({'message': 'Registration successful', 'redirect': '/login'})
    except Exception as e:
        log_error(f"Register error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/logout')
def logout():
    try:
        user = session.get('user')
        if user:
            session.pop('user', None)
        return jsonify({'message': 'Logged out'})
    except Exception as e:
        log_error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/remix', methods=['POST'])
def remix():
    try:
        user = session.get('user')
        ip_address = request.remote_addr
        if user:
            cur.execute("SELECT paid, uses FROM users WHERE username = %s", (user,))
            user_data = cur.fetchone()
            if not user_data:
                return jsonify({'error': 'User not found'}), 404
            uses_left = user_data['uses']
            is_paid = user_data['paid']
        else:
            uses_left = get_user_uses(ip_address)
            is_paid = False

        if not is_paid and uses_left <= 0:
            return jsonify({'error': 'No free remixes left!'}), 403

        prompt = request.json.get('prompt')
        if not prompt:
            return jsonify({'error': 'Prompt is required'}), 400
        remix_type = request.json.get('remix-type', 'blog')
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={API_KEY}"
        payload = {"contents": [{"parts": [{"text": f"Rewrite this as a {remix_type}: {prompt}"}]}]}
        response = requests.post(url, json=payload)
        data = response.json()
        if 'error' in data:
            raise Exception(data['error']['message'])
        if not data.get('candidates'):
            raise Exception("No candidates returned from API")
        output = data['candidates'][0]['content']['parts'][0]['text']

        if not is_paid:
            if user:
                cur.execute("UPDATE users SET uses = uses - 1 WHERE username = %s", (user,))
                conn.commit()
            else:
                set_user_uses(ip_address, uses_left - 1)

        return jsonify({'output': output, 'uses_left': uses_left - 1 if not is_paid else None})
    except Exception as e:
        log_error(f"Remix error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/update_subscription', methods=['POST'])
def update_subscription():
    try:
        user = session.get('user')
        if user:
            cur.execute("UPDATE users SET paid = TRUE WHERE username = %s", (user,))
            conn.commit()
        return jsonify({'message': 'UPGRADED!'})
    except Exception as e:
        log_error(f"Subscription error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/contact', methods=['POST'])
def contact():
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        if not all([name, email, message]):
            return jsonify({'error': 'All fields are required'}), 400
        print(f"Contact from {name} ({email}): {message}")
        return jsonify({'message': 'Message sent! (demo)'})
    except Exception as e:
        log_error(f"Contact error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500