from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_session import Session
import requests
import os
from dotenv import load_dotenv
import sys

# Ensure flask-session is used
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey123'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')  # Use project dir
app.config['SESSION_PERMANENT'] = False
load_dotenv()
CORS(app)

# Initialize Session
try:
    Session(app)
    print(f"Session initialized, directory: {app.config['SESSION_FILE_DIR']}")
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
except Exception as e:
    print(f"Failed to initialize session: {str(e)}", file=sys.stderr)
    sys.exit(1)

API_KEY = os.getenv('GENERATIVE_API_KEY')
PAYPAL_PLAN = 'P-5LK680852J287884DNDUFRKA'

users = {'test': {'password': 'test', 'paid': False, 'uses': 3}}
session_uses = {}

def log_error(message):
    print(f"ERROR: {message}", file=sys.stderr)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_session')
def check_session():
    user = session.get('user')
    if user and user in users:
        uses_left = session_uses.get(user, users[user]['uses'])
        print(f"Session check: User={user}, Uses={uses_left}, Paid={users[user]['paid']}")
        return jsonify({'logged_in': True, 'is_paid': users[user]['paid'], 'uses_left': uses_left})
    print("Session check: No user logged in")
    return jsonify({'logged_in': False})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        hcaptcha_response = request.form.get('h-captcha-response')
        if not hcaptcha_response:
            return jsonify({'error': 'Please complete the hCaptcha'}), 400
        secret_key = os.getenv('HCAPTCHA_SECRET_KEY')
        verify_url = 'https://hcaptcha.com/siteverify'
        response = requests.post(verify_url, data={'secret': secret_key, 'response': hcaptcha_response})
        result = response.json()
        if not result.get('success'):
            return jsonify({'error': 'Invalid hCaptcha'}), 400
        print(f"Login attempt: Raw Username={username!r}, Raw Password={password!r}, Form data={dict(request.form)}, Headers={dict(request.headers)}, Session={session}")

        if username.lower() == 'test' and password.lower() == 'test':
            session['user'] = 'test'
            session_uses['test'] = 3
            print(f"Login success: Session set for test")
            return jsonify({'message': 'Login OK', 'is_paid': False, 'uses_left': 3})
        print("Login failed: Invalid credentials")
        return jsonify({'error': 'Use test/test (case insensitive)'}), 401
    except Exception as e:
        log_error(f"Login error: {str(e)} with traceback: {str(e.__traceback__)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        hcaptcha_response = request.form.get('h-captcha-response')
        if not hcaptcha_response:
            return jsonify({'error': 'Please complete the hCaptcha'}), 400
        secret_key = os.getenv('HCAPTCHA_SECRET_KEY')
        verify_url = 'https://hcaptcha.com/siteverify'
        response = requests.post(verify_url, data={'secret': secret_key, 'response': hcaptcha_response})
        result = response.json()
        if not result.get('success'):
            return jsonify({'error': 'Invalid hCaptcha'}), 400
        if username in users:
            return jsonify({'error': 'Username already exists'}), 400
        users[username] = {'password': password, 'paid': False, 'uses': 3}
        session['user'] = username
        session_uses[username] = 3
        print(f"Registration success: User {username} created")
        return jsonify({'message': 'Registration successful', 'redirect': '/login'})
    except Exception as e:
        log_error(f"Register error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/logout')
def logout():
    try:
        user = session.get('user')
        if user:
            print(f"Logout: {user}")
            session.pop('user', None)
            session_uses.pop(user, None)
        return jsonify({'message': 'Logged out'})
    except Exception as e:
        log_error(f"Logout error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/remix', methods=['POST'])
def remix():
    try:
        user = session.get('user')
        print(f"Remix request: User={user}, Session={session}")
        if not user:
            print("Remix failed: No user")
            return jsonify({'error': 'Log in first!'}), 401
        
        uses_left = session_uses.get(user, 3)
        print(f"Uses left: {uses_left}")
        if uses_left <= 0:
            print("Remix failed: No uses left")
            return jsonify({'error': 'No free remixes left!'}), 403
        
        prompt = request.json.get('prompt')
        remix_type = request.json.get('remix-type', 'blog')
        print(f"Remix data: Prompt={prompt[:50]}..., Type={remix_type}")
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={API_KEY}"
        payload = {
            "contents": [{"parts": [{"text": f"Rewrite this as a {remix_type}: {prompt}"}]}]
        }
        
        response = requests.post(url, json=payload)
        print(f"API Response: Status={response.status_code}")
        data = response.json()
        if 'error' in data:
            raise Exception(f"API error: {data['error']['message']}")
        if not data.get('candidates'):
            raise Exception("No candidates returned from API")
        output = data['candidates'][0]['content']['parts'][0]['text']
        session_uses[user] = uses_left - 1
        print(f"Remix success: Output length={len(output)}")
        return jsonify({'output': output, 'uses_left': session_uses[user]})
    except Exception as e:
        log_error(f"Remix error: {str(e)}")
        return jsonify({'output': f'Error: {str(e)} or AI mock: Your {remix_type} here!'})

@app.route('/update_subscription', methods=['POST'])
def update_subscription():
    try:
        user = session.get('user')
        if user:
            users[user]['paid'] = True
            print(f"Subscription updated for {user}")
        return jsonify({'message': 'UPGRADED!'})
    except Exception as e:
        log_error(f"Subscription error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/contact', methods=['POST'])
def contact():
    print("Contact form submitted")
    return jsonify({'message': 'Message sent! (demo)'})