from flask import Flask, render_template, request, jsonify
import sqlite3
import requests
import os

app = Flask(__name__, template_folder='templates', static_folder='static')

# Initialize SQLite database
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS contacts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      email TEXT NOT NULL,
                      message TEXT NOT NULL,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()

# Verify hCaptcha response
def verify_hcaptcha(response):
    secret_key = os.getenv('HCAPTCHA_SECRET_KEY', 'your_hcaptcha_secret_key_here')
    data = {'response': response, 'secret': secret_key}
    verification = requests.post('https://hcaptcha.com/siteverify', data=data).json()
    return verification['success']

# Serve the main page
@app.route('/')
def index():
    return render_template('index.html')

# Handle form submission
@app.route('/submit', methods=['POST'])
def submit_form():
    try:
        data = request.form
        hcaptcha_response = data.get('h-captcha-response')
        
        if not verify_hcaptcha(hcaptcha_response):
            return jsonify({'error': 'hCaptcha verification failed'}), 400
            
        name = data.get('name')
        email = data.get('email')
        message = data.get('message')
        
        if not all([name, email, message]):
            return jsonify({'error': 'All fields are required'}), 400
            
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)',
                     (name, email, message))
            conn.commit()
            
        return jsonify({'message': 'Form submitted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Serve static files explicitly if needed
@app.route('/static/<path:filename>')
def serve_static(filename):
    return app.send_static_file(filename)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)