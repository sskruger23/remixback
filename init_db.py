import sqlite3
import bcrypt

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
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            username TEXT,
            ip TEXT,
            success BOOLEAN,
            timestamp TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            message TEXT,
            timestamp TIMESTAMP
        )''')
        conn.commit()
        # Create test user
        username = 'testuser'
        password = 'testpass123'
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()

init_db()