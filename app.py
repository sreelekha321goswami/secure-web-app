import os
import re
import sqlite3
import time
from functools import wraps
 
from dotenv import load_dotenv
from flask import (
    Flask, render_template, redirect, url_for, flash, g, session, request
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, Regexp, ValidationError
)
from werkzeug.security import generate_password_hash, check_password_hash
 
load_dotenv()
 
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
 
# ---------- Secure cookie settings ----------
app.config['SESSION_COOKIE_SECURE'] = True      # cookie only sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True     # JavaScript can't read the cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'    # basic CSRF protection on cookies
 
DATABASE = 'database.db'
 
 
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db
 
 
@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()
 
 
def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
 
 
def strong_password(form, field):
    pw = field.data or ''
    has_upper = re.search(r'[A-Z]', pw)
    has_lower = re.search(r'[a-z]', pw)
    has_digit = re.search(r'\d', pw)
    has_symbol = re.search(r'[^A-Za-z0-9]', pw)
    if not (has_upper and has_lower and has_digit and has_symbol):
        raise ValidationError('Password needs an uppercase letter, a lowercase letter, a number and a special character.')
 
 
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=30),
        Regexp(r'^[A-Za-z0-9_]+$', message='Only letters, numbers and underscores allowed.'),
    ])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128), strong_password])
    confirm = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
 
 
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
 
 
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
failed_attempts = {}
 
 
def is_locked_out(username):
    record = failed_attempts.get(username)
    if not record:
        return False
    count, first_failure = record
    if count < MAX_ATTEMPTS:
        return False
    if time.time() - first_failure > LOCKOUT_SECONDS:
        failed_attempts.pop(username, None)
        return False
    return True
 
 
def record_failed_attempt(username):
    count, first_failure = failed_attempts.get(username, [0, time.time()])
    count += 1
    failed_attempts[username] = [count, first_failure]
 
 
def clear_failed_attempts(username):
    failed_attempts.pop(username, None)
 
 
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access that page.', 'error')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped
 
 
# ---------- Security headers on every response ----------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
 
 
@app.route('/')
def home():
    return render_template('index.html')
 
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (form.username.data, form.email.data.lower(), generate_password_hash(form.password.data))
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash('Username or email is already in use.', 'error')
            return render_template('register.html', form=form)
        flash('Account created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', form=form)
 
 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
 
        if is_locked_out(username):
            flash('Too many failed attempts. Try again in a minute.', 'error')
            return render_template('login.html', form=form)
 
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
 
        if user is None or not check_password_hash(user['password_hash'], form.password.data):
            record_failed_attempt(username)
            flash('Invalid username or password.', 'error')
            return render_template('login.html', form=form)
 
        clear_failed_attempts(username)
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))
 
    return render_template('login.html', form=form)
 
 
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))
 
 
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))
 
 
init_db()
 
if __name__ == '__main__':
    # ssl_context='adhoc' generates a temporary self-signed certificate
    # so the dev server serves over https:// instead of http://
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", ssl_context='adhoc')
 