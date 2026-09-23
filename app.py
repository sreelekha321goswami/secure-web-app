import os
import re
import sqlite3

from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, flash, g
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, Regexp, ValidationError
)
from werkzeug.security import generate_password_hash

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']  # never hard-code secrets

DATABASE = 'database.db'


# ---------- Database helpers ----------
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


# ---------- Input validation ----------
def strong_password(form, field):
    pw = field.data or ''
    if not (re.search(r'[A-Z]', pw) and re.search(r'[a-z]', pw)
            and re.search(r'\d', pw) and re.search(r'[^A-Za-z0-9]', pw)):
        raise ValidationError(
            'Password needs an uppercase letter, a lowercase letter, '
            'a number and a special character.'
        )


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=30),
        Regexp(r'^[A-Za-z0-9_]+$',
               message='Only letters, numbers and underscores allowed.'),
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(), Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), Length(min=8, max=128), strong_password
    ])
    confirm = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')
    ])


# ---------- Routes ----------
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        db = get_db()
        try:
            # Parameterized query (?) protects against SQL injection
            db.execute(
                'INSERT INTO users (username, email, password_hash) '
                'VALUES (?, ?, ?)',
                (form.username.data,
                 form.email.data.lower(),
                 generate_password_hash(form.password.data))
            )
            db.commit()
        except sqlite3.IntegrityError:
            # Generic message: don't reveal which field already exists
            flash('Username or email is already in use.', 'error')
            return render_template('register.html', form=form)
        flash('Account created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', form=form)


init_db()

if __name__ == '__main__':
    app.run(debug=True)  # we will turn debug off before final submission