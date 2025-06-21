from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Set secret key with a fallback option
print("DEBUG: SECRET_KEY =", os.getenv("SECRET_KEY"))
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable not set. Please define it in your .env file.")
app.secret_key = secret_key

# In-memory user database (hashed passwords)
users = {
    'user1': generate_password_hash('password1'),
    'user2': generate_password_hash('password2')
}

# WTForms Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Login-required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You need to be logged in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home route redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('You were successfully logged in.')
            return redirect(url_for('protected'))
        else:
            flash('Invalid username or password.')
            return render_template('login.html', form=form)  # Render form again for invalid login
    return render_template('login.html', form=form)

# Protected route
@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html', username=session['username'])

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Main entry point
if __name__ == '__main__':
    app.run(debug=False)  # Change to debug=False in production 