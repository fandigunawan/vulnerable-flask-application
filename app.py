# WARNING: This application contains intentional security vulnerabilities
# DO NOT use this code in a production environment
# This is for educational purposes only

from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import subprocess
import pickle
import xml.etree.ElementTree as ET
import re
from datetime import datetime, timedelta
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure_secret_key'  # A1: Broken Access Control - Weak secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # A2: Cryptographic Failures - Storing passwords insecurely
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(32), unique=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create database tables
with app.app_context():
    db.create_all()
    # Add default admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password='admin123',  # A2: Cryptographic Failures - Plain text password
            email='admin@example.com',
            is_admin=True,
            api_key=''.join(random.choices(string.ascii_letters + string.digits, k=32))
        )
        db.session.add(admin)
        db.session.commit()

# A1: Broken Access Control
@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Missing authentication check
    user = User.query.get(user_id)
    if user:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard'))
    
    return "User not found", 404

# A2: Cryptographic Failures
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Insecure direct query without password hashing
        user = User.query.filter_by(username=username, password=password).first()
        
        if user:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard'))
        
        return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return render_template('login.html')

# A3: Injection
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # SQL Injection vulnerability
    sql = f"SELECT * FROM post WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
    result = db.engine.execute(sql)
    
    posts = [dict(row) for row in result]
    return render_template('search.html', posts=posts, query=query)

# A3: Injection (Command Injection)
@app.route('/ping', methods=['POST'])
def ping_server():
    hostname = request.form.get('hostname', '')
    
    # Command Injection vulnerability
    result = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
    
    return result

# A4: Insecure Design
@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    
    # Insecure design: No rate limiting, no verification
    user = User.query.filter_by(email=email).first()
    if user:
        # Generate a simple numeric token (too simple and predictable)
        token = str(random.randint(1000, 9999))
        # In a real app, we would send this token via email
        
        # Store token in session (insecure)
        session['reset_token'] = token
        session['reset_email'] = email
        
        return f"Password reset token: {token}"
    
    return "If the email exists, a reset link has been sent."

# A5: Security Misconfiguration
@app.route('/debug')
def debug_info():
    # Exposing sensitive debug information
    debug_info = {
        'app_config': str(app.config),
        'environment': os.environ,
        'python_version': sys.version,
        'db_uri': app.config['SQLALCHEMY_DATABASE_URI']
    }
    return jsonify(debug_info)

# A6: Vulnerable and Outdated Components
# Using outdated libraries (specified in requirements.txt)
# Flask 2.0.1 and Werkzeug 2.0.1 may have known vulnerabilities
# Check vulnerability here
# 1. https://security.snyk.io/vuln
# 2. Install pip-audit using pip install pip-audit
#    example of pip-audit output:
#    Found 10 known vulnerabilities in 4 packages                                                                                               
#    Name       Version ID                  Fix Versions
#    ---------- ------- ------------------- ------------
#    flask      2.0.1   PYSEC-2023-62       2.2.5,2.3.2
#    pip        21.1.1  PYSEC-2023-228      23.3
#    setuptools 56.0.0  PYSEC-2022-43012    65.5.1
#    werkzeug   2.0.1   PYSEC-2022-203      2.1.1
#    werkzeug   2.0.1   PYSEC-2023-58       2.2.3
#    werkzeug   2.0.1   PYSEC-2023-57       2.2.3
#    werkzeug   2.0.1   PYSEC-2023-221      2.3.8,3.0.1
#    werkzeug   2.0.1   GHSA-2g68-c3qc-8985 3.0.3
#    werkzeug   2.0.1   GHSA-f9vj-2wh5-fj8j 3.0.6
#    werkzeug   2.0.1   GHSA-q34m-jh98-gwm2 3.0.6

# A7: Identification and Authentication Failures
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')  # No password complexity requirements
        email = request.form.get('email')
        
        # No validation for username uniqueness before insertion
        # No email verification
        
        new_user = User(
            username=username,
            password=password,  # No password hashing
            email=email,
            api_key=''.join(random.choices(string.ascii_letters + string.digits, k=32))
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# A8: Software and Data Integrity Failures
@app.route('/import_data', methods=['POST'])
def import_data():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    
    if file.filename.endswith('.pickle'):
        # Insecure deserialization
        data = pickle.loads(file.read())
        return f"Imported data: {data}"
    
    elif file.filename.endswith('.xml'):
        # XML External Entity (XXE) vulnerability
        parser = ET.XMLParser()
        tree = ET.parse(file, parser)
        root = tree.getroot()
        return f"Parsed XML: {ET.tostring(root)}"
    
    return "Unsupported file format", 400

# A9: Security Logging and Monitoring Failures
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # No proper logging of admin actions
    # No audit trail
    
    if session.get('is_admin'):
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
    
    return "Unauthorized", 403

# A10: Server-Side Request Forgery (SSRF)
@app.route('/fetch_url', methods=['POST'])
def fetch_url():
    import urllib.request
    
    url = request.form.get('url')
    
    # SSRF vulnerability - no validation of URL
    try:
        response = urllib.request.urlopen(url)
        data = response.read().decode('utf-8')
        return data
    except Exception as e:
        return f"Error: {str(e)}", 500

# Cross-Site Scripting (XSS)
@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get(post_id)
    if not post:
        return "Post not found", 404
    
    # XSS vulnerability - unescaped content
    return f"""
    <h1>{post.title}</h1>
    <div>{post.content}</div>
    """

# Cross-Site Request Forgery (CSRF)
@app.route('/change_email', methods=['POST'])
def change_email():
    # No CSRF token validation
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    new_email = request.form.get('email')
    user = User.query.get(session['user_id'])
    
    if user:
        user.email = new_email
        db.session.commit()
        return "Email updated successfully"
    
    return "User not found", 404

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    posts = Post.query.filter_by(user_id=user.id).all()
    
    return render_template('dashboard.html', user=user, posts=posts)

# Admin dashboard
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return "Unauthorized", 403
    
    users = User.query.all()
    return render_template('admin.html', users=users)

# Create post
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_public = 'is_public' in request.form
        
        post = Post(
            title=title,
            content=content,
            user_id=session['user_id'],
            is_public=is_public
        )
        
        db.session.add(post)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    
    return render_template('create_post.html')

# API endpoint with insecure direct object reference
@app.route('/api/posts/<int:post_id>')
def api_get_post(post_id):
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({"error": "API key required"}), 401
    
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "Invalid API key"}), 401
    
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404
    
    # Insecure direct object reference - no check if the post belongs to the user
    return jsonify({
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "user_id": post.user_id,
        "is_public": post.is_public
    })

@app.route('/')
def index():
    public_posts = Post.query.filter_by(is_public=True).all()
    return render_template('index.html', posts=public_posts)

if __name__ == '__main__':
    app.run(debug=True)  # Running in debug mode - security risk in production