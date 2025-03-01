# Vulnerable Flask Application: Security Solutions

This document provides detailed explanations of the security vulnerabilities present in the application and how to fix them properly.

## 1. Broken Access Control

### Vulnerability
The application fails to properly restrict access to resources based on user privileges:
- User profiles can be accessed without authentication via `/user/<id>`
- API endpoints allow accessing any post with a valid API key, regardless of ownership
- Missing authorization checks for admin functions

### Solution
```python
@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Require authentication
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Only allow users to view their own profile unless admin
    if session['user_id'] != user_id and not session.get('is_admin'):
        return "Unauthorized", 403
    
    user = User.query.get(user_id)
    if user:
        return render_template('user.html', user=user)
    return "User not found", 404

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
    
    # Check if the post belongs to the user or is public
    if post.user_id != user.id and not post.is_public and not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify({
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "user_id": post.user_id,
        "is_public": post.is_public
    })
```

## 2. Cryptographic Failures

### Vulnerability
- Passwords are stored in plaintext
- Weak secret key for session management
- Direct comparison of plaintext passwords during login

### Solution
```python
# Use a strong, randomly generated secret key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)

# Use password hashing for storage and verification
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        
        new_user = User(
            username=username,
            password=hashed_password,  # Store the hash, not the plaintext
            email=email,
            api_key=''.join(random.choices(string.ascii_letters + string.digits, k=32))
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find the user by username only
        user = User.query.filter_by(username=username).first()
        
        # Verify the password hash
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard'))
        
        return "Invalid credentials", 401
    
    return render_template('login.html')
```

## 3. Injection

### Vulnerability
- SQL Injection in the search functionality
- Command Injection in the ping functionality
- Unvalidated user input used directly in queries and commands

### Solution

#### SQL Injection Fix
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Use parameterized queries with SQLAlchemy
    posts = Post.query.filter(
        db.or_(
            Post.title.like(f'%{query}%'),
            Post.content.like(f'%{query}%')
        )
    ).all()
    
    return render_template('search.html', posts=posts, query=query)
```

#### Command Injection Fix
```python
@app.route('/ping', methods=['POST'])
def ping_server():
    hostname = request.form.get('hostname', '')
    
    # Validate hostname format
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return "Invalid hostname format", 400
    
    # Use subprocess list form to avoid shell
    try:
        result = subprocess.check_output(['ping', '-c', '1', hostname], stderr=subprocess.STDOUT, timeout=5)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}", 400
    except subprocess.TimeoutExpired:
        return "Timeout: Command took too long to execute", 400
```

## 4. Insecure Design

### Vulnerability
- Weak password reset functionality with predictable tokens
- No rate limiting for sensitive operations
- No verification of user identity during password reset

### Solution
```python
import secrets
from datetime import datetime, timedelta

# Store reset tokens securely
reset_tokens = {}  # In a real app, use a database table

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    
    # Rate limiting
    client_ip = request.remote_addr
    now = datetime.now()
    
    # Check if this IP has made too many requests
    if client_ip in request_rate and len(request_rate[client_ip]) >= 5:
        # Check if the oldest request is less than 1 hour old
        if (now - request_rate[client_ip][0]).total_seconds() < 3600:
            return "Too many password reset attempts. Please try again later.", 429
        else:
            # Remove old requests
            while request_rate[client_ip] and (now - request_rate[client_ip][0]).total_seconds() >= 3600:
                request_rate[client_ip].pop(0)
    
    # Add this request to the rate limit tracker
    if client_ip not in request_rate:
        request_rate[client_ip] = []
    request_rate[client_ip].append(now)
    
    user = User.query.filter_by(email=email).first()
    if user:
        # Generate a secure token
        token = secrets.token_urlsafe(32)
        
        # Store token with expiration (1 hour)
        reset_tokens[token] = {
            'user_id': user.id,
            'expires': datetime.now() + timedelta(hours=1)
        }
        
        # In a real app, send this via email
        reset_url = url_for('confirm_reset', token=token, _external=True)
        
        # For demo purposes only - in a real app, don't reveal this
        return f"Password reset link: {reset_url}"
    
    # Always return the same message to prevent user enumeration
    return "If the email exists, a reset link has been sent to your email address."

@app.route('/confirm_reset/<token>', methods=['GET', 'POST'])
def confirm_reset(token):
    # Check if token exists and is valid
    if token not in reset_tokens or datetime.now() > reset_tokens[token]['expires']:
        return "Invalid or expired token", 400
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            return "Passwords do not match", 400
        
        # Update user's password
        user_id = reset_tokens[token]['user_id']
        user = User.query.get(user_id)
        
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            
            # Remove the used token
            del reset_tokens[token]
            
            return redirect(url_for('login'))
    
    return render_template('reset_password.html')
```

## 5. Security Misconfiguration

### Vulnerability
- Debug mode enabled in production
- Sensitive debug information exposed via `/debug` endpoint
- Default credentials (admin/admin123)
- Missing security headers

### Solution
```python
# Use environment-specific configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dev.db'

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///prod.db'

# Choose config based on environment
config = ProductionConfig if os.environ.get('FLASK_ENV') == 'production' else DevelopmentConfig
app.config.from_object(config)

# Remove debug endpoint
# @app.route('/debug') - Remove this entirely

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Change default admin password during setup
with app.app_context():
    db.create_all()
    # Add default admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password=generate_password_hash(os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)),
            email='admin@example.com',
            is_admin=True,
            api_key=''.join(random.choices(string.ascii_letters + string.digits, k=32))
        )
        db.session.add(admin)
        db.session.commit()
```

## 6. Vulnerable and Outdated Components

### Vulnerability
- Using outdated versions of Flask (2.0.1) and Werkzeug (2.0.1)
- Potential vulnerabilities in dependencies

### Solution
Update `requirements.txt`:
```
Flask==2.3.3
Flask-SQLAlchemy==3.1.1
Flask-WTF==1.2.1
Flask-Login==0.6.2
Werkzeug==2.3.7
email_validator==2.0.0
```

Implement a dependency management strategy:
1. Regularly update dependencies
2. Use tools to scan for vulnerabilities:
   ```bash
   pip install safety
   safety check

   pip install pip-audit
   pip-audit
   ```
3. Subscribe to security bulletins for used packages
4. Remove unused dependencies to reduce attack surface
5. Consider using a virtual environment with pinned dependencies
6. Consider source code scanner such as Sonarqube or Checkmarx

## 7. Identification and Authentication Failures

### Vulnerability
- Weak password policies
- No account lockout mechanism
- No multi-factor authentication
- No email verification

### Solution
```python
# Password validation function
def is_password_strong(password):
    # At least 8 characters, with uppercase, lowercase, number, and special char
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# Track login attempts
login_attempts = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Validate username uniqueness
        if User.query.filter_by(username=username).first():
            return "Username already exists", 400
            
        # Validate email uniqueness and format
        if User.query.filter_by(email=email).first():
            return "Email already registered", 400
        
        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            return "Invalid email format", 400
            
        # Check password strength
        if not is_password_strong(password):
            return "Password must be at least 8 characters and include uppercase, lowercase, number, and special character", 400
            
        # Create user with hashed password
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            email=email,
            api_key=secrets.token_urlsafe(32),
            email_verified=False  # Add this field to User model
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate verification token
        token = secrets.token_urlsafe(32)
        # Store token (in a real app, use a database table)
        verification_tokens[token] = {
            'user_id': new_user.id,
            'expires': datetime.now() + timedelta(days=1)
        }
        
        # Send verification email (in a real app)
        verification_url = url_for('verify_email', token=token, _external=True)
        
        # For demo purposes only
        return f"Account created. Please verify your email: {verification_url}"
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check for too many failed attempts
        client_ip = request.remote_addr
        current_time = datetime.now()
        
        if client_ip in login_attempts:
            # Remove attempts older than 15 minutes
            login_attempts[client_ip] = [time for time in login_attempts[client_ip] 
                                        if (current_time - time).total_seconds() < 900]
            
            # If 5 or more attempts in the last 15 minutes, lock out
            if len(login_attempts[client_ip]) >= 5:
                return "Too many failed login attempts. Please try again later.", 429
        
        # Find the user
        user = User.query.filter_by(username=username).first()
        
        # Verify password
        if user and check_password_hash(user.password, password):
            # Check if email is verified
            if not user.email_verified:
                return "Please verify your email before logging in", 403
                
            # Reset failed attempts on successful login
            if client_ip in login_attempts:
                login_attempts[client_ip] = []
                
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            
            # Set secure session cookie
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=1)
            
            return redirect(url_for('dashboard'))
        
        # Track failed attempt
        if client_ip not in login_attempts:
            login_attempts[client_ip] = []
        login_attempts[client_ip].append(current_time)
        
        return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    if token not in verification_tokens or datetime.now() > verification_tokens[token]['expires']:
        return "Invalid or expired verification link", 400
    
    user_id = verification_tokens[token]['user_id']
    user = User.query.get(user_id)
    
    if user:
        user.email_verified = True
        db.session.commit()
        
        # Remove the used token
        del verification_tokens[token]
        
        return redirect(url_for('login'))
    
    return "User not found", 404
```

## 8. Software and Data Integrity Failures

### Vulnerability
- Insecure deserialization of pickle files
- XML External Entity (XXE) vulnerability
- No integrity verification of uploaded files

### Solution
```python
@app.route('/import_data', methods=['POST'])
def import_data():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    
    # Only allow safe formats
    if file.filename.endswith('.json'):
        try:
            # Use safe JSON parsing
            data = json.loads(file.read().decode('utf-8'))
            return f"Imported data: {data}"
        except json.JSONDecodeError:
            return "Invalid JSON format", 400
    
    elif file.filename.endswith('.xml'):
        try:
            # Use safe XML parsing with external entities disabled
            parser = ET.XMLParser(resolve_entities=False)
            tree = ET.parse(file, parser)
            root = tree.getroot()
            return f"Parsed XML: {ET.tostring(root)}"
        except ET.ParseError:
            return "Invalid XML format", 400
    
    # Reject unsafe formats
    return "Unsupported file format. Only JSON and XML are allowed.", 400
```

## 9. Security Logging and Monitoring Failures

### Vulnerability
- No logging of security-relevant events
- No audit trail for admin actions
- No monitoring or alerting system

### Solution
```python
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s'
)

# Create a security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# Add file handler for security events
security_handler = logging.FileHandler('security.log')
security_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] - %(message)s'))
security_logger.addHandler(security_handler)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find the user
        user = User.query.filter_by(username=username).first()
        
        # Verify password
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            
            # Log successful login
            security_logger.info(f"Successful login: user={username}, ip={request.remote_addr}")
            
            return redirect(url_for('dashboard'))
        
        # Log failed login attempt
        security_logger.warning(f"Failed login attempt: username={username}, ip={request.remote_addr}")
        
        return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Check if user is admin
    if not session.get('is_admin'):
        security_logger.warning(f"Unauthorized admin action attempt: delete_user, user_id={session.get('user_id', 'unknown')}, target={user_id}, ip={request.remote_addr}")
        return "Unauthorized", 403
    
    user = User.query.get(user_id)
    if user:
        # Log the admin action
        admin_user = User.query.get(session['user_id'])
        security_logger.info(f"Admin action: delete_user, admin={admin_user.username}, target={user.username}, ip={request.remote_addr}")
        
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    
    return "User not found", 404

# Add a middleware to log all requests
@app.before_request
def log_request():
    # Don't log static file requests
    if not request.path.startswith('/static/'):
        logging.info(f"Request: {request.method} {request.path} - IP: {request.remote_addr}")

# Add error logging
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return "An unexpected error occurred", 500
```

## 10. Server-Side Request Forgery (SSRF)

### Vulnerability
- Unvalidated URL fetching in the `/fetch_url` endpoint
- Potential access to internal services and sensitive information

### Solution
```python
import ipaddress
from urllib.parse import urlparse
import socket

@app.route('/fetch_url', methods=['POST'])
def fetch_url():
    import urllib.request
    
    url = request.form.get('url')
    
    # Parse the URL
    try:
        parsed_url = urlparse(url)
        
        # Validate scheme
        if parsed_url.scheme not in ['http', 'https']:
            return "Invalid URL scheme. Only HTTP and HTTPS are allowed.", 400
        
        # Extract hostname
        hostname = parsed_url.netloc.split(':')[0]
        
        # Block localhost and private IPs
        blocked_hostnames = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if hostname in blocked_hostnames:
            return "Access to internal hosts is forbidden", 403
            
        # Try to resolve hostname to check for internal IPs
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Block private, loopback, link-local, and reserved IPs
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_reserved):
                return "Access to internal networks is forbidden", 403
                
            # Block specific cloud metadata IPs
            if ip == '169.254.169.254':  # AWS metadata
                return "Access to cloud metadata services is forbidden", 403
        except (socket.gaierror, ValueError):
            # If hostname can't be resolved, continue (will likely fail later)
            pass
        
        # Use an allowlist approach for domains if possible
        # allowed_domains = ['api.example.com', 'public-api.org']
        # if hostname not in allowed_domains:
        #     return "Domain not in allowed list", 403
        
        # Set a timeout to prevent hanging connections
        response = urllib.request.urlopen(url, timeout=5)
        data = response.read().decode('utf-8')
        
        # Log the URL fetch
        logging.info(f"URL fetched: {url}, user_id={session.get('user_id', 'anonymous')}, ip={request.remote_addr}")
        
        return data
    except Exception as e:
        return f"Error: {str(e)}", 500
```

## Additional Vulnerabilities

### Cross-Site Scripting (XSS)

#### Vulnerability
- Unescaped user content in post display
- HTML allowed in post content

#### Solution
```python
# In templates, use automatic escaping
# Change this:
# <div>{{ post.content | safe }}</div>
# To this:
# <div>{{ post.content }}</div>

# For the view_post route, use proper templating
@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get(post_id)
    if not post:
        return "Post not found", 404
    
    # Use template with automatic escaping
    return render_template('post.html', post=post)

# If HTML formatting is required, use a sanitization library
from markupsafe import Markup
from bleach import clean

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_public = 'is_public' in request.form
        
        # Sanitize HTML content
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'ul', 'ol', 'li']
        sanitized_content = clean(content, tags=allowed_tags, strip=True)
        
        post = Post(
            title=title,
            content=sanitized_content,
            user_id=session['user_id'],
            is_public=is_public
        )
        
        db.session.add(post)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    
    return render_template('create_post.html')
```

### Cross-Site Request Forgery (CSRF)

#### Vulnerability
- No CSRF tokens in forms
- Vulnerable endpoints like `/change_email`

#### Solution
```python
from flask_wtf.csrf import CSRFProtect

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Update forms to include CSRF token
# In templates:
# <form method="post" action="{{ url_for('change_email') }}">
#     <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#     ...
# </form>

@app.route('/change_email', methods=['POST'])
def change_email():
    # CSRF protection is automatically enforced by flask-wtf
    
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    new_email = request.form.get('email')
    user = User.query.get(session['user_id'])
    
    if user:
        # Log the email change
        security_logger.info(f"Email changed: user={user.username}, old={user.email}, new={new_email}, ip={request.remote_addr}")
        
        user.email = new_email
        db.session.commit()
        return "Email updated successfully"
    
    return "User not found", 404
```

## Comprehensive Security Improvements

### Session Management
```python
# Configure secure session
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Short session lifetime
```

### Database Security
```python
# Use parameterized queries for all database operations
# Example:
@app.route('/user_posts/<username>')
def user_posts(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found", 404
        
    posts = Post.query.filter_by(user_id=user.id, is_public=True).all()
    return render_template('user_posts.html', user=user, posts=posts)
```

### Input Validation
```python
# Create validation functions for all user inputs
def validate_username(username):
    if not username or len(username) < 3 or len(username) > 30:
        return False
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    return True

def validate_email(email):
    try:
        # Use email_validator library
        valid = validate_email(email)
        return True
    except EmailNotValidError:
        return False
```

### Error Handling
```python
# Create custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # Log the error
    logging.error(f"500 error: {str(e)}", exc_info=True)
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403
```

### Rate Limiting
```python
# Implement rate limiting for sensitive endpoints
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic here
    pass

@app.route('/reset_password', methods=['POST'])
@limiter.limit("3 per hour")
def reset_password():
    # Password reset logic here
    pass
```

## Conclusion

Securing a web application requires a comprehensive approach that addresses multiple layers of security. The fixes provided in this document address the OWASP Top 10 vulnerabilities and additional security concerns, but security is an ongoing process.

Key principles to remember:
1. **Defense in Depth**: Implement multiple layers of security controls
2. **Least Privilege**: Limit access to the minimum necessary
3. **Input Validation**: Never trust user input
4. **Output Encoding**: Always encode output to prevent XSS
5. **Secure by Default**: Start with secure configurations
6. **Keep Updated**: Regularly update dependencies and apply security patches
7. **Monitor and Log**: Maintain comprehensive logs and monitor for suspicious activity

By following these principles and implementing the fixes described in this document, you can significantly improve the security posture of your web application.