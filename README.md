# Vulnerable Flask Application

**WARNING: This application contains intentional security vulnerabilities!**

This is a deliberately vulnerable Flask application that demonstrates the OWASP Top 10 web application security risks. It is intended for educational purposes only, to help developers understand common security vulnerabilities and how to prevent them.

## OWASP Top 10 Vulnerabilities Demonstrated

1. **Broken Access Control** - Missing authentication checks, insecure direct object references
2. **Cryptographic Failures** - Storing passwords in plaintext, weak encryption
3. **Injection** - SQL injection, command injection
4. **Insecure Design** - Weak password reset functionality
5. **Security Misconfiguration** - Debug information exposure
6. **Vulnerable and Outdated Components** - Using outdated libraries
7. **Identification and Authentication Failures** - Weak password policies, no account lockout
8. **Software and Data Integrity Failures** - Insecure deserialization
9. **Security Logging and Monitoring Failures** - Insufficient logging
10. **Server-Side Request Forgery (SSRF)** - Unvalidated URL fetching

## Setup Instructions
0. Install Python 3.8.* (old and unsupported Python version).\
Use pyenv and env to prevent this obsolete version from ruining your computer.
1. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python app.py
   ```

3. Access the application at http://127.0.0.1:5000

## Default Credentials

- Username: admin
- Password: admin123

## Educational Purpose

This application is designed for:
- Security training
- Learning about web vulnerabilities
- Understanding how to fix security issues
- Practicing security testing techniques

## DO NOT USE IN PRODUCTION

This application is intentionally insecure and should never be deployed in a production environment or exposed to the public internet.