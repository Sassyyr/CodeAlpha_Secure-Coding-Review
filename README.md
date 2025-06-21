# CodeAlpha_Secure-Coding-Review
This project is a secure Flask-based login system built as part of a secure coding review task. It implements secure session management, hashed passwords, and CSRF protection using Flask-WTF. The code was audited using Bandit to identify vulnerabilities and follows secure coding best practices.

🛡 Features
Flask-WTF form handling with CSRF protection

Password hashing with werkzeug.security

Session management for protected pages

Secure environment variable handling for SECRET_KEY

Styled HTML templates with responsive design

🔍 Security Review Summary
Tool Used: Bandit

Issue Found: Hardcoded default SECRET_KEY fallback

Remediation: Enforced use of .env for secret key and removed fallback
