# Secure Web App

A secure login/signup web application built with **Python and Flask**, developed as a college project on secure coding practices and security testing.

**Author:** Sreeleha Goswami

## Features

- User registration and login with a protected dashboard
- Password hashing (Werkzeug)
- Server-side input validation (Flask-WTF / WTForms)
- CSRF protection on forms
- Session cookies with `Secure`, `HttpOnly` and `SameSite=Lax` flags
- Login-required protection on private pages
- Generic login error message (does not reveal whether the username or password was wrong)
- HTTPS using a self-signed certificate for local development
- Security response headers: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`
- SQLite database

## Tech stack

Python 3.12, Flask, Flask-WTF, SQLite, python-dotenv

## How to run it

1. Clone the repository and open the folder:
```
   git clone https://github.com/sreelekha321goswami/secure-web-app.git
   cd secure-web-app
```
2. Create and activate a virtual environment (Windows PowerShell):
```
   python -m venv venv
   venv\Scripts\activate
```
3. Install the dependencies:
```
   pip install -r requirements.txt
```
4. Create a file named `.env` in the project folder and add a secret key:
```
   SECRET_KEY=paste-a-long-random-value-here
```
   You can generate a value with:
```
   python -c "import secrets; print(secrets.token_hex(32))"
```
5. Start the app:
```
   python app.py
```
6. Open **https://127.0.0.1:5000** in your browser.

The app uses a self-signed certificate, so the browser shows a "Your connection is not private" warning. Click **Advanced**, then **Proceed to 127.0.0.1**. This is expected for local development.

The `.env` file and the database file are deliberately **not** included in this repository, because they contain secrets and user data.

Debug mode is **off** by default. To turn it on for development only, add `FLASK_DEBUG=1` to `.env`.

## Security testing summary

| Test | Tool / method | Result |
|---|---|---|
| Static analysis | Bandit | 1 High issue (Flask `debug=True`), fixed. Re-scan found no issues. |
| SQL injection | Manual test on login form | Rejected |
| Cross-site scripting (XSS) | Manual test on register form | Rejected by input validation |
| CSRF | Login request sent without a token | Rejected, no session created |
| Security headers | `curl` inspection | Four headers present; no Content-Security-Policy |
| Dependency vulnerabilities | pip-audit | 9 known issues in 3 packages, fixed by upgrading. Re-scan clean. |
| Dynamic scanner | OWASP ZAP | Installer was blocked by Windows Defender, so manual tests were used instead |

## Known limitations and possible improvements

- Add a `Content-Security-Policy` header.
- Hide the server version shown in the `Server` response header.
- Replace the self-signed certificate with one from a trusted authority for any real deployment.
- Run behind a production WSGI server (the Flask development server is used here).
- Add rate limiting on login attempts.

## Disclaimer

This is an educational project and is not intended for production use as it stands.
