# hashguard-security-scanner

*Privacy-preserving credential breach scanner powered by HaveIBeenPwned*

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python) ![Flask](https://img.shields.io/badge/Flask-Web_App-lightgrey?logo=flask) ![HaveIBeenPwned](https://img.shields.io/badge/API-HaveIBeenPwned-red)

---

## About

HashGuard is a Flask web application that checks whether a password has appeared in a known data breach — without ever sending the actual password anywhere.

It implements the [K-Anonymity model](https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/) used by the HaveIBeenPwned API: the password is hashed with SHA-1 locally, only the first 5 characters of that hash are transmitted to the API, and the matching check happens entirely on the client side. The plaintext password never leaves the machine.

---

## Features

- **K-Anonymity hashing** — only a 5-character hash prefix is sent to the API; the full password never leaves your machine
- **CSRF protection** — form submissions are protected via `flask-seasurf`
- **Rate limiting** — 1,000 requests/hour globally with a stricter 10/minute limit on the check endpoint via `flask-limiter`
- **Security headers** — HTTP security headers applied automatically via `flask-talisman`
- **Dark/light theme** — toggle persists across page loads and form submissions via `localStorage`
- **Error handling** — API failures surface as user-friendly flash messages rather than raw exceptions

---

## How K-Anonymity Works

```
Your Password → SHA-1 Hash → Split into prefix (5 chars) + suffix (35 chars)
                                        ↓
                          API receives only the prefix
                                        ↓
                     API returns all breach hashes with that prefix
                                        ↓
                  Your code checks locally if your suffix is in the list
```

The API never sees enough of the hash to reverse-engineer the original password, and it has no way to know which entry in its response you were checking against.

---

## Project Structure

```
hashguard/
├── app.py                  # Flask app, routes, K-Anonymity logic
├── requirements.txt        # Python dependencies
├── templates/
│   ├── layout.html         # Base template (nav, theme toggle, flash messages)
│   └── home.html           # Password check form and results
└── static/
    └── css/
        └── main.css        # Theming via CSS custom properties
```

---

## Setup & Usage

**1. Create a virtual environment and install dependencies:**
```
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

**2. Run the development server:**
```
python app.py
```

**3. Open in your browser:**
```
http://127.0.0.1:5000
```

> **Note:** A `SECRET_KEY` environment variable should be set in any real deployment. The app falls back to a development key locally, which is safe for local use only.

---

## Technical Highlights

**K-Anonymity via SHA-1 range query**

The `pwned_api_check()` function hashes the input with `hashlib.sha1()`, splits the result into a 5-character prefix and 35-character suffix, and queries the HaveIBeenPwned range endpoint with only the prefix. The API returns all known breach hashes sharing that prefix — the function then checks locally whether the suffix appears in that list, returning the breach count if found or `0` if clean.

**Layered security middleware**

Three Flask extensions handle distinct security concerns independently: `flask-talisman` injects HTTP security headers on every response, `flask-seasurf` validates CSRF tokens on all POST requests, and `flask-limiter` enforces rate limits at both the application and route level. Each addresses a different attack surface without overlapping.

**CSS custom properties for theming**

Light and dark themes are implemented entirely via CSS custom properties (`--bg`, `--text`, `--accent`, etc.) on the `:root` and `[data-theme="light"]` selectors. Switching themes is a single `setAttribute` call in JavaScript — no class toggling or style recalculation needed. The selected theme is persisted to `localStorage` so it survives page reloads and form submissions.

---

## License

[MIT](LICENSE)
