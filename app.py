import hashlib
import os

import requests
from flask import Flask, flash, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_seasurf import SeaSurf
from flask_talisman import Talisman

app = Flask(__name__)
# In production, this would be a real secret key from environment variables
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-for-resume-project")

# 1. SECURITY HEADERS (Talisman)
# We allow inline styles/scripts for simplicity in this demo, but force HTTPS logic
Talisman(app, content_security_policy=None, force_https=False)

# 2. CSRF PROTECTION (SeaSurf)
csrf = SeaSurf(app)

# 3. RATE LIMITING (Limiter)
# High limit (1000/hour) so it doesn't annoy you, but shows you know how to implement it.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per hour"],
    storage_uri="memory://",
)


def pwned_api_check(password):
    """
    K-Anonymity Logic:
    1. Hash password with SHA-1.
    2. Send only the first 5 chars to the API.
    3. Receive a list of suffixes and check if our tail matches one.
    """
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5, tail = sha1password[:5], sha1password[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5}"
    try:
        res = requests.get(url, timeout=5)
        res.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"API Error: {str(e)}")

    # Process response
    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return int(count)
    return 0


@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Specific stricter limit for the actual check
def home():
    result = None
    if request.method == "POST":
        password = request.form.get("password")
        if password:
            try:
                count = pwned_api_check(password)
                result = {
                    "count": count,
                    "safe": count == 0,
                    "message": f"This password has been seen {count:,} times in data breaches."
                    if count > 0
                    else "Good news! This password was not found in known breaches.",
                }
            except Exception as e:
                flash(f"Error connecting to check service: {e}", "error")

    return render_template("home.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
