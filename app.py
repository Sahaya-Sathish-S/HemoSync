import os
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Set a strong SECRET_KEY in your environment before deploying.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-dev-secret-key")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["DATABASE"] = os.path.join(app.root_path, "hemosync.db")

# -------------------- Database --------------------

def get_db():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT,
                role TEXT NOT NULL DEFAULT 'normal_user',
                auth_provider TEXT NOT NULL DEFAULT 'local',
                is_verified INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()


init_db()

# These are the roles that can be selected during public signup.
# Admin is deliberately excluded: an ordinary visitor must not be
# able to grant themselves administrator access.
ALLOWED_ROLES = {
    "donator",
    "hospital_manager",
    "camp_organizer",
    "blood_bank_manager",
    "normal_user",
    "student",
}


# -------------------- Optional Google OAuth --------------------
# Install with: pip install Authlib
# Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET as environment variables.
google = None
try:
    from authlib.integrations.flask_client import OAuth

    if os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
        oauth = OAuth(app)
        google = oauth.register(
            name="google",
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            server_metadata_url=(
                "https://accounts.google.com/.well-known/openid-configuration"
            ),
            client_kwargs={"scope": "openid email profile"},
        )
except ImportError:
    # The rest of the app still works without Google OAuth.
    google = None


# -------------------- Helpers --------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def save_user_session(user):
    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["email"] = user["email"]
    session["role"] = user["role"]


def find_user_by_email(email):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.strip().lower(),)
        ).fetchone()


# -------------------- Main pages --------------------

@app.route("/")
def loading():
    # Renders templates/loading.html
    return render_template("loading.html")


@app.route("/home")
def home():
    # Renders templates/index.html
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # GET displays the login/signup page.
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("home"))
        return render_template("login.html")

    # POST processes the login form.
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    remember = request.form.get("remember") == "on"

    if not email or not password:
        flash("Enter your email address and password.", "error")
        return redirect(url_for("login"))

    user = find_user_by_email(email)

    if not user or not user["password_hash"]:
        flash("Invalid email or password. Please try again.", "error")
        return redirect(url_for("login"))

    if not check_password_hash(user["password_hash"], password):
        flash("Invalid email or password. Please try again.", "error")
        return redirect(url_for("login"))

    save_user_session(user)
    session.permanent = remember
    flash("You are now logged in.", "success")
    return redirect(url_for("home"))


@app.route("/signup", methods=["POST"])
def signup():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(name) < 2 or len(name) > 100:
        flash("Please enter a valid full name.", "error")
        return redirect(url_for("login"))

    if not email or len(email) > 254:
        flash("Please enter a valid email address.", "error")
        return redirect(url_for("login"))

    if role not in ALLOWED_ROLES:
        flash("That account role is not available for public signup.", "error")
        return redirect(url_for("login"))

    if len(password) < 8:
        flash("Your password must contain at least 8 characters.", "error")
        return redirect(url_for("login"))

    if password != confirm_password:
        flash("The passwords do not match.", "error")
        return redirect(url_for("login"))

    if find_user_by_email(email):
        flash("An account with this email already exists. Please log in.", "error")
        return redirect(url_for("login"))

    password_hash = generate_password_hash(password)

    try:
        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO users (name, email, password_hash, role, auth_provider)
                VALUES (?, ?, ?, ?, 'local')
                """,
                (name, email, password_hash, role),
            )
            db.commit()
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        flash("This email is already registered. Please log in.", "error")
        return redirect(url_for("login"))

    user = {
        "id": user_id,
        "name": name,
        "email": email,
        "role": role,
    }
    save_user_session(user)
    flash("Your HemoSync account has been created successfully.", "success")
    return redirect(url_for("home"))


# -------------------- Google sign-in --------------------

@app.route("/auth/google")
def google_login():
    if google is None:
        flash(
            "Google sign-in is not configured. Set GOOGLE_CLIENT_ID and "
            "GOOGLE_CLIENT_SECRET and install Authlib.",
            "error",
        )
        return redirect(url_for("login"))

    callback_url = url_for("google_callback", _external=True)
    return google.authorize_redirect(callback_url)


@app.route("/auth/google/callback")
def google_callback():
    if google is None:
        flash("Google sign-in is not configured.", "error")
        return redirect(url_for("login"))

    try:
        token = google.authorize_access_token()
        profile = token.get("userinfo")

        if not profile:
            profile = google.parse_id_token(token, nonce=None)

        email = (profile.get("email") or "").strip().lower()
        name = (profile.get("name") or profile.get("given_name") or "HemoSync User").strip()

        if not email or profile.get("email_verified") is False:
            flash("Google did not provide a verified email address.", "error")
            return redirect(url_for("login"))

        user = find_user_by_email(email)

        if user:
            # Existing account: keep its role and account details.
            save_user_session(user)
        else:
            # Google-created accounts start as normal users.
            # They can update/request an organization role through a
            # separate verification workflow later.
            with get_db() as db:
                cursor = db.execute(
                    """
                    INSERT INTO users (name, email, password_hash, role, auth_provider)
                    VALUES (?, ?, NULL, 'normal_user', 'google')
                    """,
                    (name, email),
                )
                db.commit()
                user_id = cursor.lastrowid

            save_user_session({
                "id": user_id,
                "name": name,
                "email": email,
                "role": "normal_user",
            })

        flash("You have signed in with Google.", "success")
        return redirect(url_for("home"))

    except Exception:
        app.logger.exception("Google OAuth callback failed")
        flash("Google sign-in failed. Please try again.", "error")
        return redirect(url_for("login"))


# -------------------- Account and utility routes --------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password")
def forgot_password():
    # Replace this placeholder with an email-based password reset flow.
    return (
        "<h2>HemoSync password recovery</h2>"
        "<p>Password recovery has not been connected yet.</p>"
        '<p><a href="/login">Return to login</a></p>'
    )


@app.route("/terms")
def terms():
    return (
        "<h2>HemoSync Terms</h2>"
        "<p>Please add your application's terms of use here.</p>"
        '<p><a href="/login">Back</a></p>'
    )


@app.route("/privacy")
def privacy():
    return (
        "<h2>HemoSync Privacy Policy</h2>"
        "<p>Please add your application's privacy policy here.</p>"
        '<p><a href="/login">Back</a></p>'
    )


@app.route("/account")
@login_required
def account():
    return {
        "id": session["user_id"],
        "name": session["name"],
        "email": session["email"],
        "role": session["role"],
    }


if __name__ == "__main__":
    # Development only. Use a production WSGI server and HTTPS in deployment.
    app.run(host="0.0.0.0", port=5000, debug=True)
