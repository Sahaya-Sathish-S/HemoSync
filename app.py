
import os
import sqlite3
import secrets
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, abort, g
)
from supabase import create_client, Client

load_dotenv()

app = Flask(__name__)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY is missing from your .env file.")

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("FLASK_ENV") == "production"
)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase URL or publishable key is missing.")

DATABASE = os.path.join(app.root_path, "hemosync_sessions.db")


# --------------------------------------------------
# SUPABASE CLIENT
# --------------------------------------------------

def get_supabase_client() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)


# --------------------------------------------------
# LOCAL SESSION STORAGE
# This does NOT store users or passwords.
# --------------------------------------------------

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS app_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                access_token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()


init_db()


# --------------------------------------------------
# SUPABASE AUTH HELPERS
# --------------------------------------------------

def verify_supabase_token(access_token):
    """
    Verify the access token with Supabase Auth.
    Never trust a user ID or role sent by the browser.
    """

    client = get_supabase_client()

    try:
        result = client.auth.get_user(access_token)
        user = result.user

        if not user:
            return None

        return user

    except Exception:
        app.logger.exception("Supabase token verification failed")
        return None


def get_supabase_profile(user_id, access_token):
    """
    Retrieve the authenticated user's own profile.

    The access token is attached to the PostgREST request,
    so the profiles table's RLS policies apply.
    """

    client = get_supabase_client()
    client.postgrest.auth(access_token)

    result = (
        client.table("profiles")
        .select(
            "id, full_name, email, role, "
            "is_verified, is_active, avatar_url"
        )
        .eq("id", user_id)
        .maybe_single()
        .execute()
    )

    return result.data


def create_app_session(user_id, access_token):
    """
    Store the Supabase token on the server.
    Only the random session ID is stored in Flask's cookie.
    """

    session_id = secrets.token_urlsafe(32)

    with get_db() as db:
        db.execute(
            """
            INSERT INTO app_sessions
                (session_id, user_id, access_token)
            VALUES (?, ?, ?)
            """,
            (session_id, user_id, access_token)
        )
        db.commit()

    session.clear()
    session["app_session_id"] = session_id
    session.permanent = True


def destroy_app_session():
    session_id = session.get("app_session_id")

    if session_id:
        with get_db() as db:
            db.execute(
                "DELETE FROM app_sessions WHERE session_id = ?",
                (session_id,)
            )
            db.commit()

    session.clear()


def get_current_user():
    """
    Validate the server-side session and recheck the
    Supabase token before using the user's profile.
    """

    session_id = session.get("app_session_id")

    if not session_id:
        return None

    with get_db() as db:
        auth_session = db.execute(
            """
            SELECT user_id, access_token
            FROM app_sessions
            WHERE session_id = ?
            """,
            (session_id,)
        ).fetchone()

    if not auth_session:
        session.clear()
        return None

    user = verify_supabase_token(auth_session["access_token"])

    if not user or str(user.id) != auth_session["user_id"]:
        destroy_app_session()
        return None

    try:
        profile = get_supabase_profile(
            auth_session["user_id"],
            auth_session["access_token"]
        )
    except Exception:
        app.logger.exception("Could not retrieve user profile")
        return None

    if not profile:
        destroy_app_session()
        return None

    if not profile.get("is_active", True):
        destroy_app_session()
        return None

    return profile


# --------------------------------------------------
# LOGIN DECORATOR
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):

        user = get_current_user()

        if not user:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        g.current_user = user

        return view(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):

            user_role = g.current_user.get("role")

            if user_role not in allowed_roles:
                abort(403)

            return view(*args, **kwargs)

        return wrapped_view

    return decorator


# --------------------------------------------------
# PUBLIC PAGES
# --------------------------------------------------

@app.route("/")
def loading():
    return render_template("loading.html")


@app.route("/login")
def login():

    user = get_current_user()

    if user:
        return redirect(url_for("home"))

    return render_template(
        "login.html",
        supabase_url=SUPABASE_URL,
        supabase_publishable_key=SUPABASE_KEY
    )


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


# --------------------------------------------------
# SUPABASE AUTH SESSION EXCHANGE
# Called by login.html after Supabase login/signup.
# --------------------------------------------------

@app.route("/auth/session", methods=["POST"])
def establish_session():

    data = request.get_json(silent=True) or {}
    access_token = data.get("access_token")

    if not access_token or not isinstance(access_token, str):
        return jsonify({
            "success": False,
            "message": "Missing access token."
        }), 400

    # Verify token with Supabase Auth.
    auth_user = verify_supabase_token(access_token)

    if not auth_user:
        return jsonify({
            "success": False,
            "message": "Invalid or expired login session."
        }), 401

    user_id = str(auth_user.id)

    try:
        profile = get_supabase_profile(user_id, access_token)
    except Exception:
        app.logger.exception("Profile lookup failed")
        return jsonify({
            "success": False,
            "message": "Could not load your HemoSync profile."
        }), 500

    if not profile:
        return jsonify({
            "success": False,
            "message": "Your profile has not been created yet."
        }), 403

    if not profile.get("is_active", True):
        return jsonify({
            "success": False,
            "message": "Your account is currently disabled."
        }), 403

    create_app_session(user_id, access_token)

    return jsonify({
        "success": True,
        "redirect": url_for("home"),
        "user": {
            "id": profile["id"],
            "name": profile["full_name"],
            "email": profile["email"],
            "role": profile["role"]
        }
    })


# --------------------------------------------------
# HOME / DASHBOARD
# --------------------------------------------------

@app.route("/home")
@login_required
def home():

    user = g.current_user

    return render_template(
        "index.html",
        user=user,
        user_name=user["full_name"],
        user_role=user["role"],
        is_verified=user["is_verified"]
    )


# --------------------------------------------------
# ROLE-BASED DASHBOARD EXAMPLE
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    role = g.current_user["role"]

    dashboard_routes = {
        "donator": "donor_dashboard",
        "hospital_manager": "hospital_dashboard",
        "camp_organizer": "camp_dashboard",
        "blood_bank_manager": "blood_bank_dashboard",
        "student": "user_dashboard",
        "normal_user": "user_dashboard",
        "admin": "admin_dashboard"
    }

    endpoint = dashboard_routes.get(role)

    if not endpoint:
        abort(403)

    return redirect(url_for(endpoint))


# --------------------------------------------------
# EXAMPLE ROLE-BASED PAGES
# Replace these with your actual dashboard templates.
# --------------------------------------------------

@app.route("/donor-dashboard")
@role_required("donator")
def donor_dashboard():
    return render_template("donor_dashboard.html", user=g.current_user)


@app.route("/hospital-dashboard")
@role_required("hospital_manager")
def hospital_dashboard():
    return render_template("hospital_dashboard.html", user=g.current_user)


@app.route("/camp-dashboard")
@role_required("camp_organizer")
def camp_dashboard():
    return render_template("camp_dashboard.html", user=g.current_user)


@app.route("/blood-bank-dashboard")
@role_required("blood_bank_manager")
def blood_bank_dashboard():
    return render_template("blood_bank_dashboard.html", user=g.current_user)


@app.route("/user-dashboard")
@role_required("normal_user", "student")
def user_dashboard():
    return render_template("user_dashboard.html", user=g.current_user)


@app.route("/admin-dashboard")
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", user=g.current_user)


# --------------------------------------------------
# ACCOUNT INFORMATION
# --------------------------------------------------

@app.route("/account")
@login_required
def account():

    user = g.current_user

    return jsonify({
        "id": user["id"],
        "name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
        "is_verified": user["is_verified"],
        "is_active": user["is_active"]
    })


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():

    destroy_app_session()

    if request.method == "POST":
        return jsonify({"success": True})

    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


# --------------------------------------------------
# RUN
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1"
    )
