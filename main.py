from datetime import datetime, timedelta
import os
from urllib.parse import urlparse, urljoin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

from forms import RegisterForm, LoginForm, RidePostForm, ProfileForm

# ---------------- Extensions ----------------
db = SQLAlchemy()
login_manager = LoginManager()

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

# Email + token generator
mail = Mail()
serializer = URLSafeTimedSerializer(os.environ.get("SECRET_KEY"))



# ---------- helper ----------
def flash_first_error(form):
    if not form.errors:
        return
    if 'email' in form.errors:
        flash(form.errors['email'][0], "danger")
    else:
        field, errors = next(iter(form.errors.items()))
        flash(errors[0], "danger")


def is_safe_url(target: str) -> bool:
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ("http", "https")) and (ref_url.netloc == test_url.netloc)


def send_verification_email(user):
    """Send verification email to user"""
    token = serializer.dumps(user.email, salt="email-confirm")
    verify_url = url_for("verify_email", token=token, _external=True)

    msg = Message("Verify Your FouzFleet Account", recipients=[user.email])
    msg.body = f"""
Hey {user.full_name},

Welcome to FouzFleet!

Click below to verify your email:
{verify_url}

If this wasn't you, just ignore this email.
"""
    mail.send(msg)


def create_app():
    app = Flask(__name__)

    # ---------- Core config ----------
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-only-change-me")

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        db_url = "sqlite:///" + os.path.join(BASE_DIR, "fouzfleet.db").replace("\\", "/")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ---------- Email config (Gmail) ----------
    app.config['MAIL_SERVER'] = "smtp.gmail.com"
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")   # Gmail
    app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")   # App password
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_USERNAME")
    mail.init_app(app)

    # Security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE']  = os.environ.get("COOKIE_SECURE", "0") == "1"
    app.config['REMEMBER_COOKIE_SECURE'] = os.environ.get("COOKIE_SECURE", "0") == "1"
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
    app.config['WTF_CSRF_TIME_LIMIT'] = 60 * 60 * 8

    # CDU email enforcement
    app.config['ENFORCE_CDU_EMAIL'] = os.environ.get("ENFORCE_CDU_EMAIL", "1") == "1"
    app.config['CDU_EMAIL_DOMAINS'] = ["cdu.edu.au", "students.cdu.edu.au", "student.cdu.edu.au"]

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = None
    login_manager.needs_refresh_message = None

    # ---------------- Models ----------------
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        full_name = db.Column(db.String(50), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False, index=True)
        phone = db.Column(db.String(15), nullable=False)
        dob = db.Column(db.Date, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        
        verified = db.Column(db.Boolean, default=False)   # ✅ REQUIRED FIELD
        
        posts = db.relationship("Post", backref="author", lazy=True)

    class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        origin = db.Column(db.String(120), nullable=False)
        destination = db.Column(db.String(120), nullable=False)
        time_str = db.Column(db.String(80), nullable=False)
        days = db.Column(db.String(120), nullable=False)
        seats = db.Column(db.Integer, nullable=False, default=1)
        notes = db.Column(db.Text, nullable=True)
        created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---------------- Security headers ----------------
    @app.after_request
    def add_security_headers(resp):
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp

    # ---------------- Routes ----------------
    @app.route("/", methods=["GET"])
    @login_required
    def home():
        posts = Post.query.order_by(Post.created_at.desc()).all()
        return render_template("home_page.html", posts=posts)

    # POST RIDE
    @app.route("/post", methods=["GET", "POST"])
    @login_required
    @limiter.limit("20/hour;100/day")
    def post_ride():
        form = RidePostForm()
        if form.validate_on_submit():
            p = Post(
                origin=form.origin.data.strip(),
                destination=form.destination.data.strip(),
                time_str=form.time_str.data.strip(),
                days=form.days.data.strip(),
                seats=form.seats.data,
                notes=(form.notes.data or "").strip(),
                author=current_user,
            )
            db.session.add(p)
            db.session.commit()
            flash("Ride posted!", "success")
            return redirect(url_for("home"))
        elif request.method == "POST":
            flash_first_error(form)
        return render_template("posting_page.html", form=form)

    # REGISTER (✅ Sends email verification)
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5/minute;15/hour")
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("home"))

        form = RegisterForm()

        if form.validate_on_submit():
            email_l = form.email.data.lower().strip()

            existing = User.query.filter(func.lower(User.email) == email_l).first()
            if existing:
                flash("Email already registered.", "danger")
                return redirect(url_for("register"))

            u = User(
                full_name=form.full_name.data.strip(),
                email=email_l,
                phone=form.phone.data.strip(),
                dob=form.dob.data,
                password_hash=generate_password_hash(form.password.data),
                verified=False     # 🚨 not verified until clicking link
            )

            db.session.add(u)
            db.session.commit()

            send_verification_email(u)  # ✅ send email

            flash("Account created! Check your CDU email for verification link.", "success")
            return redirect(url_for("login"))

        elif request.method == "POST":
            flash_first_error(form)
        return render_template("signup_page.html", form=form)

    # LOGIN (✅ Blocks unverified users)
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10/minute;50/hour")
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("home"))

        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter(
                func.lower(User.email) == form.email.data.lower().strip()
            ).first()
            if user and check_password_hash(user.password_hash, form.password.data):

                if not user.verified:     # ⛔ BLOCK IF NOT VERIFIED
                    flash("Verify your email first — check your inbox.", "warning")
                    return redirect(url_for("login"))

                login_user(user, remember=True)
                next_page = request.args.get("next")
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)
                flash(f"Welcome back, {user.full_name.split()[0]}!", "success")
                return redirect(url_for("home"))
            flash("Invalid email or password.", "danger")
        elif request.method == "POST":
            flash_first_error(form)

        return render_template("login_page.html", form=form)

    # ✅ VERIFY EMAIL ROUTE
    @app.route("/verify/<token>")
    def verify_email(token):
        try:
            email = serializer.loads(token, salt="email-confirm", max_age=3600)
        except:
            flash("Verification link expired or invalid.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first_or_404()
        user.verified = True
        db.session.commit()

        flash("✅ Email verified! You can now log in.", "success")
        return redirect(url_for("login"))

    # LOGOUT
    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # PROFILE
    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    @limiter.limit("30/hour")
    def profile():
        form = ProfileForm(obj=current_user)
        if form.validate_on_submit():
            new_email = form.email.data.lower().strip()
            if new_email != current_user.email:
                exists = User.query.filter(User.email == new_email, User.id != current_user.id).first()
                if exists:
                    flash("That email is already in use.", "danger")
                    return render_template("profile_page.html", form=form)
            current_user.email = new_email
            current_user.phone = form.phone.data.strip()
            db.session.commit()
            flash("Contact details updated.", "success")
            return redirect(url_for("profile"))
        elif request.method == "POST":
            flash_first_error(form)
        return render_template("profile_page.html", form=form)

    # DELETE POST
    @app.route("/delete/<int:post_id>", methods=["GET"])
    @login_required
    def delete_post(post_id):
        post = Post.query.get_or_404(post_id)
        if post.author != current_user:
            flash("You can only delete your own posts.", "danger")
            return redirect(url_for("home"))
        db.session.delete(post)
        db.session.commit()

        flash("Your post has been deleted.", "info")
        return redirect(url_for("home"))

    # Ensure tables exist
    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)

