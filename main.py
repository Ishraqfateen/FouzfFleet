from datetime import datetime, timedelta
import os
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

from forms import RegisterForm, LoginForm, RidePostForm, ProfileForm
db = SQLAlchemy()
login_manager = LoginManager()

#rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def flash_first_error(form):
    """Flash the first validation error; prefer email to surface 'CDU email only'."""
    if not form.errors:
        return
    if 'email' in form.errors:
        flash(form.errors['email'][0], "danger")
    else:
        field, errors = next(iter(form.errors.items()))
        flash(errors[0], "danger")


def is_safe_url(target: str) -> bool:
    """Only allow redirects to same-origin absolute/relative URLs."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ("http", "https")) and (ref_url.netloc == test_url.netloc)


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

    #Security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
    #mark cookies secure when served via HTTPS 
    app.config['SESSION_COOKIE_SECURE']  = os.environ.get("COOKIE_SECURE", "0") == "1"
    app.config['REMEMBER_COOKIE_SECURE'] = os.environ.get("COOKIE_SECURE", "0") == "1"
    #session lifetime
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
    #CSRF token age
    app.config['WTF_CSRF_TIME_LIMIT'] = 60 * 60 * 8  # 8 hours

    #Checks CDU emails
    app.config['ENFORCE_CDU_EMAIL'] = os.environ.get("ENFORCE_CDU_EMAIL", "1") == "1"
    app.config['CDU_EMAIL_DOMAINS'] = ["cdu.edu.au", "students.cdu.edu.au", "student.cdu.edu.au"]

    #init extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = None          
    login_manager.needs_refresh_message = None  

    #models
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        full_name = db.Column(db.String(50), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False, index=True)
        phone = db.Column(db.String(15), nullable=False)
        dob = db.Column(db.Date, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
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

    #security headers
    @app.after_request
    def add_security_headers(resp):
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp

    #error handlers 
    @app.errorhandler(429)
    def ratelimit_handler(e):
        flash("Too many requests. Please wait a moment and try again.", "warning")
        
        return redirect(request.referrer or url_for("home"))

    #routes 
    @app.route("/", methods=["GET"])
    @login_required
    def home():
        posts = Post.query.order_by(Post.created_at.desc()).all()
        return render_template("home_page.html", posts=posts)

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

            # create user
            u = User(
                full_name=form.full_name.data.strip(),
                email=email_l,
                phone=form.phone.data.strip(),
                dob=form.dob.data,
                password_hash=generate_password_hash(form.password.data),
            )
            db.session.add(u)
            db.session.commit()
            login_user(u, remember=True)
            flash(f"Welcome to FouzFleet, {u.full_name.split()[0]}!", "success")
            return redirect(url_for("home"))

        elif request.method == "POST":
            flash_first_error(form)
        return render_template("signup_page.html", form=form)

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

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))


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

    
    with app.app_context():
        db.create_all()

    return app



app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
