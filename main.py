from datetime import datetime
import os
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message

from forms import RegisterForm, LoginForm, RidePostForm, ProfileForm

# ---------- GLOBAL EXTENSIONS ----------
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")




# ---------- HELPERS ----------
def flash_first_error(form):
    if form.errors:
        field, errors = next(iter(form.errors.items()))
        flash(errors[0], "danger")


def is_safe_url(target: str) -> bool:
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


# ---------- APP FACTORY ----------
def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

    # Token generator (signed data stored temporarily)
    serializer = URLSafeTimedSerializer(os.environ.get("SECRET_KEY", "dev-secret"))

    # DB setup
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        db_url = "sqlite:///" + os.path.join(BASE_DIR, "fouzfleet.db").replace("\\", "/")

    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Email config
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")
    mail.init_app(app)

    # Security cookies
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
    app.config["REMEMBER_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = None

    # ---------- MODELS ----------
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        full_name = db.Column(db.String(50), nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False, index=True)
        phone = db.Column(db.String(15), nullable=False)
        dob = db.Column(db.Date, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)

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


    # ---------- ROUTES ----------

    @app.route("/")
    @login_required
    def home():
        posts = Post.query.order_by(Post.created_at.desc()).all()
        return render_template("home_page.html", posts=posts)


    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5/minute;15/hour")
    def register():

        form = RegisterForm()

        if form.validate_on_submit():
            email_l = form.email.data.lower().strip()

            existing = User.query.filter(func.lower(User.email) == email_l).first()
            if existing:
                flash("Email already registered. Log in instead.", "warning")
                return redirect(url_for("login"))

            # ✅ Store form data in token, DO NOT create user yet
            token = serializer.dumps({
                "full_name": form.full_name.data.strip(),
                "email": email_l,
                "phone": form.phone.data.strip(),
                "dob": form.dob.data.strftime("%Y-%m-%d"),
                "password_hash": generate_password_hash(form.password.data)
            }, salt="register-temp")

            verify_url = url_for("verify_email", token=token, _external=True)

            msg = Message(
                subject="Verify Your FouzFleet Account",
                recipients=[email_l],
                body=f"""
Hey {form.full_name.data},

Click here to activate your account:
{verify_url}

Expires in 1 hour.
"""
            )
            mail.send(msg)

            flash("✅ Verification link sent! Check your CDU email.", "success")
            return redirect(url_for("login"))

        return render_template("signup_page.html", form=form)


    @app.route("/verify/<token>")
    def verify_email(token):
        try:
            data = serializer.loads(token, salt="register-temp", max_age=3600)
        except SignatureExpired:
            flash("❌ Verification link expired.", "danger")
            return redirect(url_for("register"))
        except BadSignature:
            flash("❌ Invalid link.", "danger")
            return redirect(url_for("register"))

        # ✅ Create user now
        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            user = User(
                full_name=data["full_name"],
                email=data["email"],
                phone=data["phone"],
                dob=datetime.strptime(data["dob"], "%Y-%m-%d").date(),
                password_hash=data["password_hash"]
            )
            db.session.add(user)
            db.session.commit()

        # ✅ Auto login after verification
        login_user(user, remember=True)
        flash("✅ Account verified & created!", "success")
        return redirect(url_for("home"))


    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10/minute;50/hour")
    def login():
        form = LoginForm()

        if current_user.is_authenticated:
            return redirect(url_for("home"))

        if form.validate_on_submit():
            user = User.query.filter(
                func.lower(User.email) == form.email.data.lower().strip()
            ).first()

            if user and check_password_hash(user.password_hash, form.password.data):

                login_user(user, remember=True)
                flash(f"Welcome, {user.full_name.split()[0]}!", "success")

                next_page = request.args.get("next")
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)

                return redirect(url_for("home"))

            flash("Invalid email or password.", "danger")

        return render_template("login_page.html", form=form)


    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out.", "info")
        return redirect(url_for("login"))


    @app.route("/post", methods=["GET", "POST"])
    @login_required
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
                user_id=current_user.id
            )
            db.session.add(p)
            db.session.commit()

            flash("✅ Ride posted!", "success")
            return redirect(url_for("home"))

        return render_template("posting_page.html", form=form)


    @app.route("/delete/<int:post_id>")
    @login_required
    def delete_post(post_id):
        post = Post.query.get_or_404(post_id)

        if post.user_id != current_user.id:
            flash("You can only delete your own posts.", "danger")
            return redirect(url_for("home"))

        db.session.delete(post)
        db.session.commit()

        flash("Ride deleted.", "info")
        return redirect(url_for("home"))


    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)






