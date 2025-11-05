from datetime import datetime
import os

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


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-secret"

    # db
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "fouzfleet.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"

    # models
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

    #routes
    @app.route("/")
    @login_required
    def home():
        posts = Post.query.order_by(Post.created_at.desc()).all()
        return render_template("home_page.html", posts=posts)

    @app.route("/register", methods=["GET", "POST"])
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
            )
            db.session.add(u)
            db.session.commit()

            flash("Account created successfully!", "success")
            return redirect(url_for("login"))

        return render_template("signup_page.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
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
                flash(f"Welcome back, {user.full_name.split()[0]}!", "success")
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
                author=current_user,
            )
            db.session.add(p)
            db.session.commit()
            flash("Ride posted!", "success")
            return redirect(url_for("home"))

        return render_template("posting_page.html", form=form)

    @app.route("/delete/<int:post_id>")
    @login_required
    def delete_post(post_id):
        post = Post.query.get_or_404(post_id)
        if post.author != current_user:
            flash("You can only delete your own posts.", "danger")
            return redirect(url_for("home"))

        db.session.delete(post)
        db.session.commit()

        flash("Post deleted.", "info")
        return redirect(url_for("home"))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        form = ProfileForm(obj=current_user)

        if form.validate_on_submit():
            current_user.email = form.email.data.lower().strip()
            current_user.phone = form.phone.data.strip()
            db.session.commit()

            flash("Profile updated.", "success")
            return redirect(url_for("profile"))

        return render_template("profile_page.html", form=form)

    
    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)


