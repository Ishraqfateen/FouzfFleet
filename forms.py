from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, IntegerField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange, ValidationError
from flask import current_app
import re

CDU_DEFAULT_DOMAINS = ["cdu.edu.au", "students.cdu.edu.au", "student.cdu.edu.au"]

class RegisterForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField("Phone", validators=[DataRequired(), Length(min=10, max=20)])
    dob = DateField("Date of Birth", format="%Y-%m-%d", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create Account")

    def validate_email(self, field):
        if current_app.config.get("ENFORCE_CDU_EMAIL", False):
            allowed = current_app.config.get("CDU_EMAIL_DOMAINS", CDU_DEFAULT_DOMAINS)
            email_l = field.data.lower().strip()
            if not any(email_l.endswith("@"+d) for d in allowed):
                raise ValidationError("CDU email only")  

    def validate_password(self, field):
        pwd = field.data 
        if not re.search(r"[A-Za-z]", pwd) or not re.search(r"\d", pwd):
            raise ValidationError("Password must include at least one letter and one number.")

    def validate_phone(self, field):
        if not re.fullmatch(r"[0-9+\-\s()]{10}", field.data.strip()):
            raise ValidationError("Phone can contain digits, spaces, +, -, () and must be 10 chars.")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Log In")

class RidePostForm(FlaskForm):
    origin = StringField("From", validators=[DataRequired(), Length(max=40)])
    destination = StringField("To", validators=[DataRequired(), Length(max=40)])
    time_str = StringField("Time", validators=[DataRequired(), Length(max=40)])
    days = StringField("Days", validators=[DataRequired(), Length(max=70)])
    seats = IntegerField("Seats", validators=[DataRequired(), NumberRange(min=1, max=5)])
    notes = TextAreaField("Extra Notes", validators=[Length(max=400)])
    submit = SubmitField("Post Ride")

class ProfileForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField("Phone", validators=[DataRequired(), Length(min=10, max=20)])
    submit = SubmitField("Save Changes")

    def validate_email(self, field):
        if current_app.config.get("ENFORCE_CDU_EMAIL", False):
            allowed = current_app.config.get("CDU_EMAIL_DOMAINS", CDU_DEFAULT_DOMAINS)
            email_l = field.data.lower().strip()
            if not any(email_l.endswith("@"+d) for d in allowed):
                raise ValidationError("CDU email only")  

    def validate_phone(self, field):
        if not re.fullmatch(r"[0-9+\-\s()]{10}", field.data.strip()):
            raise ValidationError("Phone can contain digits, spaces, +, -, () and must be 10 chars.")
