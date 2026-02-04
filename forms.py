from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, TelField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import re

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])

    remember_me = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(message="First name is required"),
        Length(min=2, max=50, message="First name must be between 2 and 50 characters")
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(message="Last name is required"),
        Length(min=2, max=50, message="Last name must be between 2 and 50 characters")
    ])
    email = EmailField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    phone = TelField('Phone Number', validators=[
        DataRequired(message="Phone number is required")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])

    def validate_phone(self, field):
        # Phone number patterns for different countries
        phone_patterns = {
            'UK': r'^\+?44[0-9]{10}$',
            'Nepal': r'^\+?977[0-9]{10}$',
            'USA': r'^\+?1[0-9]{10}$',
            'India': r'^\+?91[0-9]{10}$',
            'Australia': r'^\+?61[0-9]{9}$',
            'Canada': r'^\+?1[0-9]{10}$',
            'China': r'^\+?86[0-9]{11}$',
            'Germany': r'^\+?49[0-9]{10,11}$',
            'France': r'^\+?33[0-9]{9}$',
            'Japan': r'^\+?81[0-9]{10}$',
            'Singapore': r'^\+?65[0-9]{8}$',
            'UAE': r'^\+?971[0-9]{9}$'
        }

        # Remove any spaces or hyphens from the phone number
        phone = re.sub(r'[\s-]', '', field.data)

        # Check if the phone number matches any of the patterns
        valid = False
        for country, pattern in phone_patterns.items():
            if re.match(pattern, phone):
                valid = True
                break

        if not valid:
            raise ValidationError(
                'Invalid phone number format. Please enter a valid phone number '
                'with country code (e.g., +44 for UK, +977 for Nepal, +1 for USA/Canada)'
            )

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired(), Length(min=2, max=200)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=2000)])
    submit = SubmitField('Send Message')