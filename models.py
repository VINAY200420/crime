from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import random

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)  # New field for memorable answer
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    reports = db.relationship('CrimeReport', backref='reporter', lazy=True)

    def __init__(self, username, email, security_answer, **kwargs):
        super().__init__(**kwargs)
        self.username = username
        self.email = email
        self.security_answer = security_answer

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CrimeReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, investigating, resolved
    reporter_location = db.Column(db.String(200))
    evidence_file = db.Column(db.String(200))  # Path to uploaded evidence file 

    def __init__(self, type, description, latitude, longitude, location, **kwargs):
        super().__init__(**kwargs)
        self.type = type
        self.description = description
        self.latitude = latitude
        self.longitude = longitude
        self.location = location 