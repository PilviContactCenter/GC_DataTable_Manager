from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False) # Stores hash now
    role = db.Column(db.String(20), nullable=False, default='user')
    
    # Relationships
    table_permissions = db.relationship('TablePermission', backref='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class AppConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default='Default')
    client_id = db.Column(db.String(200), nullable=False)
    client_secret = db.Column(db.String(200), nullable=False)
    region = db.Column(db.String(50), nullable=False, default='eu_central_1')
    is_active = db.Column(db.Boolean, default=False)

class TablePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    table_id = db.Column(db.String(100), nullable=False)
    can_update_rows = db.Column(db.Boolean, default=False)
    can_read_rows = db.Column(db.Boolean, default=False)
    
    # Relationships
    column_permissions = db.relationship('ColumnPermission', backref='table_permission', lazy=True, cascade="all, delete-orphan")

class ColumnPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_permission_id = db.Column(db.Integer, db.ForeignKey('table_permission.id'), nullable=False)
    column_name = db.Column(db.String(100), nullable=False)
    access_level = db.Column(db.String(20), nullable=False, default='none') # none, read, write

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(200))
    details = db.Column(db.Text)
    previous_state = db.Column(db.Text) # JSON string
    new_state = db.Column(db.Text) # JSON string
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')
