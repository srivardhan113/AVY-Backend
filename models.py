from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    address = db.Column(db.Text, nullable=False)
    country = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    user_type = db.Column(db.Enum('individual', 'organization'), nullable=False, default='individual')
    organization_name = db.Column(db.String(255), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)

class Device(db.Model):
    __tablename__ = 'devices'
    device_id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), unique=True, nullable=False)
    device_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('Active', 'Inactive'), nullable=True, default='Active')
    renewal_date = db.Column(db.Date, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)

class DeviceAccess(db.Model):
    __tablename__ = 'device_access'
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    granted_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)

class TrackingData(db.Model):
    __tablename__ = 'tracking_data'
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    latitude = db.Column(db.Float(10, 6), nullable=False)
    longitude = db.Column(db.Float(10, 6), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)

    # Add unique constraint for imei and timestamp combination
    __table_args__ = (
        db.UniqueConstraint('imei', 'timestamp', name='unique_imei_timestamp'),
    )

class OTP(db.Model):
    __tablename__ = 'otps'
    otp_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)