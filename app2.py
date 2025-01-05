# made for the nextjs front end

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
from twilio.rest import Client
import random
import requests
from threading import Timer
import threading
from pytz import timezone
import time
import atexit
from flask_mail import Mail, Message
from sqlalchemy import func
from flask_cors import CORS
from functools import wraps

# Flask Application
app = Flask(__name__)
# Enable CORS
CORS(app)

API_URL = "http://sripto.tech:8080/get_all_data"
# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Nithin1234#@localhost/avy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:sql123@34.56.147.135:3306/avy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nithinjambula89@gmail.com'  # Your Gmail
app.config['MAIL_PASSWORD'] = 'njmr izng bzrm dkbo'  # Your App Password
mail = Mail(app)

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# Twilio Config
TWILIO_ACCOUNT_SID = 'ACbf3a84933c8187f5933baec382de3945'
TWILIO_AUTH_TOKEN = '79bd543b69a4166a2d64634e21e58d57'
TWILIO_PHONE_NUMBER = '+919347632259'
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Global flag for thread control
fetch_thread_running = True
app.config.update({
    'JWT_SECRET_KEY': 'your-jwt-secret-key',  # Change this to a secure secret key
    'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
    'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30)
})

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


class OTP(db.Model):
    __tablename__ = 'otps'
    otp_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    otp_type = db.Column(db.Enum('email', 'mobile'), nullable=False, default='email')
    otp_code = db.Column(db.String(6), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

class TrackingData(db.Model):
    __tablename__ = 'tracking_data'
    __table_args__ = (
        db.UniqueConstraint('imei', 'timestamp', name='uix_imei_timestamp'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    organization_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))

class Device(db.Model):
    __tablename__ = 'devices'
    device_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    imei = db.Column(db.String(50), unique=True, nullable=False)
    device_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('Active', 'Inactive'), default='Active')
    renewal_date = db.Column(db.Date, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

class DeviceAccess(db.Model):
    __tablename__ = 'device_access'
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    granted_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

# Routes
def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(4)])

def generate_and_send_otp(email, mobile):
    otp_code = generate_otp()
    expiry_time = datetime.now() + timedelta(minutes=10)
    
    otp_record = OTP(user_id=None, otp_code=otp_code, expiry_time=expiry_time)
    db.session.add(otp_record)
    db.session.commit()
    
    # Send OTP via email and SMS
    try:
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP code is {otp_code}'
        mail.send(msg)
        
        message = twilio_client.messages.create(
            body=f'Your OTP code is {otp_code}',
            from_=TWILIO_PHONE_NUMBER,
            to=mobile
        )
        return True, otp_code
    except Exception as e:
        db.session.rollback()
        return False, str(e)

def send_otp_email(email, otp):
    try:
        msg = Message(
            'Your OTP for Signup Verification',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'Your OTP for signup verification is: {otp}\nThis OTP will expire in 10 minutes.'
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        return False

# Add token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            # Remove 'Bearer ' from token
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
            return f(current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Signup Page
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid data"}), 400

    try:
        email = data.get('email')
        mobile = data.get('mobile')

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400

        if User.query.filter_by(mobile=mobile).first():
            return jsonify({"error": "Mobile already registered"}), 400

        password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
        new_user = User(
            name=data.get('name'),
            email=email,
            mobile=mobile,
            password=password,
            address=data.get('address'),
            country=data.get('country'),
            state=data.get('state'),
            city=data.get('city'),
            pincode=data.get('pincode'),
            user_type=data.get('user_type'),
            organization_name=data.get('organization_name', None)
        )
        db.session.add(new_user)
        db.session.flush()

        # Generate email OTP
        email_otp = generate_otp()
        email_expiry = datetime.now() + timedelta(minutes=10)
        email_otp_record = OTP(
            user_id=new_user.user_id,
            otp_type='email',
            otp_code=email_otp,
            expiry_time=email_expiry
        )

        # Generate mobile OTP
        mobile_otp = generate_otp()
        mobile_expiry = datetime.now() + timedelta(minutes=10)
        mobile_otp_record = OTP(
            user_id=new_user.user_id,
            otp_type='mobile',
            otp_code=mobile_otp,
            expiry_time=mobile_expiry
        )

        db.session.add(email_otp_record)
        db.session.add(mobile_otp_record)
        db.session.commit()

        # Send OTPs
        send_otp_email(email, email_otp)
        send_otp_sms(mobile, mobile_otp)
        
        def send_otp_sms(mobile, otp):
            try:
                message = twilio_client.messages.create(
                    body=f'Your OTP code is {otp}',
                    from_=TWILIO_PHONE_NUMBER,
                    to=mobile
                )
                return True
            except Exception as e:
                app.logger.error(f"Error sending SMS: {str(e)}")
                return False

        return jsonify({
            "message": "Signup successful. OTPs sent",
            "email": email,
            "user_id": new_user.user_id
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid data"}), 400

    email = data.get('email')
    email_otp = data.get('email_otp')
    mobile_otp = data.get('mobile_otp')
    
    if not email or not email_otp or not mobile_otp:
        return jsonify({"error": "Email and both OTPs required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Verify email OTP
    email_otp_record = OTP.query.filter_by(
        user_id=user.user_id,
        otp_code=email_otp,
        is_used=False
    ).first()

    # Verify mobile OTP
    mobile_otp_record = OTP.query.filter_by(
        user_id=user.user_id,
        otp_code=mobile_otp,
        is_used=False
    ).first()

    # Check if either OTP is invalid or expired
    current_time = datetime.now()
    if not email_otp_record or not mobile_otp_record:
        return jsonify({"error": "Invalid OTP codes"}), 400
    
    if (email_otp_record.expiry_time < current_time or 
        mobile_otp_record.expiry_time < current_time):
        return jsonify({"error": "OTP has expired"}), 400

    try:
        # Mark both OTPs as used
        email_otp_record.is_used = True
        mobile_otp_record.is_used = True
        
        db.session.commit()
        
        # Generate tokens after successful verification
        # access_token = create_access_token(identity=user.user_id)
        # refresh_token = create_refresh_token(identity=user.user_id)
        
        return jsonify({
            "message": "Verification successful",
            # "access_token": access_token,
            # "refresh_token": refresh_token,
            "user": {
                "id": user.user_id,
                "email": user.email,
                "name": user.name,
                "user_type": user.user_type
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
        
@app.route('/verify-token', methods=['POST'])
def verify_token():
    try:
        # Get token from Authorization header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        # Remove 'Bearer ' prefix
        token = token.split(' ')[1]
        
        # Verify token and get user data
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = data.get('sub')  # JWT standard claim for subject/user
        
        # Get user details
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'status': 'success',
            'user': {
                'user_id': user.user_id,
                'email': user.email,
                'name': user.name,
                'user_type': user.user_type,
                'organization_name': user.organization_name if user.user_type == 'organization' else None
            },
            'token_valid': True
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired', 'token_valid': False}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token', 'token_valid': False}), 401
    except Exception as e:
        return jsonify({'error': str(e), 'token_valid': False}), 500
    
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': access_token}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid data"}), 400

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid password"}), 401

    # Check if both OTPs are verified
    email_verified = OTP.query.filter_by(
        user_id=user.user_id, 
        otp_type='email',
        is_used=True
    ).first()
    mobile_verified = OTP.query.filter_by(
        user_id=user.user_id,
        otp_type='mobile',
        is_used=True
    ).first()

    if not (email_verified):
        return jsonify({"error": "Please verify both email and mobile"}), 403

    access_token = create_access_token(identity=user.user_id)
    refresh_token = create_refresh_token(identity=user.user_id)

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.user_id,
            'email': user.email,
            'name': user.name
        }
    }), 200

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    if request.method == 'GET':
        return render_template('change_password.html')

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid or missing JSON data"}), 400

    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.check_password_hash(user.password, current_password):
        return jsonify({"error": "Current password is incorrect"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters long"}), 400

    try:
        hashed_password = bcrypt.generate_password_hash(new_password)
        user.password = hashed_password
        db.session.commit()
        return jsonify({"message": "Password successfully changed"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while changing password"}), 500

# Dashboard
@app.route('/dashboard')
@token_required
def dashboard(current_user):
    try:
        user_data = {
            "user_id": current_user.user_id,
            "email": current_user.email,
            "name": current_user.name,
            "mobile": current_user.mobile,
            "address": current_user.address,
            "country": current_user.country,
            "state": current_user.state,
            "city": current_user.city,
            "pincode": current_user.pincode,
            "user_type": current_user.user_type,
            "organization_name": current_user.organization_name if current_user.user_type == 'organization' else None,
            "is_verified": current_user.is_verified
        }
        
        # Get organization details if user belongs to one
        if current_user.organization_id:
            org = User.query.filter_by(user_id=current_user.organization_id).first()
            user_data["organization_details"] = {
                "id": org.user_id,
                "name": org.organization_name
            } if org else None

        return jsonify({
            "status": "success",
            "user": user_data
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# Logout
@app.route('/logout')
def logout():
    """Logout the user"""
    session.pop('user_id', None)
    return jsonify({"message": "Logged out successfully"}), 200


#Track
@app.route('/track')
@token_required
def track(current_user):
    """Get tracking data for logged-in user"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    user = User.query.filter_by(user_id=session['user_id']).first()
    if not user:
        session.clear()
        return jsonify({"error": "User  not found"}), 404
        
    # Get devices and their associated users
    devices_with_users = db.session.query(Device, User).join(
        DeviceAccess, Device.device_id == DeviceAccess.device_id
    ).join(
        User, Device.owner_id == User.user_id
    ).filter(
        DeviceAccess.organization_id == user.user_id
    ).all()
    
    return jsonify({
        "devices": [{
            "device_id": device.device_id,
            "device_name": device.device_name,
            "user_id": user.user_id,
            "user_name": user.name
        } for device, user in devices_with_users]
    }), 200

def fetch_and_store_location_data():
    """Fetch location data and store it in the database"""
    API_URL = "http://sripto.tech:8080/get_all_data"
    try:
        with app.app_context():
            response = requests.get(API_URL)
            data = response.json()
            
            for location in data:
                try:
                    imei = location['IMEI']
                    timestamp = datetime.strptime(location['Timestamp'], '%Y-%m-%d %H:%M:%S')
                    
                    # Get device and user info
                    device = Device.query.filter_by(imei=imei).first()
                    if not device:
                        continue
                    
                    # Only check for exact timestamp duplicate
                    existing = TrackingData.query.filter_by(timestamp=timestamp).first()
                    
                    if not existing:
                        # Create new record if timestamp doesn't exist
                        tracking_data = TrackingData(
                            imei=imei,
                            latitude=location['Latitude'],
                            longitude=location['Longitude'],
                            timestamp=timestamp,
                            user_id=device.owner_id,
                            organization_id=device.owner_id
                        )
                        db.session.add(tracking_data)
                        try:
                            db.session.commit()
                        except Exception as e:
                            db.session.rollback()
                            continue
                            
                except Exception as e:
                    db.session.rollback()
                    continue
            
            return True
    except Exception as e:
        app.logger.error(f"Error fetching location data: {str(e)}")
        return False

def background_fetch():
    while fetch_thread_running:
        fetch_and_store_location_data()
        time.sleep(20)

@app.route('/fetch-locations', methods=['GET'])
def fetch_locations():
    """Fetch location data for logged-in user"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    success = fetch_and_store_location_data()
    return jsonify({
        "status": "success" if success else "error",
        "message": "Locations updated" if success else "Failed to update"
    }), 200

@app.route('/track_imei', methods=['GET', 'POST'])
def track_imei():
    """Get tracking data for a specific IMEI"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid or missing JSON data"}), 400
    
    identifier = data.get('identifier')
    if not identifier:
        return jsonify({"error": "Identifier is missing"}), 400
    
    # Check if identifier is a user or organization ID
    if identifier.isdigit():
        user = User.query.filter_by(user_id=identifier).first()
        organization = User.query.filter_by(user_id=identifier, user_type='organization').first()
    else:
        user = User.query.filter_by(email=identifier).first()
        organization = User.query.filter_by(email=identifier, user_type='organization').first()
    
    if user:
        data = TrackingData.query.filter_by(user_id=identifier).all()
    elif organization:
        data = TrackingData.query.filter_by(organization_id=identifier).all()
    else:
        return jsonify({"error": "No data found for the provided identifier"}), 404
    
    return jsonify({
        "data": [{
            "imei": tracking_data.imei,
            "latitude": tracking_data.latitude,
            "longitude": tracking_data.longitude,
            "timestamp": tracking_data.timestamp
        } for tracking_data in data]
    }), 200

@app.route('/add_device', methods=['POST'])
@token_required
def add_device(current_user):
    """Add a new device for logged-in user"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid or missing JSON data"}), 400
    
    try:
        user_id = data.get('user_id')
        email = data.get('email')
        imei = data.get('imei')
        device_name = data.get('device_name')
        authorized_email = "nithinjambula89@gmail.com"
        
        # Check if the email is authorized to add new devices
        if email != authorized_email:
            # If not authorized, check if the IMEI exists and grant access
            existing_device = Device.query.filter_by(imei=imei).first()
            if existing_device:
                # Check if access is already granted
                existing_access = DeviceAccess.query.filter_by(
                    device_id=existing_device.device_id,
                    organization_id=user_id
                ).first()
                if existing_access:
                    return jsonify({"error": "Access already granted to this user for this device"}), 400
                
                # Grant access to the existing device
                device_access = DeviceAccess(
                    device_id=existing_device.device_id,
                    organization_id=user_id
                )
                db.session.add(device_access)
                db.session.commit()
                return jsonify({"message": "Access successfully granted to the device"}), 200
            else:
                # If the IMEI does not exist, unauthorized email cannot add new devices
                return jsonify({"error": "Unauthorized email. Only the authorized user can add new devices"}), 400
        
        # Verify organization status
        # org = User.query.filter_by(user_id=session['user_id']).first()
        # if not org or org.user_type != 'organization':
        #     return jsonify({"error": "Invalid organization access"}), 400
        
        # Check if IMEI already exists
        if Device.query.filter_by(imei=imei).first():
            return jsonify({"error": "Device with this IMEI already exists"}), 400
        
        # Create new device
        new_device = Device(
            imei=imei,
            device_name=device_name,
            owner_id=user_id,
            status='Active'
        )
        db.session.add(new_device)
        db.session.flush()
        
        # Create device access for organization
        device_access_org = DeviceAccess(
            device_id=new_device.device_id,
            organization_id=session['user_id']
        )
        db.session.add(device_access_org)
        
        db.session.commit()
        
        return jsonify({"message": "Device successfully added"}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error adding device: {str(e)}"}), 500

# Add a new template for viewing organization users
@app.route('/view_org_users')
@token_required
def view_org_users(current_user):
    """View all users in the organization"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    org_id = session['user_id']
    
    # Get all devices accessible to the organization with their latest tracking data
    devices = db.session.query(
        Device,
        User,
        db.func.max(TrackingData.timestamp).label('last_seen')
    ).join(
        DeviceAccess, Device.device_id == DeviceAccess.device_id
    ).join(
        User, Device.owner_id == User.user_id
    ).outerjoin(
        TrackingData, Device.imei == TrackingData.imei
    ).filter(
        DeviceAccess.organization_id == org_id
    ).group_by(
        Device.device_id,
        User.user_id
    ).all()
    
    return jsonify({
        "devices": [{
 "device_id": device.device_id,
            "device_name": device.device_name,
            "user_id": user.user_id,
            "user_name": user.name,
            "last_seen": last_seen
        } for device, user, last_seen in devices]
    }), 200
@app.route('/get_device/<device_id>', methods=['GET'])
def get_device(device_id):
    """Get details of a specific device"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    return jsonify({
        "device_id": device.device_id,
        "device_name": device.device_name,
        "imei": device.imei,
        "status": device.status
    }), 200
@app.route('/delete_device/<device_id>', methods=['DELETE'])
def delete_device(device_id):
    """Delete a device"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        device = Device.query.filter_by(device_id=device_id).first()
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        db.session.delete(device)
        db.session.commit()
        
        return jsonify({"message": "Device deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error deleting device: {str(e)}"}), 500


@app.route('/get_all_devices', methods=['GET'])
def get_all_devices():
    """Get all devices for the logged-in user"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    devices = Device.query.filter_by(owner_id=session['user_id']).all()
    
    return jsonify({
        "devices": [{
            "device_id": device.device_id,
            "device_name": device.device_name,
            "imei": device.imei,
            "status": device.status
        } for device in devices]
    }), 200

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(4)])

def send_otp_email(email, otp):
    try:
        msg = Message(
            'Your OTP for Signup Verification',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'Your OTP for signup verification is: {otp}\nThis OTP will expire in 10 minutes.'
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        return False

@app.route('/get_org_locations')
def get_org_locations():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    org_id = session['user_id']
    timestamp = request.args.get('timestamp')
    
    try:
        # If no timestamp provided, use current time
        if not timestamp:
            target_time = datetime.now(timezone.utc)
        else:
            target_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M')
            
        # Subquery to get the latest timestamp for each IMEI
        latest_timestamps = db.session.query(
            TrackingData.imei,
            func.max(TrackingData.timestamp).label('max_timestamp')
        ).group_by(TrackingData.imei).subquery()
        
        # Main query using the subquery
        locations = db.session.query(
            TrackingData,
            Device.device_name,
            User.name.label('user_name')
        ).join(
            latest_timestamps,
            db.and_(
                TrackingData.imei == latest_timestamps.c.imei,
                TrackingData.timestamp == latest_timestamps.c.max_timestamp
            )
        ).join(
            Device,
            TrackingData.imei == Device.imei
        ).join(
            DeviceAccess,
            Device.device_id == DeviceAccess.device_id
        ).join(
            User,
            Device.owner_id == User.user_id
        ).filter(
            DeviceAccess.organization_id == org_id,
            TrackingData.timestamp <= target_time
        ).all()
        
        return jsonify([{
            'latitude': float(loc.TrackingData.latitude),
            'longitude': float(loc.TrackingData.longitude),
            'imei': loc.TrackingData.imei,
            'device_name': loc.device_name,
            'user_name': loc.user_name,
            'timestamp': loc.TrackingData.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for loc in locations])
        
    except Exception as e:
        app.logger.error(f"Error in get_org_locations: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/org_map')
def org_map():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.user_type != 'organization':
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    return render_template('maps.html')

@app.route('/map/<imei>')
def show_map(imei):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('maps.html', imei=imei)

@app.route('/get_device_location/<imei>')
def get_device_location(imei):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    # Get the latest location for the device
    latest_location = db.session.query(
        TrackingData,
        Device.device_name,
        User.name.label('user_name')
    ).join(
        Device, TrackingData.imei == Device.imei
    ).join(
        User, Device.owner_id == User.user_id
    ).filter(
        TrackingData.imei == imei
    ).order_by(
        TrackingData.timestamp.desc()
    ).first()
    
    if latest_location:
        return jsonify({
            'latitude': float(latest_location.TrackingData.latitude),
            'longitude': float(latest_location.TrackingData.longitude),
            'device_name': latest_location.device_name,
            'user_name': latest_location.user_name,
            'timestamp': latest_location.TrackingData.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'error': 'Location not found'}), 404

if __name__ == '__main__':
    # Start background fetch thread
    fetch_thread = threading.Thread(target=background_fetch)
    fetch_thread.daemon = True
    fetch_thread.start()
    
    # Register cleanup
    atexit.register(lambda: setattr(app, 'fetch_thread_running', False))
    
    app.run(debug=True)
