from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
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

# Twilio Config
# TWILIO_ACCOUNT_SID = 'ACbf3a84933c8187f5933baec382de3945'
# TWILIO_AUTH_TOKEN = '79bd543b69a4166a2d64634e21e58d57'
# TWILIO_PHONE_NUMBER = '+919347632259'
# twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Global flag for thread control
fetch_thread_running = True

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
    otp_code = db.Column(db.String(6), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)

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

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Signup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        mobile = request.form['mobile']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        address = request.form['address']
        country = request.form['country']
        state = request.form['state']
        city = request.form['city']
        pincode = request.form['pincode']
        user_type = request.form['user_type']
        organization_name = request.form.get('organization_name', None)

        # Validate if email or mobile already exists
        if User.query.filter_by(email=email).first():
            flash('Email is already registered.', 'error')
            return render_template('signup.html', error="Email already registered.")
        if User.query.filter_by(mobile=mobile).first():
            flash('Mobile number is already registered.', 'error')
            return render_template('signup.html', error="Mobile number already registered.")

        # Create a new user
        new_user = User(
            name=name,
            email=email,
            mobile=mobile,
            password=password,
            address=address,
            country=country,
            state=state,
            city=city,
            pincode=pincode,
            user_type=user_type,
            organization_name=organization_name if user_type == 'organization' else None
        )
        db.session.add(new_user)
        db.session.flush()  # Flush ensures `new_user.user_id` is available

        # Generate and store OTP with timezone-aware datetime
        otp = generate_otp()
        expiry_time = datetime.now() + timedelta(minutes=10)
        new_otp = OTP(
            user_id=new_user.user_id,
            otp_code=otp,
            expiry_time=expiry_time
        )
        db.session.add(new_otp)

        try:
            db.session.commit()
            # Send OTP via email
            if send_otp_email(email, otp):
                flash('OTP sent to your email. Please verify.', 'info')
                return redirect(url_for('verify_otp', email=email))
            else:
                db.session.rollback()
                flash('Error sending OTP. Please try again.', 'error')
                return render_template('signup.html')
        except Exception as e:
            db.session.rollback()
            flash('Error during signup. Please try again.', 'error')
            return render_template('signup.html')

    return render_template('signup.html')


# OTP Verification Page
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if not email:
        flash('Email is missing. Please sign up again.', 'error')
        return redirect(url_for('signup'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please sign up again.', 'error')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        otp_record = OTP.query.filter_by(
            user_id=user.user_id,
            otp_code=otp_code
        ).first()

        if otp_record and otp_record.expiry_time > datetime.now():
            # OTP is valid
            try:
                db.session.delete(otp_record)
                db.session.commit()
                flash('Email verified successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Error during OTP verification. Please try again.', 'error')
        else:
            flash('Invalid or expired OTP.', 'error')

    return render_template('verify_otp.html', email=email)


# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            return redirect(url_for('dashboard'))

        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.get(session['user_id'])
        
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('dashboard'))
            
        # Verify current password
        if not bcrypt.check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html')
            
        # Check if new password matches confirmation
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
            
        # Check password length (you can add more validation as needed)
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            return render_template('change_password.html')
            
        try:
            # Hash the new password and update
            hashed_password = bcrypt.generate_password_hash(new_password)
            user.password = hashed_password
            db.session.commit()
            
            flash('Password successfully changed!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while changing password.', 'error')
            return render_template('change_password.html')
    
    return render_template('change_password.html')
# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(user_id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    return render_template('dashboard.html', user=user)

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

#Track
@app.route('/track')
def track():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(user_id=session['user_id']).first()
    # if not user or user.user_type != 'organization':
    #     flash('Only organizations can access tracking')
    #     return redirect(url_for('dashboard'))
    
    # Get devices and their associated users
    devices_with_users = db.session.query(Device, User).join(
        DeviceAccess, Device.device_id == DeviceAccess.device_id
    ).join(
        User, Device.owner_id == User.user_id
    ).filter(
        DeviceAccess.organization_id == user.user_id
    ).all()
    
    return render_template('track.html', devices=devices_with_users, user=user)

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
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Not logged in"})
    
    success = fetch_and_store_location_data()
    return jsonify({
        "status": "success" if success else "error",
        "message": "Locations updated" if success else "Failed to update"
    })

@app.route('/track_imei', methods=['GET', 'POST'])
def track_imei():
    
    identifier =  request.form.get('identifier')
    print("Identifier: ", identifier)
    if not identifier:
        return render_template('track.html', error="Identifier is missing.")

    # Check if identifier is a user or organization ID
    if identifier.isdigit():
        user = User.query.filter_by(user_id=identifier).first()
        organization = User.query.filter_by(user_id=identifier, user_type='organization').first()
    else:
        user = User.query.filter_by(email=identifier).first()
        organization = User.query.filter_by(email=identifier, user_type='organization').first()
    user = User.query.filter_by(user_id=identifier).first()
    organization = User.query.filter_by(user_id=identifier).first()
    print("User: ", user)
    if user:
        data = TrackingData.query.filter_by(user_id=identifier).all()
    elif organization:
        data = TrackingData.query.filter_by(organization_id=identifier).all()
    else:
        return render_template('track.html', error="No data found for the provided identifier.")

    return render_template('tracking_results.html', data=data)

@app.route('/add_device', methods=['POST'])
def add_device():
    # if 'user_id' not in session:
    #     return redirect(url_for('login'))
    
    try:
        user_id = request.form.get('user_id')
        email = request.form.get('email')  # Get the email of the logged-in user
        imei = request.form.get('imei')
        device_name = request.form.get('device_name')
        authorized_email = "nithinjambula89@gmail.com"
        print("Authorized Email: ", authorized_email)
        # Check if the email is authorized to add new devices
        if email != authorized_email:
            # If not authorized, check if the IMEI exists and grant access
            existing_device = Device.query.filter_by(imei=imei).first()
            print("Existing Device: ", existing_device)
            if existing_device:
                # Check if access is already granted
                existing_access = DeviceAccess.query.filter_by(
                    device_id=existing_device.device_id,
                    organization_id=user_id
                ).first()
                if existing_access:
                    flash('Access already granted to this user for this device.')
                    return redirect(url_for('track'))
                print("Existing Access: ", existing_access)

                # Grant access to the existing device
                device_access = DeviceAccess(
                    device_id=existing_device.device_id,
                    organization_id=user_id
                )
                print("Device Access: ", device_access)
                db.session.add(device_access)
                db.session.commit()
                flash('Access successfully granted to the device.')
                return redirect(url_for('track'))
            else:
                # If the IMEI does not exist, unauthorized email cannot add new devices
                flash('Unauthorized email. Only the authorized user can add new devices.')
                return redirect(url_for('track'))

        # Verify organization status
        # org = User.query.filter_by(user_id=session['user_id']).first()
        # if not org or org.user_type != 'organization':
        #     flash('Invalid organization access.')
        #     return redirect(url_for('track'))

        # Check if IMEI already exists
        if Device.query.filter_by(imei=imei).first():
            flash('Device with this IMEI already exists.')
            return redirect(url_for('track'))
        print("IMEI: ", imei)


        # Create new device
        new_device = Device(
            imei=imei,
            device_name=device_name,
            owner_id=user_id,  # Make sure user_id is an integer
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

        flash('Device successfully added.')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding device: {str(e)}')
    
    return redirect(url_for('track'))

# Add a new template for viewing organization users
@app.route('/view_org_users')
def view_org_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
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
    
    return render_template('org_users.html', devices=devices)


def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

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
