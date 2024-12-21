from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from twilio.rest import Client
import random
import requests
from threading import Timer

# Flask Application
app = Flask(__name__)
API_URL = "http://sripto.tech:8080/get_all_data"
# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Nithin1234#@localhost/avy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Twilio Config
TWILIO_ACCOUNT_SID = 'ACbf3a84933c8187f5933baec382de3945'
TWILIO_AUTH_TOKEN = '79bd543b69a4166a2d64634e21e58d57'
TWILIO_PHONE_NUMBER = '+919347632259'
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


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
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)

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
        password = bcrypt.generate_password_hash(request.form['password'])
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
        db.session.commit()

        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')
# OTP Verification Page
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')

    if request.method == 'POST':
        data = request.form
        otp_code = data.get('otp_code')

        user = User.query.filter_by(email=email).first()
        otp_entry = OTP.query.filter_by(user_id=user.user_id, otp_code=otp_code).first()

        if otp_entry and otp_entry.expiry_time >= datetime.utcnow():
            db.session.delete(otp_entry)
            db.session.commit()
            return redirect(url_for('login'))

        return render_template('verify_otp.html', error='Invalid or expired OTP')

    return render_template('verify_otp.html')

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

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', name=user.name, email=user.email)

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

#Track
@app.route('/track')
def track():
    session.pop('user_id', None)
    return render_template('track.html')



def fetch_location_data():
    try:
  
        response = requests.get(API_URL)
        if response.status_code == 200:
            data = response.json()
            process_location_data(data)
        else:
            print(f"Error fetching data: {response.status_code}")
    except Exception as e:
        print(f"Error during API fetch: {e}")

def process_location_data(data):
    for record in data:
        imei = record["IMEI"]
        latitude = record["Latitude"]
        longitude = record["Longitude"]
        timestamp = datetime.strptime(record["Timestamp"], "%Y-%m-%d %H:%M:%S")

        user = User.query.filter_by(imei=imei).first()
        if not user:
            
            new_user = User(
                imei=imei,
                name=f"User-{imei[-4:]}",  
                email=f"{imei}@placeholder.com",  
                mobile="0000000000",  
                password="password",  
                address="Placeholder Address",
                country="Placeholder Country",
                state="Placeholder State",
                city="Placeholder City",
                pincode="000000"
            )
            db.session.add(new_user)
            db.session.commit()

            create_user_table(new_user.user_id)
            
            def create_user_table(user_id):
                table_name = f"user_{user_id}_tracking"
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    imei VARCHAR(255) NOT NULL,
                    latitude FLOAT NOT NULL,
                    longitude FLOAT NOT NULL,
                    timestamp DATETIME NOT NULL
                );
                """
                db.engine.execute(create_table_query)

        table_name = f"user_{user.user_id}_tracking" if user else f"user_{new_user.user_id}_tracking"
        insert_query = f"""
        INSERT INTO {table_name} (imei, latitude, longitude, timestamp)
        VALUES ('{imei}', {latitude}, {longitude}, '{timestamp}');
        """
        db.engine.execute(insert_query)

def schedule_periodic_fetch(interval=20):  
    fetch_location_data()
    Timer(interval, schedule_periodic_fetch).start()

@app.route("/fetch-locations", methods=["GET"])
def fetch_locations():
    try:
        fetch_location_data()
        return jsonify({"status": "success", "message": "Location data fetched and stored successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

schedule_periodic_fetch()
if __name__ == '__main__':
    app.run(debug=True)
