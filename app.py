from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify, send_file, make_response
import mysql.connector
import os, json, random
import smtplib
from email.mime.text import MIMEText
from fpdf import FPDF
from datetime import datetime
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = 'Shreesha1@'

# Email credentials
EMAIL_USER = 'aiml8thsem@gmail.com'
EMAIL_PASS = 'rjxs iukr qcmd pgzg'

# Ensure uploads directory exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Allowed file extensions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="vstand4u_website"
    )

# Email OTP function
def send_otp_email(recipient_email, otp):
    try:
        msg = MIMEText(f'Your OTP for registration is: {otp}')
        msg['Subject'] = 'OTP Verification'
        msg['From'] = EMAIL_USER
        msg['To'] = recipient_email

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, recipient_email, msg.as_string())
        return True
    except Exception as e:
        print(f'Failed to send OTP email: {e}')
        return False

# OTP generation
def generate_otp():
    return random.randint(100000, 999999)

# Update user progress
def update_user_progress(user_id, video_id, completed, watch_duration, last_position):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO user_video_progress 
            (user_id, video_id, completed, last_watched_at, watch_duration, last_position)
            VALUES (%s, %s, %s, NOW(), %s, %s)
            ON DUPLICATE KEY UPDATE
            completed = VALUES(completed),
            last_watched_at = NOW(),
            watch_duration = VALUES(watch_duration),
            last_position = VALUES(last_position)
        ''', (user_id, video_id, completed, watch_duration, last_position))
        conn.commit()
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

# Parse duration helper
def parse_duration(duration_str):
    parts = duration_str.split(':')
    if len(parts) == 3:
        hours, minutes, seconds = parts
        return int(hours) * 3600 + int(minutes) * 60 + int(seconds)
    elif len(parts) == 2:
        minutes, seconds = parts
        return int(minutes) * 60 + int(seconds)
    else:
        return int(parts[0])

# Load questions
def load_questions():
    with open('data/questions.json', 'r') as file:
        questions = json.load(file)
        random.shuffle(questions)  # Shuffle the questions
        return questions

# Home route
@app.route('/')
def index():
    return render_template('signup.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        mobile_number = request.form['mobile_number']
        college_name = request.form['college_name']
        qualification = request.form['qualification']
        password = request.form['password']
        gender = request.form['gender']
        
        profile_pic = request.files.get('profile_pic')
        profile_pic_path = 'static/images/profile_pictures/default_profile.png'

        if profile_pic and allowed_file(profile_pic.filename):
            profile_pic_filename = f"{email}.jpg"
            profile_pic_path = os.path.join('static/images/profile_pictures', profile_pic_filename)
            profile_pic.save(profile_pic_path)

        otp = generate_otp()
        if send_otp_email(email, otp):
            session['otp'] = otp
            session['signup_data'] = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'mobile_number': mobile_number,
                'college_name': college_name,
                'qualification': qualification,
                'password': password,
                'gender': gender,
                'profile_pic_path': profile_pic_path
            }
            flash('OTP sent to your email. Please enter the OTP to complete registration.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send OTP. Please try again.', 'danger')

    return render_template('signup.html')

# Verify OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session and otp == str(session['otp']):
            signup_data = session.pop('signup_data')
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (first_name, last_name, email, mobile_number, college_name, qualification, password_hash, gender, profile_picture)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    signup_data['first_name'], signup_data['last_name'], signup_data['email'],
                    signup_data['mobile_number'], signup_data['college_name'], signup_data['qualification'],
                    signup_data['password'], signup_data['gender'], signup_data['profile_pic_path']
                ))
                conn.commit()
                flash('You have successfully signed up!', 'success')
                return redirect(url_for('login'))
            except mysql.connector.IntegrityError:
                flash('Email or mobile number already exists.', 'danger')
            finally:
                cursor.close()
                conn.close()
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')

# Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user:
            otp = generate_otp()
            if send_otp_email(email, otp):
                session['otp'] = otp
                session['email'] = email
                flash('OTP sent to your email. Please enter the OTP to reset your password.', 'info')
                return redirect(url_for('reset_password'))
            else:
                flash('Failed to send OTP. Please try again.', 'danger')
        else:
            flash('Email not registered. Please sign up.', 'danger')

    return render_template('forgot_password.html')

# Reset password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if 'otp' in session and otp == str(session['otp']):
            if new_password == confirm_password:
                email = session['email']
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = %s WHERE email = %s', (new_password, email))
                conn.commit()
                cursor.close()
                conn.close()
                session.pop('otp', None)
                session.pop('email', None)
                flash('Password updated successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Passwords do not match. Please try again.', 'danger')
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('reset_password.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and user['password_hash'] == password:
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# Home route
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()

    cursor.execute('SELECT COUNT(*) AS total_videos FROM videos')
    total_videos = cursor.fetchone()['total_videos']

    cursor.execute('''
        SELECT COUNT(DISTINCT video_id) AS completed_videos 
        FROM user_video_progress 
        WHERE user_id = %s AND completed = TRUE
    ''', (user_id,))
    completed_videos = cursor.fetchone()['completed_videos']

    progress = (completed_videos / total_videos) * 100 if total_videos > 0 else 0
    conn.close()

    return render_template('home.html', user=user, progress=progress, completed_videos=completed_videos)

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
