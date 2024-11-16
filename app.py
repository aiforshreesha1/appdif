from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify, send_file,make_response
import sqlite3
import os , json
import smtplib
from email.mime.text import MIMEText
from fpdf import FPDF
from datetime import datetime
import random
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = 'Vstand4u1@'

# Email credentials
EMAIL_USER = 'aiml8thsem@gmail.com'
EMAIL_PASS = 'rjxs iukr qcmd pgzg'

# Ensure uploads directory exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

def generate_otp():
    return random.randint(100000, 999999)

# Database connection function
def get_db_connection():
    conn = sqlite3.connect('database/vstand4u.db') 
    conn.row_factory = sqlite3.Row
    return conn

def update_user_progress(user_id, video_id, completed, watch_duration, last_position):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT OR REPLACE INTO user_video_progress 
            (user_id, video_id, completed, last_watched_at, watch_duration, last_position)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
        ''', (user_id, video_id, completed, watch_duration, last_position))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
    finally:
        conn.close()

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
    
def load_questions():
    with open('data/questions.json', 'r') as file:
        questions = json.load(file)
        random.shuffle(questions)  # Shuffle the questions
        return questions
    
# Home page route
@app.route('/')
def index():
    return render_template('signup.html')

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
        
        # Handle profile picture upload
        profile_pic = request.files.get('profile_pic')
        profile_pic_path = 'static/images/profile_pictures/default_profile.png'  # Default path

        if profile_pic and allowed_file(profile_pic.filename):
            profile_pic_filename = f"{email}.jpg"
            profile_pic_path = os.path.join('static/images/profile_pictures', profile_pic_filename)
            profile_pic.save(profile_pic_path)

        # Generate OTP and send email
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

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session and otp == str(session['otp']):
            signup_data = session.pop('signup_data')
            conn = get_db_connection()
            try:
                conn.execute('INSERT INTO users (first_name, last_name, email, mobile_number, college_name, qualification, password_hash, gender, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                             (signup_data['first_name'], signup_data['last_name'], signup_data['email'], signup_data['mobile_number'], signup_data['college_name'], signup_data['qualification'], signup_data['password'], signup_data['gender'], signup_data['profile_pic_path']))
                conn.commit()
                flash('You have successfully signed up!', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email or mobile number already exists.', 'danger')
            finally:
                conn.close()
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
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
                conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (new_password, email))
                conn.commit()
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and user['password_hash'] == password:
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')  # Render login.html template

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()

    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    total_videos = conn.execute('SELECT COUNT(*) as total_videos FROM videos').fetchone()['total_videos']
    completed_videos = conn.execute('SELECT COUNT(DISTINCT video_id) as completed_videos FROM user_video_progress WHERE user_id = ? AND completed = 1', (user_id,)).fetchone()['completed_videos']
    last_watched = conn.execute('SELECT last_watched_at, SUM(watch_duration) as total_watch_duration FROM user_video_progress WHERE user_id = ? ORDER BY last_watched_at DESC LIMIT 1', (user_id,)).fetchone()
    certificate = conn.execute('SELECT * FROM certificates WHERE user_id = ?', (user_id,)).fetchone()
    last_video = conn.execute('''
        SELECT v.*, uvp.last_position 
        FROM videos v 
        LEFT JOIN user_video_progress uvp ON v.id = uvp.video_id AND uvp.user_id = ?
        ORDER BY uvp.last_watched_at DESC LIMIT 1
    ''', (user_id,)).fetchone()
    conn.close()

    progress = completed_videos / total_videos * 100 if total_videos > 0 else 0
    status = 'Completed' if certificate else 'Incomplete'

    return render_template('home.html', 
                           user=user, 
                           user_name=session.get('user_name'), 
                           progress=progress, 
                           completed_videos=completed_videos, 
                           total_videos=total_videos,
                           last_watched=last_watched,
                           status=status,
                           last_video=last_video)

# @app.route('/videos')
# def video_list():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#     user_id = session['user_id']
#     conn = get_db_connection()
#     user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
#     videos = conn.execute('SELECT * FROM videos ORDER BY order_number').fetchall()
#     conn.close()
#     return render_template('video/list.html', user=user, user_name=session.get('user_name'), videos=videos)
@app.route('/videos')
def video_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    videos = conn.execute('''
        SELECT v.*, 
               COALESCE(uvp.completed, 0) as completed, 
               COALESCE(uvp.watch_duration, 0) as watch_duration,
               COALESCE(uvp.last_position, 0) as last_position
        FROM videos v
        LEFT JOIN (
            SELECT video_id, completed, watch_duration, last_position,
                   ROW_NUMBER() OVER (PARTITION BY video_id ORDER BY last_watched_at DESC) as rn
            FROM user_video_progress
            WHERE user_id = ?
        ) uvp ON v.id = uvp.video_id AND uvp.rn = 1
        ORDER BY v.order_number
    ''', (user_id,)).fetchall()
    
    all_videos_completed = all(video['completed'] for video in videos)
    
    # Get the latest test result
    test_result = conn.execute('SELECT * FROM user_test_results WHERE user_id = ? ORDER BY completed_at DESC LIMIT 1', (user_id,)).fetchone()
    test_taken = test_result is not None
    test_score = test_result['score'] if test_result else None
    test_passed = test_result['passed'] if test_result else False
    
    conn.close()
    return render_template('video/list.html', user=user, user_name=session.get('user_name'), 
                           videos=videos, all_videos_completed=all_videos_completed, 
                           test_taken=test_taken, test_score=test_score, test_passed=test_passed)

# @app.route('/videos/<int:video_id>')
# def video_player(video_id):
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#     conn = get_db_connection()
#     video = conn.execute('SELECT * FROM videos WHERE id = ?', (video_id,)).fetchone()
#     progress = conn.execute('SELECT * FROM user_video_progress WHERE user_id = ? AND video_id = ?', (session['user_id'], video_id)).fetchone()
#     conn.close()
#     return render_template('video/player.html', video=video, progress=progress)
@app.route('/videos/<int:video_id>')
def video_player(video_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    # Get the current video
    video = conn.execute('SELECT * FROM videos WHERE id = ?', (video_id,)).fetchone()
    
    if not video:
        conn.close()
        flash('Video not found.', 'error')
        return redirect(url_for('video_list'))
    
    # Check if there's a previous video
    previous_video = conn.execute('''
        SELECT * FROM videos 
        WHERE order_number = (SELECT order_number FROM videos WHERE id = ?) - 1
    ''', (video_id,)).fetchone()
    
    if previous_video:
        # Check if the previous video has been completed
        previous_progress = conn.execute('''
            SELECT completed FROM user_video_progress 
            WHERE user_id = ? AND video_id = ?
            ORDER BY last_watched_at DESC
            LIMIT 1
        ''', (user_id, previous_video['id'])).fetchone()
        
        if not previous_progress or not previous_progress['completed']:
            conn.close()
            flash('Please watch the previous video first.', 'warning')
            return redirect(url_for('video_list'))
    
    # Get progress for the current video
    progress = conn.execute('''
        SELECT * FROM user_video_progress 
        WHERE user_id = ? AND video_id = ?
        ORDER BY last_watched_at DESC
        LIMIT 1
    ''', (user_id, video_id)).fetchone()
    
    conn.close()
    
    return render_template('video/player.html', video=video, progress=progress, user=user, user_name=session.get('user_name'))
    
@app.route('/update_progress', methods=['POST'])
def update_progress():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    try:
        data = request.json
        user_id = session['user_id']
        video_id = data['video_id']
        watch_duration = data['watch_duration']
        last_position = data['last_position']
        completed = data['completed']

        conn = get_db_connection()
        
        # Get video duration
        video = conn.execute('SELECT duration FROM videos WHERE id = ?', (video_id,)).fetchone()
        video_duration = parse_duration(video['duration'])  # You'll need to implement this function
        
        # Check if the video is completed
        if watch_duration >= video_duration * 0.9:  # Consider video completed if 90% watched
            completed = True
        
        update_user_progress(user_id, video_id, completed, watch_duration, last_position)
        
        conn.close()
        
        return jsonify({"success": True})
    except KeyError as e:
        print(f"KeyError: {e}")
        return jsonify({"error": "Missing required data"}), 400
    except Exception as e:
        print(f"Error updating progress: {e}")
        return jsonify({"error": "An error occurred while updating progress"}), 500

@app.route('/test')
def test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    # Check if all videos are completed
    videos = conn.execute('SELECT completed FROM user_video_progress WHERE user_id = ? AND completed = 1', (user_id,)).fetchall()
    total_videos = conn.execute('SELECT COUNT(*) FROM videos').fetchone()[0]
    all_videos_completed = len(videos) >= total_videos

    if not all_videos_completed:
        flash('Please complete all videos before taking the test....', 'warning')
        return redirect(url_for('video_list'))
    
    # Load and shuffle questions for the test
    questions = load_questions()
    session['shuffled_questions'] = questions  # Store the shuffled questions in the session
    conn.close()
    return render_template('video/test.html', questions=questions, user=user)

@app.route('/upload_recording', methods=['POST'])
def upload_recording():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user_id = session['user_id']
    if 'video' not in request.files:
        return jsonify({"error": "No video file uploaded"}), 400

    # Save video with user identifier as filename
    video_file = request.files['video']
    user_email = session.get('email', user_id)  # Use email or user ID as filename if email is not available
    video_filename = f"{user_email}_recording.webm"
    video_path = os.path.join('uploads', video_filename)

    try:
        video_file.save(video_path)
        return jsonify({"success": True, "message": "Recording uploaded successfully"}), 200
    except Exception as e:
        print(f"Error saving recording: {e}")
        return jsonify({"error": "Failed to save recording"}), 500

@app.route('/submit_test', methods=['POST'])
def submit_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    answers = request.form
    questions = session.get('shuffled_questions')  # Retrieve the shuffled questions from the session
    
    score = 0
    total_questions = len(questions)
    
    for question in questions:
        if str(question['id']) in answers and answers[str(question['id'])] == question['correct_answer']:
            score += 1
    
    percentage = (score / total_questions) * 100
    passed = percentage >= 90  # 90% to pass
    
    conn = get_db_connection()
    # Insert a new test result 
    conn.execute('INSERT INTO user_test_results (user_id, score, passed, completed_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', 
                 (user_id, score, passed))
    conn.commit()
    conn.close()
    
    flash(f'Test submitted. Your score: {score}/{total_questions} ({percentage:.2f}%)', 'success')
    if passed:
        flash('Congratulations! You passed the test.', 'success')
    else:
        flash('Unfortunately, you did not pass the test. Please review the material and try again.', 'warning')
    
    return redirect(url_for('video_list'))


@app.route('/about')
def about():
    return render_template('about.html')

# @app.route('/help', methods=['GET', 'POST'])
# def help():
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         phone_number = request.form['phone_number']
#         subject = request.form['subject']
#         content = request.form['content']
#         flash('Your message has been sent.', 'success')
#         return redirect(url_for('help'))
#     return render_template('help.html')

@app.route('/help', methods=['GET', 'POST'])
def help():
    if request.method == 'POST':
        # Get the data from the form
        data = request.get_json()
        name = data['name']
        email = data['email']
        phone_number = data['phone']
        subject = data['subject']
        content = data['content']

        # Save the help request in the database
        conn = get_db_connection()
        conn.execute('INSERT INTO help_requests (name, email, phone_number, subject, content) VALUES (?, ?, ?, ?, ?)', 
                     (name, email, phone_number, subject, content))
        conn.commit()
        conn.close()

        # Send an email notification
        try:
            # Setup email
            msg = MIMEText(f"Help request from {name} ({email}, {phone_number}):\n\n{content}")
            msg['Subject'] = subject
            msg['From'] = EMAIL_USER  # Change to your email
            msg['To'] = 'shreeshabaiml@gmail.com'  # Send to the user's email or a different email for tracking

            # Send the email
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASS)  # Your email credentials
                server.sendmail(EMAIL_USER, 'shreeshabaiml@gmail.com', msg.as_string())  # Change recipient as needed
            
            flash('Your message has been sent.', 'success')

        except Exception as e:
            flash('Error sending email: ' + str(e), 'danger')

        return redirect(url_for('help'))

    return render_template('help.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        # Retrieve form data
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        mobile = request.form['mobile']  # Ensure this matches your database column
        college = request.form['college']
        qualification = request.form['qualification']
        gender = request.form['gender']

        # Update user data in the database
        conn = get_db_connection()
        try:
            conn.execute('''UPDATE users 
                            SET first_name = ?, last_name = ?, email = ?, mobile_number = ?, college_name = ?, qualification = ?, gender = ? 
                            WHERE id = ?''',
                         (first_name, last_name, email, mobile, college, qualification, gender, user_id))
            conn.commit()

            # Handle profile picture upload
            profile_pic = request.files.get('profile_pic')  # Use get to avoid KeyError
            if profile_pic:
                if allowed_file(profile_pic.filename):
                    profile_pic_path = os.path.join('static/images/profile_pictures', f'{email}.jpg')
                    profile_pic.save(profile_pic_path)
                    conn.execute('UPDATE users SET profile_picture = ? WHERE id = ?', (profile_pic_path, user_id))
                    conn.commit()
                else:
                    flash('Invalid file type. Only PNG, JPG, JPEG, and GIF files are allowed.', 'danger')

            flash('Settings updated successfully.', 'success')
        except sqlite3.IntegrityError as e:
            flash('Error updating settings: ' + str(e), 'danger')
        finally:
            conn.close()

        return redirect(url_for('settings'))

    # Retrieve user data from the database
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    return render_template('settings.html', user=user, user_name=session.get('user_name'))

@app.route('/vstand4udata')
def vstand4u_data():
    password = request.args.get('p')
    if password != 'Vstand4u1@':
        return "Unauthorized", 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user details along with their total watch duration, test results, and certificates
    cursor.execute('''
        SELECT u.id, u.first_name, u.last_name, u.email, u.mobile_number, u.college_name, 
               u.qualification, u.gender, u.created_at, 
               COALESCE(SUM(uvp.watch_duration), 0) as total_watch_duration,
               utr.score, utr.passed, utr.completed_at,
               CASE WHEN c.id IS NOT NULL THEN 'Yes' ELSE 'No' END as certificate_taken
        FROM users u
        LEFT JOIN user_video_progress uvp ON u.id = uvp.user_id
        LEFT JOIN user_test_results utr ON u.id = utr.user_id
        LEFT JOIN certificates c ON u.id = c.user_id
        GROUP BY u.id, utr.id, c.id
    ''')
    
    users = cursor.fetchall()
    conn.close()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'First Name', 'Last Name', 'Email', 'Mobile Number', 'College Name', 
                     'Qualification', 'Gender', 'Created At', 'Total Watch Duration', 
                     'Score', 'Passed', 'Test Taken On', 'Certificate Taken'])
    
    for user in users:
        writer.writerow([
            user['id'], user['first_name'], user['last_name'], user['email'], user['mobile_number'], 
            user['college_name'], user['qualification'], user['gender'], user['created_at'], 
            user['total_watch_duration'], user['score'], user['passed'], user['completed_at'], 
            user['certificate_taken']
        ])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=users_data.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/vstand4uhelp')
def vstand4u_help():
    password = request.args.get('p')
    if password != 'Vstand4u1@':  # Replace 'your_password' with the actual password
        return "Unauthorized", 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get help requests
    cursor.execute('SELECT * FROM help_requests')
    help_requests = cursor.fetchall()
    conn.close()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Name', 'Email', 'Phone Number', 'Subject', 'Content', 'Created At'])
    
    for help_request in help_requests:
        writer.writerow([
            help_request['id'], help_request['name'], help_request['email'], help_request['phone_number'], 
            help_request['subject'], help_request['content'], help_request['created_at']
        ])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=help_requests.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

def generate_certificate(name: str):
    pdf = FPDF()
    pdf.add_page()
    
    # Add logo
    pdf.image('static/images/logo.png', x=10, y=8, w=30)
    
    # Set title
    pdf.set_font("Arial", "B", 24)
    pdf.cell(0, 20, "Certificate of Completion", ln=True, align='C')
    pdf.ln(10)
    
    # Certificate content
    pdf.set_font("Arial", size=14)
    certificate_text = f"This certifies that {name} has successfully completed the Vstand4u training program."
    pdf.multi_cell(0, 10, certificate_text, align='C')
    
    # Add the date of completion
    date_of_completion = datetime.now().strftime("%B %d, %Y")
    pdf.ln(10)
    pdf.cell(0, 10, f"Date: {date_of_completion}", ln=True, align='C')
    
    # Save the PDF
    pdf_file_name = f"static/certificates/{name}_certificate.pdf"
    pdf.output(pdf_file_name)
    
    return pdf_file_name

@app.route('/download_certificate')
def download_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    test_result = conn.execute('SELECT * FROM user_test_results WHERE user_id = ? AND passed = 1', (user_id,)).fetchone()
    
    if not test_result:
        flash('You are not eligible for a certificate.', 'warning')
        return redirect(url_for('video_list'))
    
    full_name = f"{user['first_name']} {user['last_name']}"
    certificate_path = generate_certificate(full_name)

    # Check if a certificate already exists for the user
    existing_certificate = conn.execute('SELECT * FROM certificates WHERE user_id = ?', (user_id,)).fetchone()
    if not existing_certificate:
        conn.execute('INSERT INTO certificates (user_id) VALUES (?)', (user_id,))
        conn.commit()
    conn.close()
    return send_file(certificate_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
