from flask import Flask, render_template, jsonify, request, flash, redirect, url_for, send_file, after_this_request, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from models import db, User, CrimeReport
from forms import LoginForm, RegistrationForm, CrimeReportForm, SecurityAnswerForm, ResetPasswordForm, AdminResetForm, UserCredentialResetForm
import pdfkit
import tempfile
import time
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crimemap.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

# Configure wkhtmltopdf path - check multiple possible locations
WKHTMLTOPDF_PATHS = [
    r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
    r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
    r'wkhtmltopdf'  # If added to system PATH
]

def find_wkhtmltopdf():
    for path in WKHTMLTOPDF_PATHS:
        try:
            if path == 'wkhtmltopdf':
                # Try to use from system PATH
                config = pdfkit.configuration()
            else:
                # Try specific path
                if os.path.exists(path):
                    config = pdfkit.configuration(wkhtmltopdf=path)
            # Test if configuration works
            pdfkit.from_string('test', None, configuration=config)
            return config
        except Exception:
            continue
    return None

# Try to configure wkhtmltopdf
pdf_config = find_wkhtmltopdf()
if pdf_config is None:
    print("""
    WARNING: wkhtmltopdf not found. PDF generation will not work.
    Please install wkhtmltopdf:
    1. Download from https://wkhtmltopdf.org/downloads.html
    2. Install and add to system PATH
    3. Restart the application
    """)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Try to find user by username first, then by email
        user = User.query.filter_by(username=form.username.data).first()
        if user is None:
            user = User.query.filter_by(email=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid username/email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            security_answer=(form.security_answer.data.strip().lower() if form.security_answer.data else None)
        )  # type: ignore
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# User routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    form = CrimeReportForm()
    return render_template('user_dashboard.html', form=form)

@app.route('/user/reports')
@login_required
def my_reports():
    reports = CrimeReport.query.filter_by(reporter_id=current_user.id).all()
    ist = pytz.timezone('Asia/Kolkata')
    for report in reports:
        if report.timestamp:
            report.timestamp = report.timestamp.replace(tzinfo=pytz.utc).astimezone(ist)
    return render_template('my_reports.html', reports=reports)

@app.route('/report/crime', methods=['POST'])
@login_required
def report_crime():
    form = CrimeReportForm()
    if form.validate_on_submit():
        report = CrimeReport(
            type=form.type.data,
            description=form.description.data,
            latitude=form.latitude.data,
            longitude=form.longitude.data,
            location=form.location.data
        )  # type: ignore
        report.reporter_id = current_user.id
        
        if form.evidence.data:
            file = form.evidence.data
            if file and allowed_file(file.filename):
                # Secure the filename and add timestamp
                original_filename = secure_filename(file.filename)
                file_extension = original_filename.rsplit('.', 1)[1].lower()
                timestamp = int(time.time())
                filename = f"{timestamp}_{original_filename}"
                
                # Save the file
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    report.evidence_file = filename
                    app.logger.info(f"File saved successfully at {file_path}")
                except Exception as e:
                    app.logger.error(f"Error saving file: {str(e)}")
                    flash('Error saving evidence file')
                    return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid file type. Allowed types are: png, jpg, jpeg, gif, pdf, doc, docx')
                return redirect(url_for('user_dashboard'))
        
        try:
            db.session.add(report)
            db.session.commit()
            flash('Crime report submitted successfully')
        except Exception as e:
            app.logger.error(f"Error saving report: {str(e)}")
            flash('Error saving report. Please try again.')
            
        return redirect(url_for('my_reports'))
    return redirect(url_for('user_dashboard'))

@app.route('/static/uploads/<path:filename>')
@login_required
def serve_evidence(filename):
    """Serve evidence files from the uploads directory."""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        app.logger.error(f"Error serving file {filename}: {str(e)}")
        flash('Error loading evidence file')
        return redirect(url_for('my_reports'))

# Admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('user_dashboard'))
    
    reports = CrimeReport.query.all()
    ist = pytz.timezone('Asia/Kolkata')
    for report in reports:
        if report.timestamp:
            report.timestamp = report.timestamp.replace(tzinfo=pytz.utc).astimezone(ist)
    current_month = datetime.now().month
    current_year = datetime.now().year
    previous_month = (datetime.now().replace(day=1) - timedelta(days=1)).month
    previous_year = (datetime.now().replace(day=1) - timedelta(days=1)).year
    
    # Calculate location statistics
    location_stats = {}
    for report in reports:
        if report.location in location_stats:
            location_stats[report.location]['total_crimes'] += 1
            if report.status == 'resolved':
                location_stats[report.location]['resolved_crimes'] += 1
            if report.timestamp.month == current_month and report.timestamp.year == current_year:
                location_stats[report.location]['current_month_crimes'] += 1
            elif report.timestamp.month == previous_month and report.timestamp.year == previous_year:
                location_stats[report.location]['previous_month_crimes'] += 1
        else:
            location_stats[report.location] = {
                'total_crimes': 1,
                'resolved_crimes': 0,
                'current_month_crimes': 1 if (report.timestamp.month == current_month and report.timestamp.year == current_year) else 0,
                'previous_month_crimes': 1 if (report.timestamp.month == previous_month and report.timestamp.year == previous_year) else 0
            }
    
    # Sort locations by total crimes to find hotspots
    sorted_locations = sorted(
        [(loc, stats) for loc, stats in location_stats.items()],
        key=lambda x: x[1]['total_crimes'],
        reverse=True
    )
    
    # Calculate statistics for template
    most_active_location = sorted_locations[0][0] if sorted_locations else "No Data"
    total_locations = len(location_stats)
    
    # Calculate total resolved and total crimes
    total_resolved = sum(stats['resolved_crimes'] for stats in location_stats.values())
    total_crimes = sum(stats['total_crimes'] for stats in location_stats.values())
    resolved_percentage = int((total_resolved / total_crimes * 100) if total_crimes > 0 else 0)
    
    # Calculate month-over-month changes
    current_month_crimes = sum(stats['current_month_crimes'] for stats in location_stats.values())
    previous_month_crimes = sum(stats['previous_month_crimes'] for stats in location_stats.values())
    
    # Calculate month-over-month change percentage for most active location
    if most_active_location != "No Data":
        most_active_stats = location_stats[most_active_location]
        current_month_active = most_active_stats['current_month_crimes']
        previous_month_active = most_active_stats['previous_month_crimes']
        
        if previous_month_active > 0:
            monthly_change_percentage = int(((current_month_active - previous_month_active) / previous_month_active) * 100)
        else:
            # If there were no crimes in the previous month, we'll show "New" instead of a percentage
            monthly_change_percentage = 0  # This will be handled specially in the template
    else:
        monthly_change_percentage = 0
    
    app.logger.info(f"Monthly change percentage: {monthly_change_percentage}%")
    
    # Calculate resolution rate improvement
    current_month_resolved = sum(1 for report in reports 
                               if report.status == 'resolved' 
                               and report.timestamp.month == current_month
                               and report.timestamp.year == current_year)
    current_month_total = sum(1 for report in reports 
                            if report.timestamp.month == current_month
                            and report.timestamp.year == current_year)
    
    previous_month_resolved = sum(1 for report in reports 
                                if report.status == 'resolved' 
                                and report.timestamp.month == previous_month
                                and report.timestamp.year == previous_year)
    previous_month_total = sum(1 for report in reports 
                             if report.timestamp.month == previous_month
                             and report.timestamp.year == previous_year)
    
    current_resolution_rate = (current_month_resolved / current_month_total * 100) if current_month_total > 0 else 0
    previous_resolution_rate = (previous_month_resolved / previous_month_total * 100) if previous_month_total > 0 else 0
    
    resolution_improvement = int(current_resolution_rate - previous_resolution_rate) if previous_month_total > 0 else 0
    
    # Prepare hotspot locations data
    hotspot_locations = []
    for location, stats in sorted_locations[:5]:  # Top 5 hotspots
        total_crimes = stats['total_crimes']
        resolved = stats['resolved_crimes']
        resolved_percentage = int((resolved / total_crimes * 100) if total_crimes > 0 else 0)
        
        # Determine risk level based on crime count and resolution rate
        if total_crimes >= 10 and resolved_percentage < 50:
            risk_level = 'high'
        elif total_crimes >= 5 or resolved_percentage < 70:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        hotspot_locations.append({
            'name': location,
            'total_crimes': total_crimes,
            'recent_crimes': stats['current_month_crimes'],
            'resolved_percentage': resolved_percentage,
            'risk_level': risk_level
        })
    
    return render_template(
        'admin_dashboard.html',
        reports=reports,
        most_active_location=most_active_location,
        total_locations=total_locations,
        resolved_percentage=resolved_percentage,
        hotspot_locations=hotspot_locations,
        monthly_change_percentage=monthly_change_percentage,
        resolution_improvement=resolution_improvement
    )

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/api/crimes')
@login_required
def api_crimes():
    if not current_user.is_admin:
        reports = CrimeReport.query.filter_by(reporter_id=current_user.id).all()
    else:
        reports = CrimeReport.query.all()
    return jsonify([{
        'id': r.id,
        'type': r.type,
        'description': r.description,
        'latitude': r.latitude,
        'longitude': r.longitude,
        'location': r.location,
        'timestamp': r.timestamp.isoformat(),
        'status': r.status,
        'reporter_id': r.reporter_id
    } for r in reports])

@app.route('/api/route', methods=['POST'])
@login_required
def api_route():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        return jsonify({
            "start": {
                "lat": float(data.get('police_lat')),
                "lng": float(data.get('police_lng'))
            },
            "end": {
                "lat": float(data.get('crime_lat')),
                "lng": float(data.get('crime_lng'))
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/report/<int:crime_id>')
@login_required
def report(crime_id):
    report = CrimeReport.query.get_or_404(crime_id)
    if not current_user.is_admin and report.reporter_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('user_dashboard'))
    return render_template('report.html', crime=report)

@app.route('/api/update_status/<int:report_id>', methods=['POST'])
@login_required
def update_status(report_id):
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    report = CrimeReport.query.get_or_404(report_id)
    status = request.json.get('status') if request.json else None
    
    if status not in ['pending', 'investigating', 'resolved']:
        return jsonify({"error": "Invalid status"}), 400
    
    report.status = status
    db.session.commit()
    
    # Get updated statistics
    reports = CrimeReport.query.all()
    current_month = datetime.now().month
    current_year = datetime.now().year
    previous_month = (datetime.now().replace(day=1) - timedelta(days=1)).month
    previous_year = (datetime.now().replace(day=1) - timedelta(days=1)).year
    
    app.logger.info(f"Calculating statistics for month {current_month}/{current_year}")
    app.logger.info(f"Previous month: {previous_month}/{previous_year}")
    
    # Calculate location statistics
    location_stats = {}
    for report in reports:
        if report.location in location_stats:
            location_stats[report.location]['total_crimes'] += 1
            if report.status == 'resolved':
                location_stats[report.location]['resolved_crimes'] += 1
            if report.timestamp.month == current_month and report.timestamp.year == current_year:
                location_stats[report.location]['current_month_crimes'] += 1
            elif report.timestamp.month == previous_month and report.timestamp.year == previous_year:
                location_stats[report.location]['previous_month_crimes'] += 1
        else:
            location_stats[report.location] = {
                'total_crimes': 1,
                'resolved_crimes': 0 if report.status != 'resolved' else 1,
                'current_month_crimes': 1 if (report.timestamp.month == current_month and report.timestamp.year == current_year) else 0,
                'previous_month_crimes': 1 if (report.timestamp.month == previous_month and report.timestamp.year == previous_year) else 0
            }
    
    app.logger.info(f"Location stats: {location_stats}")
    
    # Calculate total resolved and total crimes
    total_resolved = sum(stats['resolved_crimes'] for stats in location_stats.values())
    total_crimes = sum(stats['total_crimes'] for stats in location_stats.values())
    resolved_percentage = int((total_resolved / total_crimes * 100) if total_crimes > 0 else 0)
    
    app.logger.info(f"Total resolved: {total_resolved}")
    app.logger.info(f"Total crimes: {total_crimes}")
    app.logger.info(f"Resolved percentage: {resolved_percentage}%")
    
    # Calculate month-over-month changes
    current_month_crimes = sum(stats['current_month_crimes'] for stats in location_stats.values())
    previous_month_crimes = sum(stats['previous_month_crimes'] for stats in location_stats.values())
    
    # Calculate resolution rate improvement
    current_month_resolved = sum(1 for r in reports 
                               if r.status == 'resolved' 
                               and r.timestamp.month == current_month
                               and r.timestamp.year == current_year)
    current_month_total = sum(1 for r in reports 
                            if r.timestamp.month == current_month
                            and r.timestamp.year == current_year)
    
    previous_month_resolved = sum(1 for r in reports 
                                if r.status == 'resolved' 
                                and r.timestamp.month == previous_month
                                and r.timestamp.year == previous_year)
    previous_month_total = sum(1 for r in reports 
                             if r.timestamp.month == previous_month
                             and r.timestamp.year == previous_year)
    
    app.logger.info(f"Current month - Resolved: {current_month_resolved}, Total: {current_month_total}")
    app.logger.info(f"Previous month - Resolved: {previous_month_resolved}, Total: {previous_month_total}")
    
    current_resolution_rate = (current_month_resolved / current_month_total * 100) if current_month_total > 0 else 0
    previous_resolution_rate = (previous_month_resolved / previous_month_total * 100) if previous_month_total > 0 else 0
    
    resolution_improvement = int(current_resolution_rate - previous_resolution_rate) if previous_month_total > 0 else 0
    
    app.logger.info(f"Current resolution rate: {current_resolution_rate}%")
    app.logger.info(f"Previous resolution rate: {previous_resolution_rate}%")
    app.logger.info(f"Resolution improvement: {resolution_improvement}%")
    
    # Sort locations by total crimes to find hotspots
    sorted_locations = sorted(
        [(loc, stats) for loc, stats in location_stats.items()],
        key=lambda x: x[1]['total_crimes'],
        reverse=True
    )
    
    # Get most active location
    most_active_location = sorted_locations[0][0] if sorted_locations else "No Data"
    
    # Calculate month-over-month change percentage for most active location
    if most_active_location != "No Data":
        most_active_stats = location_stats[most_active_location]
        current_month_active = most_active_stats['current_month_crimes']
        previous_month_active = most_active_stats['previous_month_crimes']
        
        if previous_month_active > 0:
            monthly_change_percentage = int(((current_month_active - previous_month_active) / previous_month_active) * 100)
        else:
            # If there were no crimes in the previous month, we'll show "New" instead of a percentage
            monthly_change_percentage = 0  # This will be handled specially in the template
    else:
        monthly_change_percentage = 0
    
    app.logger.info(f"Monthly change percentage: {monthly_change_percentage}%")
    
    response_data = {
        "success": True,
        "message": f"Status updated to {status}",
        "report_id": report_id,
        "status": status,
        "stats": {
            "resolved_percentage": resolved_percentage,
            "monthly_change_percentage": monthly_change_percentage,
            "resolution_improvement": resolution_improvement
        }
    }
    
    app.logger.info(f"Sending response: {response_data}")
    return jsonify(response_data)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    class UsernameForm(FlaskForm):
        username = StringField('Username', validators=[DataRequired()])
        submit = SubmitField('Next')
    form = UsernameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            return redirect(url_for('verify_security_answer', username=user.username))
        flash('Username not found', 'error')
    return render_template('reset_password_request.html', form=form)

@app.route('/verify_security_answer/<username>', methods=['GET', 'POST'])
def verify_security_answer(username):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid username', 'error')
        return redirect(url_for('reset_password_request'))
    form = SecurityAnswerForm()
    if form.validate_on_submit():
        if user.security_answer and form.security_answer.data and user.security_answer.strip().lower() == form.security_answer.data.strip().lower():
            return redirect(url_for('reset_password', username=user.username))
        flash('Incorrect answer. Please try again.', 'error')
    return render_template('verify_security_answer.html', form=form)

@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid username', 'error')
        return redirect(url_for('reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset. You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/admin/reset_credentials', methods=['GET', 'POST'])
@login_required
def admin_reset_credentials():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    form = AdminResetForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.username = form.new_username.data
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Admin credentials updated successfully')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Current password is incorrect')
    
    return render_template('admin_reset_credentials.html', form=form)

@app.route('/user/reset_credentials', methods=['GET', 'POST'])
def user_reset_credentials():
    if current_user.is_authenticated:
        form = UserCredentialResetForm()
        if form.validate_on_submit():
            if current_user.check_password(form.current_password.data):
                # Check if new username is already taken
                if form.new_username.data != current_user.username and User.query.filter_by(username=form.new_username.data).first():
                    flash('Username already exists')
                    return render_template('user_reset_credentials.html', form=form)
                
                # Check if new email is already taken
                if form.new_email.data != current_user.email and User.query.filter_by(email=form.new_email.data).first():
                    flash('Email already exists')
                    return render_template('user_reset_credentials.html', form=form)
                
                current_user.username = form.new_username.data
                current_user.email = form.new_email.data
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Your credentials have been updated successfully')
                return redirect(url_for('user_dashboard' if not current_user.is_admin else 'admin_dashboard'))
            else:
                flash('Current password is incorrect')
        return render_template('user_reset_credentials.html', form=form)
    else:
        # For unauthenticated users, show a form to enter username and current password first
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash('Please update your credentials now')
                return redirect(url_for('user_reset_credentials'))
            flash('Invalid username or password')
        return render_template('verify_credentials.html', form=form, title='Verify Credentials')

@app.route('/report/<int:crime_id>/download')
@login_required
def download_report(crime_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('user_dashboard'))
    
    if pdf_config is None:
        flash('PDF generation is not available. Please install wkhtmltopdf first.')
        return redirect(url_for('admin_dashboard'))
    
    report = CrimeReport.query.get_or_404(crime_id)
    
    # Render the template with the report data
    rendered_html = render_template(
        'report_pdf.html',
        report=report,
        current_time=datetime.now()
    )
    
    try:
        # Create a unique temporary file name
        temp_dir = tempfile.gettempdir()
        timestamp = int(time.time())
        pdf_path = os.path.join(temp_dir, f'report_{report.id}_{timestamp}.pdf')
        
        # Configure pdfkit options
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': 'UTF-8',
            'no-outline': None
        }
        
        # Generate PDF from HTML
        pdfkit.from_string(rendered_html, pdf_path, options=options, configuration=pdf_config)
        
        # Send the file
        return_value = send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'crime_report_{report.id}.pdf'
        )
        
        # Schedule file deletion after response is sent
        @after_this_request
        def remove_file(response):
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception as e:
                app.logger.error(f"Error removing temporary file: {e}")
            return response
        
        return return_value
            
    except Exception as e:
        app.logger.error(f"Error generating PDF: {e}")
        flash('Error generating PDF. Please make sure wkhtmltopdf is installed correctly.')
        return redirect(url_for('admin_dashboard'))

@app.route('/report/delete/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    report = CrimeReport.query.get_or_404(report_id)
    
    # Check if the current user owns this report
    if report.reporter_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this report')
        return redirect(url_for('my_reports'))
    
    try:
        # Delete evidence file if it exists
        if report.evidence_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], report.evidence_file)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete the report
        db.session.delete(report)
        db.session.commit()
        flash('Report deleted successfully')
    except Exception as e:
        app.logger.error(f"Error deleting report: {str(e)}")
        flash('Error deleting report')
        
    return redirect(url_for('my_reports'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
