#!/usr/bin/env python3
from flask import Flask, render_template, request, session, flash, redirect, url_for
import os
import json
import logging
from email_security import batch_analyze_emails
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, logout_user, current_user, login_user
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
# Initialize the app with the extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'index'

# Import models and create tables
with app.app_context():
    from models import EmailSession, Email, User
    db.create_all()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Set up Google Auth
from google_auth import google_auth
app.register_blueprint(google_auth)

@app.route('/', methods=['GET'])
def index():
    """Home page to redirect to Google login."""
    if current_user.is_authenticated and 'credentials' in session:
        # Already logged in and has credentials, redirect to fetch emails
        return redirect(url_for('fetch_google_emails'))
    
    # Otherwise, show the home page with Google login button
    return render_template('index.html')

@app.route('/results', methods=['GET'])
def results():
    """Display the fetched email results."""
    # Get session ID from the session
    session_id = session.get('email_session_id')
    
    if not session_id:
        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    # Retrieve the session and its emails from the database
    email_session = EmailSession.query.get(session_id)
    
    if not email_session:
        flash('Email results not found. Please fetch emails again.', 'warning')
        session.pop('email_session_id', None)
        return redirect(url_for('index'))
    
    # Get email data and perform security analysis
    email_list = [email.to_dict() for email in email_session.emails]
    analyzed_emails = batch_analyze_emails(email_list)
    
    # Format the results to match the template expectations
    results = {
        'email_address': email_session.email_address,
        'provider': 'Gmail (OAuth)',
        'count': len(email_session.emails),
        'emails': analyzed_emails
    }
    
    return render_template('results.html', results=results)

@app.route('/fetch_google_emails', methods=['GET'])
@login_required
def fetch_google_emails():
    """Fetch emails directly from Gmail using OAuth."""
    from google_auth import fetch_gmail_messages
    
    if 'credentials' not in session:
        flash('Not authenticated with Google. Please log in.', 'warning')
        return redirect(url_for('index'))
    
    # Set parameters from request
    max_emails = request.args.get('max_emails', default=15, type=int)
    offset = request.args.get('offset', default=0, type=int)
    folder = request.args.get('folder', default='INBOX', type=str)
    append = request.args.get('append', default='false', type=str).lower() == 'true'
    
    try:
        # Fetch emails using Gmail API
        emails_data, error = fetch_gmail_messages(max_results=max_emails, offset=offset, folder=folder)
        
        if error:
            # Specific handling for the Gmail API not enabled error
            if "Gmail API has not been used in project" in error or "accessNotConfigured" in error:
                flash("The Gmail API needs to be enabled in your Google Cloud Console project. "
                      "Please visit your Google Cloud Console, go to 'APIs & Services' > 'Library', "
                      "search for 'Gmail API', and click 'Enable'.", 'warning')
                
                # Return a special template with instructions on how to enable Gmail API
                return render_template('gmail_setup.html', 
                                      user_email=session.get('user_email'),
                                      error_details=error)
            else:
                # Handle other errors
                flash(f"Error fetching emails: {error}", 'danger')
                return redirect(url_for('index'))
        
        if not emails_data:
            flash(f"No emails found in {folder}", 'warning')
            if append:
                # If appending, just return to results
                return redirect(url_for('results'))
            return redirect(url_for('index'))
        
        # Create a new email session or use existing one if appending
        if append and 'email_session_id' in session:
            email_session = EmailSession.query.get(session['email_session_id'])
            if not email_session:
                # If session was deleted, create a new one
                email_session = EmailSession(
                    email_address=session.get('user_email', 'Unknown Gmail user'),
                    provider='gmail-oauth'
                )
                db.session.add(email_session)
                db.session.flush()  # Generate ID for session
                session['email_session_id'] = email_session.id
        else:
            # Create new session
            email_session = EmailSession(
                email_address=session.get('user_email', 'Unknown Gmail user'),
                provider='gmail-oauth'
            )
            db.session.add(email_session)
            db.session.flush()  # Generate ID for session
            session['email_session_id'] = email_session.id
        
        # Store each email in the database
        for email_data in emails_data:
            email = Email(
                session_id=email_session.id,
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                date=email_data.get('date', ''),
                body=email_data.get('body', ''),
                error=False,
                email_metadata=json.dumps({
                    'folder': email_data.get('folder', 'INBOX'),
                    'labels': email_data.get('labels', []),
                    'unread': email_data.get('unread', False),
                    'important': email_data.get('important', False),
                    'starred': email_data.get('starred', False),
                })
            )
            db.session.add(email)
        
        # Commit all changes to database
        db.session.commit()
        
        # Store only the session ID in the session cookie
        session['email_session_id'] = email_session.id
        session['last_offset'] = offset + len(emails_data)
        session['current_folder'] = folder
        
        return redirect(url_for('results'))
        
    except Exception as e:
        logger.error(f"Error in fetch_google_emails: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/clear', methods=['GET'])
def clear():
    """Clear the session data and optionally delete the data from database."""
    session_id = session.get('email_session_id')
    
    if session_id:
        # Option to delete from database too
        try:
            email_session = EmailSession.query.get(session_id)
            if email_session:
                db.session.delete(email_session)
                db.session.commit()
        except Exception as e:
            logger.error(f"Error deleting email session: {str(e)}")
    
    # Clear session data but keep Google auth if present
    session.pop('email_session_id', None)
    
    flash('Results cleared.', 'info')
    return redirect(url_for('index'))

@app.route('/logout', methods=['GET'])
def logout():
    """Logout from Google and clear all session data."""
    # Logout from Flask-Login
    logout_user()
    
    # Clear all session data
    session.clear()
    
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
