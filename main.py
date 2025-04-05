#!/usr/bin/env python3
from flask import render_template, request, session, flash, redirect, url_for
import os
import logging
from email_fetcher import fetch_emails, auto_detect_provider, get_imap_server
# Import analysis methods
from email_security import batch_analyze_emails as rule_based_analyze_emails
# Import the new hybrid AI analyzer that combines OpenAI with rule-based fallback (full content analysis)
from hybrid_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails
# Import the headers-only AI analyzer for privacy-focused analysis
from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
from flask_login import login_required, logout_user, current_user, login_user

# Import the database and app setup from the new module
from db_setup import app, db, login_manager, logger

# Import models and create tables
from models import EmailSession, Email, User

with app.app_context():
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
    """Home page with email fetcher form."""
    return render_template('index.html')

@app.route('/fetch', methods=['POST'])
def fetch():
    """Process the form and fetch emails."""
    email_address = request.form.get('email')
    password = request.form.get('password')
    imap_server = request.form.get('imap_server')
    provider = request.form.get('provider')
    max_emails = int(request.form.get('max_emails', 10))
    folder = request.form.get('folder', 'INBOX')
    
    # Validate inputs
    if not email_address or not password:
        flash('Email and password are required.', 'danger')
        return redirect(url_for('index'))
    
    # If IMAP server not provided, try to get it from the provider or auto-detect
    if not imap_server:
        if provider and provider != 'auto':
            imap_server = get_imap_server(provider)
        else:
            imap_server = auto_detect_provider(email_address)
            
        if not imap_server:
            flash('Could not determine IMAP server. Please specify it manually.', 'danger')
            return redirect(url_for('index'))
    
    # Fetch emails
    try:
        emails_data = fetch_emails(
            email_address=email_address,
            password=password,
            imap_server=imap_server,
            max_emails=max_emails,
            folder=folder
        )
        
        # Check for errors
        if emails_data and 'error' in emails_data[0]:
            flash(f"Error fetching emails: {emails_data[0]['message']}", 'danger')
            return redirect(url_for('index'))
        
        # Create a new email session in the database
        email_session = EmailSession(
            email_address=email_address,
            provider=provider or 'auto-detected'
        )
        db.session.add(email_session)
        db.session.flush()  # Generate ID for session
        
        # Store each email in the database
        for email_data in emails_data:
            email = Email(
                session_id=email_session.id,
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                date=email_data.get('date', ''),
                body=email_data.get('body', ''),
                error='error' in email_data,
                error_message=email_data.get('message', '') if 'error' in email_data else None
            )
            db.session.add(email)
        
        # Commit all changes to database
        db.session.commit()
        
        # Store only the session ID in the session cookie
        session['email_session_id'] = email_session.id
        
        return redirect(url_for('results'))
        
    except Exception as e:
        logger.error(f"Error in fetch_emails: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/results', methods=['GET'])
def results():
    """Display the fetched email results."""
    # Get session ID from the session
    session_id = session.get('email_session_id')
    
    # Check if we're being redirected with the 'ai' and 'full_content' flags
    use_ai = request.args.get('ai', 'false').lower() == 'true'
    full_content = request.args.get('full_content', 'false').lower() == 'true'
    
    if not session_id:
        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    # Retrieve the session and its emails from the database
    email_session = EmailSession.query.get(session_id)
    
    if not email_session:
        flash('Email results not found. Please fetch emails again.', 'warning')
        session.pop('email_session_id', None)
        return redirect(url_for('index'))
    
    # Get email data from database
    email_list = [email.to_dict() for email in email_session.emails]
    
    # Import all analyzer modules at the beginning to avoid issues with fallback
    from email_security import batch_analyze_emails as rule_based_analyze_emails
    from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
    from simple_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails
    
    # Perform security analysis based on user settings
    try:
        if use_ai:
            if full_content:
                # Full content AI analysis - sends the entire email to AI
                logger.info("Using full-content AI-based email analysis")
                analyzed_emails = full_ai_analyze_emails(email_list)
            else:
                # Headers-only AI analysis for enhanced privacy
                logger.info("Using headers-only AI-based email analysis")
                analyzed_emails = headers_only_ai_analyze_emails(email_list)
        else:
            # Traditional rule-based analysis - no AI
            logger.info("Using rule-based email analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        # Fallback to rule-based analysis if AI analysis fails
        try:
            logger.info("Falling back to rule-based analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
            flash("AI analysis failed. Showing results from rule-based analysis instead.", "warning")
        except Exception as e2:
            logger.error(f"Error in fallback analysis: {str(e2)}")
            analyzed_emails = email_list  # Just show raw emails if all analysis fails
            flash("Email analysis failed. Showing raw emails without security analysis.", "danger")
    
    # Format the results to match the template expectations
    results = {
        'email_address': email_session.email_address,
        'imap_server': 'Stored in database',
        'folder': 'INBOX',
        'count': len(email_session.emails),
        'emails': analyzed_emails,
        'using_ai': use_ai,
        'full_content': full_content
    }
    
    return render_template('results.html', results=results)

@app.route('/analyze_with_ai', methods=['GET'])
def analyze_with_ai():
    """Run headers-only AI analysis on already fetched emails."""
    session_id = session.get('email_session_id')
    
    if not session_id:
        flash('No emails to analyze. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    return redirect(url_for('results', ai='true', full_content='false'))

@app.route('/analyze_with_full_ai', methods=['GET'])
def analyze_with_full_ai():
    """Run full-content AI analysis on already fetched emails."""
    session_id = session.get('email_session_id')
    
    if not session_id:
        flash('No emails to analyze. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    return redirect(url_for('results', ai='true', full_content='true'))

@app.route('/fetch_google_emails', methods=['GET'])
@login_required
def fetch_google_emails():
    """Fetch emails directly from Gmail using OAuth."""
    from google_auth import fetch_gmail_messages
    
    if 'credentials' not in session:
        flash('Not authenticated with Google. Please log in.', 'warning')
        return redirect(url_for('index'))
    
    # Set max emails
    max_emails = request.args.get('max_emails', default=10, type=int)
    
    try:
        # Fetch emails using Gmail API
        emails_data, error = fetch_gmail_messages(max_results=max_emails)
        
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
            flash("No emails found", 'warning')
            return redirect(url_for('index'))
        
        # Create a new email session in the database
        email_session = EmailSession(
            email_address=session.get('user_email', 'Unknown Gmail user'),
            provider='gmail-oauth'
        )
        db.session.add(email_session)
        db.session.flush()  # Generate ID for session
        
        # Store each email in the database
        for email_data in emails_data:
            email = Email(
                session_id=email_session.id,
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                date=email_data.get('date', ''),
                body=email_data.get('body', ''),
                error=False
            )
            db.session.add(email)
        
        # Commit all changes to database
        db.session.commit()
        
        # Store only the session ID in the session cookie
        session['email_session_id'] = email_session.id
        
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
