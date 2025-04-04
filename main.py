#!/usr/bin/env python3
from flask import Flask, render_template, request, session, flash, redirect, url_for
import os
import logging
from email_fetcher import fetch_emails, auto_detect_provider, get_imap_server

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))

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
        emails = fetch_emails(
            email_address=email_address,
            password=password,
            imap_server=imap_server,
            max_emails=max_emails,
            folder=folder
        )
        
        # Check for errors
        if emails and 'error' in emails[0]:
            flash(f"Error fetching emails: {emails[0]['message']}", 'danger')
            return redirect(url_for('index'))
        
        # Store results in session for display
        session['email_results'] = {
            'email_address': email_address,
            'imap_server': imap_server,
            'folder': folder,
            'count': len(emails),
            'emails': emails
        }
        
        return redirect(url_for('results'))
        
    except Exception as e:
        logger.error(f"Error in fetch_emails: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/results', methods=['GET'])
def results():
    """Display the fetched email results."""
    # Get results from session
    email_results = session.get('email_results')
    
    if not email_results:
        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    return render_template('results.html', results=email_results)

@app.route('/clear', methods=['GET'])
def clear():
    """Clear the session data and return to the form."""
    if 'email_results' in session:
        del session['email_results']
    
    flash('Results cleared.', 'info')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
