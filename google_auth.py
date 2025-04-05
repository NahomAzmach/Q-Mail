import json
import os
import base64

import requests
from flask import Blueprint, redirect, request, url_for, session, flash
from flask_login import login_user, logout_user, current_user, login_required
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from oauthlib.oauth2 import WebApplicationClient
from main import db
from models import User

# Configuration
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]
REDIRECT_URI = None  # Will be set dynamically

google_auth = Blueprint("google_auth", __name__)

@google_auth.route("/google_login")
def google_login():
    """Start the Google OAuth flow."""
    # Check if Google OAuth credentials are available
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    
    # Debug environment info
    replit_domain = os.environ.get('REPLIT_DOMAINS')
    if replit_domain:
        if ',' in replit_domain:
            domain_for_uri = replit_domain.split(',')[0].strip()
        else:
            domain_for_uri = replit_domain
        print(f"DEBUG - Detected Replit domain: {domain_for_uri}")
    else:
        print("DEBUG - No Replit domain found in environment variables")
    
    if not client_id or not client_secret:
        flash("Google OAuth credentials are not configured. Please add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET to the environment variables.", "danger")
        return redirect(url_for("index"))
        
    # Set up the OAuth flow with the client secrets
    try:
        # Get the Replit domain from environment
        replit_domain = os.environ.get('REPLIT_DOMAINS')
        if replit_domain:
            if ',' in replit_domain:
                domain_for_uri = replit_domain.split(',')[0].strip()
            else:
                domain_for_uri = replit_domain
                
            # Always use HTTP for the redirect URI (not HTTPS)
            # Google seems to be trying to use HTTP even when we configure HTTPS
            redirect_uri = f"http://{domain_for_uri}/google_login/callback"
            
            # Override the REDIRECT_URI global
            global REDIRECT_URI
            REDIRECT_URI = redirect_uri
            
            # Recreate the client_config with the updated REDIRECT_URI
            client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
            client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
            client_config = {
                "web": {
                    "client_id": client_id,
                    "project_id": "",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_secret": client_secret,
                    "redirect_uris": [REDIRECT_URI]
                }
            }
            with open(CLIENT_SECRETS_FILE, 'w') as f:
                json.dump(client_config, f)
        
        # This will initialize or use our updated REDIRECT_URI
        flow = get_oauth_flow()
        
        # Print the exact redirect URI that will be used
        print(f"DEBUG - login_route - Using Redirect URI: {REDIRECT_URI}")
        print(f"DEBUG - login_route - Make sure this URI is EXACTLY registered in Google Cloud Console")
        
        # Generate the authorization URL with the required scopes
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        print(f"DEBUG - Authorization URL: {authorization_url}")
        
        # Store the state in the session for later validation
        session['state'] = state
        
        # Redirect to the Google authorization URL
        return redirect(authorization_url)
    
    except Exception as e:
        flash(f"Error starting Google login: {str(e)}", "danger")
        print(f"DEBUG - Error in google_login: {str(e)}")
        return redirect(url_for("index"))

@google_auth.route("/google_login/callback")
def callback():
    """Handle the OAuth callback."""
    # Check if there was an error in the callback
    error = request.args.get('error')
    if error:
        if error == "redirect_uri_mismatch":
            # Print more detailed debugging information for redirect URI mismatch
            global REDIRECT_URI
            current_uri = request.base_url
            print(f"Error: Redirect URI mismatch")
            print(f"Expected URI in Google Console: {REDIRECT_URI}")
            print(f"Actual request URI: {current_uri}")
            
            # Redirect to the setup page which will show detailed instructions
            flash(f"OAuth Configuration Error: The redirect URI doesn't match what's configured in your Google Cloud Console. Please see the detailed setup instructions.", "danger")
            return redirect(url_for("oauth_setup"))
        else:
            flash(f"Authorization failed: {error}", "danger")
        return redirect(url_for("index"))
    
    # Get the authorization code from the callback
    code = request.args.get("code")
    state = request.args.get("state")
    
    # Verify the state to prevent CSRF attacks
    if not state or session.get("state") != state:
        flash("Invalid state parameter. Authorization request may have been tampered with.", "danger")
        return redirect(url_for("index"))
    
    try:
        # Exchange the authorization code for credentials
        flow = get_oauth_flow()
        
        # Print debug info
        print(f"Authorization response URL: {request.url}")
        print(f"Configured redirect URI: {REDIRECT_URI}")
        
        # Fix the URL if it's http instead of https
        auth_response = request.url
        if auth_response and REDIRECT_URI:
            if auth_response.startswith('http:') and REDIRECT_URI.startswith('https:'):
                auth_response = 'https:' + auth_response[5:]
                print(f"Fixed auth response URL to: {auth_response}")
        else:
            print("Warning: auth_response or REDIRECT_URI is None")
        
        flow.fetch_token(authorization_response=auth_response)
        
        # Get the credentials from the flow
        credentials = flow.credentials
        
        # Store credentials in the session (only the necessary parts)
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Get user info
        user_info = get_user_info(credentials)
        user_email = user_info.get('email')
        user_name = user_info.get('name', user_email.split('@')[0] if user_email else 'Unknown')
        profile_pic = user_info.get('picture')
        
        # Store in session
        session['user_email'] = user_email
        session['user_name'] = user_name
        
        # Check if user exists in database, if not create
        user = User.query.filter_by(email=user_email).first()
        if not user:
            # Create new user
            user = User(
                username=user_name,
                email=user_email,
                profile_pic=profile_pic
            )
            db.session.add(user)
            db.session.commit()
        
        # Login user with Flask-Login
        login_user(user)
        
        flash(f"Successfully logged in as {user_email}", "success")
        return redirect(url_for("fetch_google_emails"))
    
    except Exception as e:
        flash(f"Error during authentication: {str(e)}", "danger")
        return redirect(url_for("index"))

def get_oauth_flow():
    """Create and configure the OAuth flow."""
    # Determine the redirect URI based on the environment
    global REDIRECT_URI
    if not REDIRECT_URI:
        # First try to get the domain from the request if available
        if request and hasattr(request, 'host'):
            host = request.host
            scheme = request.scheme
            REDIRECT_URI = f"{scheme}://{host}/google_login/callback"
            print(f"DEBUG - Using host-based redirect URI: {REDIRECT_URI}")
        else:
            replit_domain = os.environ.get('REPLIT_DOMAINS')  # Note: it's DOMAINS with an 'S'
            if replit_domain:
                # Use the exact domain from environment
                # If it contains multiple domains (comma-separated), take the first one
                if ',' in replit_domain:
                    replit_domain = replit_domain.split(',')[0].strip()
                
                REDIRECT_URI = f"https://{replit_domain}/google_login/callback"
                print(f"DEBUG - Using environment-based redirect URI: {REDIRECT_URI}")
                print(f"DEBUG - Please make sure this exact URI is configured in Google Cloud Console")
            else:
                # Fallback to localhost
                REDIRECT_URI = "http://localhost:5000/google_login/callback"
                print("DEBUG - No Replit domain found, using localhost redirect URI")
    
    print(f"FINAL REDIRECT URI: {REDIRECT_URI}")
    print("Make sure this EXACT URI is registered in your Google Cloud Console!")
    
    # Get client ID and client secret from environment variables
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    
    # Validate that we have the required credentials
    if not client_id or not client_secret:
        raise ValueError("Google OAuth credentials missing. Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET environment variables.")
    
    # Always recreate the client_secret.json file to ensure it has the latest credentials
    client_config = {
        "web": {
            "client_id": client_id,
            "project_id": "",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": [REDIRECT_URI]
        }
    }
    with open(CLIENT_SECRETS_FILE, 'w') as f:
        json.dump(client_config, f)
    
    # Create the flow
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    
    return flow

def get_user_info(credentials):
    """Get the user's information using the given credentials."""
    try:
        # Build the service
        service = build('oauth2', 'v2', credentials=credentials)
        
        # Get the user's info
        user_info = service.userinfo().get().execute()
        return user_info
    
    except Exception as e:
        print(f"Error getting user info: {str(e)}")
        return {}

def get_credentials_from_session():
    """Retrieve and validate credentials from the session."""
    if 'credentials' not in session:
        return None
    
    # Get the credentials from the session
    creds_data = session['credentials']
    
    # Create credentials object
    return Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )

def fetch_gmail_messages(max_results=50, offset=0, folder='INBOX'):
    """
    Fetch the user's Gmail messages using stored credentials.
    
    Args:
        max_results: Maximum number of emails to fetch
        offset: Number of emails to skip (for pagination)
        folder: Gmail label/folder to fetch from (INBOX, SPAM, TRASH, etc.)
        
    Returns:
        Tuple of (emails_data, error_message)
    """
    credentials = get_credentials_from_session()
    if not credentials:
        return None, "Not authenticated with Google"
    
    try:
        # Build the Gmail API service
        service = build('gmail', 'v1', credentials=credentials)
        
        # Convert folder names to Gmail labels
        label_mapping = {
            'INBOX': 'INBOX',
            'SPAM': 'SPAM',
            'JUNK': 'SPAM',  # Alias for SPAM
            'TRASH': 'TRASH',
            'DRAFTS': 'DRAFT',
            'SENT': 'SENT',
            'IMPORTANT': 'IMPORTANT',
            'STARRED': 'STARRED',
            'UNREAD': 'UNREAD',
            'CATEGORY_PERSONAL': 'CATEGORY_PERSONAL',
            'CATEGORY_SOCIAL': 'CATEGORY_SOCIAL',
            'CATEGORY_PROMOTIONS': 'CATEGORY_PROMOTIONS',
            'CATEGORY_UPDATES': 'CATEGORY_UPDATES',
            'CATEGORY_FORUMS': 'CATEGORY_FORUMS',
        }
        
        gmail_label = label_mapping.get(folder.upper(), 'INBOX')
        
        # Get a list of messages with optional label filter
        query = f'label:{gmail_label}' if gmail_label != 'INBOX' else None
        
        # Get list of message IDs
        results = service.users().messages().list(
            userId='me', 
            maxResults=max_results,
            q=query,
            pageToken=None if offset == 0 else f"p{offset}"  # Simplistic pagination
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            return [], f"No messages found in {folder}"
        
        # Fetch details for each message
        emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            
            # Get labels for the message
            labels = msg.get('labelIds', [])
            
            # Extract email details
            headers = msg['payload']['headers']
            subject = ""
            sender = ""
            date = ""
            
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Date':
                    date = header['value']
            
            # Get the body of the message
            body = ""
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        data = part['body'].get('data', '')
                        if data:
                            body += base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
            else:
                data = msg['payload']['body'].get('data', '')
                if data:
                    body += base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
            
            # Determine folder/category based on labels
            message_folder = 'INBOX'
            if 'SPAM' in labels:
                message_folder = 'SPAM'
            elif 'TRASH' in labels:
                message_folder = 'TRASH'
            elif 'DRAFT' in labels:
                message_folder = 'DRAFTS'
            elif 'SENT' in labels:
                message_folder = 'SENT'
            elif 'CATEGORY_PROMOTIONS' in labels:
                message_folder = 'PROMOTIONS'
            elif 'CATEGORY_SOCIAL' in labels:
                message_folder = 'SOCIAL'
            elif 'CATEGORY_FORUMS' in labels:
                message_folder = 'FORUMS'
            elif 'CATEGORY_UPDATES' in labels:
                message_folder = 'UPDATES'
            
            # Add the email to the list
            emails.append({
                'id': msg['id'],
                'subject': subject,
                'from': sender,
                'date': date,
                'body': body,
                'folder': message_folder,
                'labels': labels,
                'unread': 'UNREAD' in labels,
                'important': 'IMPORTANT' in labels,
                'starred': 'STARRED' in labels,
            })
        
        return emails, None
    
    except Exception as e:
        return None, f"Error fetching Gmail messages: {str(e)}"