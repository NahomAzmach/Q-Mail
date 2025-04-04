#!/usr/bin/env python3
from email_fetcher import fetch_emails, auto_detect_provider
import argparse
import os
import getpass
import sys

def main():
    """
    Test script to verify email fetching functionality.
    This script allows testing the email_fetcher module with command line options.
    """
    parser = argparse.ArgumentParser(description='Test email fetching functionality')
    
    parser.add_argument('--email', type=str, help='Email address to fetch from')
    parser.add_argument('--password', type=str, help='Password or app password (not recommended, use --ask-password)')
    parser.add_argument('--ask-password', action='store_true', help='Prompt for password instead of command line')
    parser.add_argument('--server', type=str, help='IMAP server address')
    parser.add_argument('--max', type=int, default=5, help='Maximum number of emails to fetch')
    parser.add_argument('--folder', type=str, default="INBOX", help='Email folder to fetch from')
    
    args = parser.parse_args()
    
    # Get email address
    email = args.email
    if not email:
        email = os.environ.get("EMAIL_ADDRESS")
        if not email:
            email = input("Enter your email address: ")
    
    # Detect IMAP server if not provided
    imap_server = args.server
    if not imap_server:
        imap_server = os.environ.get("IMAP_SERVER")
        if not imap_server:
            # Try to auto-detect
            imap_server = auto_detect_provider(email)
            if not imap_server:
                imap_server = input("Enter your IMAP server address (e.g., imap.gmail.com): ")
    
    # Get password
    password = args.password
    if not password:
        password = os.environ.get("EMAIL_PASSWORD")
        if not password or args.ask_password:
            password = getpass.getpass(f"Enter your password or app password for {email}: ")
    
    # Validate required inputs
    if not email or not password or not imap_server:
        print("Error: Email, password, and IMAP server are required.")
        parser.print_help()
        sys.exit(1)
    
    print(f"Fetching up to {args.max} emails from {email} ({imap_server})...")
    print(f"Using folder: {args.folder}")
    
    try:
        # Fetch emails using the email_fetcher module
        emails = fetch_emails(email, password, imap_server, max_emails=args.max, folder=args.folder)
        
        # Check for errors
        if emails and 'error' in emails[0]:
            print(f"Error: {emails[0]['message']}")
            sys.exit(1)
        
        # Display results
        print(f"Successfully fetched {len(emails)} emails!")
        
        for i, email_data in enumerate(emails):
            print(f"\nEmail {i+1}:")
            print(f"Subject: {email_data['subject']}")
            print(f"From: {email_data['from']}")
            print(f"Date: {email_data['date']}")
            # Show body preview
            body_preview = email_data['body'][:100].replace('\n', ' ')
            print(f"Body preview: {body_preview}...")
            
            # Ask to view full body
            if len(emails) > 1 and len(email_data['body']) > 100:
                view_full = input("\nView full body? (y/n) [n]: ").lower().strip()
                if view_full == 'y':
                    print("\n--- FULL EMAIL BODY ---\n")
                    print(email_data['body'])
                    print("\n--- END OF EMAIL BODY ---\n")
                    input("Press Enter to continue...")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
