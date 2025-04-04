#!/usr/bin/env python3
"""
Simple test script for email fetcher
This is a simplified version that demonstrates how to use the email_fetcher module directly
"""
from email_fetcher import fetch_emails, auto_detect_provider
import getpass

def main():
    # Get user input for email credentials
    email = input("Enter your email address: ")
    
    # Try to auto-detect the IMAP server
    imap_server = auto_detect_provider(email)
    if not imap_server:
        imap_server = input("Could not auto-detect server. Enter IMAP server (e.g., imap.gmail.com): ")
    else:
        print(f"Auto-detected IMAP server: {imap_server}")
        change = input("Use this server? (y/n): ").lower()
        if change != 'y':
            imap_server = input("Enter IMAP server: ")
    
    # Get password securely (won't show on screen)
    password = getpass.getpass("Enter your app password (not your regular password): ")
    
    # Get number of emails to fetch
    try:
        max_emails = int(input("Maximum number of emails to fetch (default: 5): ") or "5")
    except ValueError:
        max_emails = 5
        print("Invalid input, using default: 5")
    
    print(f"Fetching up to {max_emails} emails from {email} ({imap_server})...")
    try:
        # Fetch emails from the server
        emails = fetch_emails(
            email_address=email,
            password=password,
            imap_server=imap_server,
            max_emails=max_emails
        )
        
        # Check for errors
        if emails and 'error' in emails[0]:
            print(f"Error: {emails[0]['message']}")
            return
            
        # Print results
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
            if i < len(emails) - 1:  # Not the last email
                view_full = input("\nView full body? (y/n) [n]: ").lower().strip()
                if view_full == 'y':
                    print("\n--- FULL EMAIL BODY ---\n")
                    print(email_data['body'])
                    print("\n--- END OF EMAIL BODY ---\n")
                    input("Press Enter to continue...")
            else:  # Last email
                print("\n--- FULL EMAIL BODY ---\n")
                print(email_data['body'])
                print("\n--- END OF EMAIL BODY ---\n")
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()