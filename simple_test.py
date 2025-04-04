#!/usr/bin/env python3
"""
Simple test script for email fetcher
This is a simplified version that demonstrates how to use the email_fetcher module directly
"""
from email_fetcher import fetch_emails

# REPLACE THESE VALUES WITH YOUR OWN
EMAIL = "your_email@gmail.com"  # Your email address
PASSWORD = "your_app_password"   # Use an app password, not your regular password
IMAP_SERVER = "imap.gmail.com"   # For Gmail (change for other providers)

def main():
    print("Fetching emails...")
    try:
        # Fetch emails from the server
        emails = fetch_emails(
            email_address=EMAIL,
            password=PASSWORD,
            imap_server=IMAP_SERVER,
            max_emails=5  # Adjust as needed
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
            print(f"Body preview: {email_data['body'][:100]}...")
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()