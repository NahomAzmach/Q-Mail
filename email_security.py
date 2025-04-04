"""Email security module for validating email senders and content."""
import re
import logging
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# List of common trusted email domains
# This is just a sample list, could be expanded or loaded from a database/file
DEFAULT_TRUSTED_DOMAINS = [
    # Major email providers
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'me.com', 'aol.com',
    'protonmail.com', 'pm.me', 'msn.com', 'live.com', 'mail.com', 'zoho.com',
    
    # Educational
    'edu', 'ac.uk', 'edu.au',
    
    # Government
    'gov', 'gov.uk', 'gov.au', 'mil',
    
    # Business
    'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'github.com', 'salesforce.com', 'ibm.com', 'oracle.com',
    
    # Add more trusted domains as needed
]

# Common email patterns indicating phishing or spam
SUSPICIOUS_PATTERNS = [
    r'urgent.*action', 
    r'verify.*account.*immediately',
    r'suspicious.*activity',
    r'password.*expire',
    r'won.*lottery',
    r'million.*dollar',
    r'claim.*prize',
    r'click.*here',
    r'account.*suspended',
    r'update.*payment',
    r'unusual.*login',
]

def extract_domain_from_email(email_address: str) -> str:
    """Extract the domain from an email address.
    
    Args:
        email_address: The full email address string
        
    Returns:
        The domain portion of the email address
    """
    # Handle cases where email might contain a display name
    # Example: "John Smith <john@example.com>"
    match = re.search(r'<([^<>]+)>', email_address)
    if match:
        email_address = match.group(1)
    
    # Extract domain using regex
    match = re.search(r'@([^@]+)$', email_address)
    
    if match:
        return match.group(1).lower()
    
    return ""

def is_trusted_domain(domain: str, trusted_domains: List[str] = None) -> bool:
    """Check if a domain is in the list of trusted domains.
    
    Args:
        domain: The domain to check
        trusted_domains: Optional list of trusted domains (uses default if None)
        
    Returns:
        True if the domain is trusted, False otherwise
    """
    if trusted_domains is None:
        trusted_domains = DEFAULT_TRUSTED_DOMAINS
    
    # Check for exact domain match
    if domain.lower() in [d.lower() for d in trusted_domains]:
        return True
    
    # Check for TLD match (e.g., if 'edu' is trusted, then 'university.edu' is trusted)
    domain_parts = domain.lower().split('.')
    if len(domain_parts) >= 2:
        tld = domain_parts[-1]  # Last part (com, org, etc)
        if len(domain_parts) >= 3:
            # Check for country-specific domains (e.g., .co.uk)
            extended_tld = f"{domain_parts[-2]}.{tld}"
            if extended_tld in trusted_domains:
                return True
        
        # Academic or government domains often use the pattern subdomain.edu or subdomain.gov
        if tld in trusted_domains:
            return True
    
    return False

def check_for_suspicious_patterns(subject: str, body: str) -> List[str]:
    """Check email content for suspicious patterns.
    
    Args:
        subject: The email subject
        body: The email body
        
    Returns:
        List of suspicious patterns found
    """
    found_patterns = []
    combined_text = (subject + " " + body).lower()
    
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            found_patterns.append(pattern)
    
    return found_patterns

def analyze_email_security(email: Dict) -> Dict:
    """Analyze an email for security concerns.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    sender = email.get('from', '')
    subject = email.get('subject', '')
    body = email.get('body', '')
    
    # Extract domain from sender
    domain = extract_domain_from_email(sender)
    
    # Check if domain is trusted
    trusted = False
    if domain:
        trusted = is_trusted_domain(domain)
    
    # Check for suspicious patterns
    suspicious_patterns = check_for_suspicious_patterns(subject, body)
    
    # Determine overall risk level
    if not domain:
        risk_level = "Unknown"
    elif trusted and not suspicious_patterns:
        risk_level = "Low"
    elif trusted and suspicious_patterns:
        risk_level = "Medium"
    elif not trusted and not suspicious_patterns:
        risk_level = "Medium"
    else:
        risk_level = "High"
    
    return {
        'sender_domain': domain,
        'is_trusted_domain': trusted,
        'suspicious_patterns': suspicious_patterns,
        'risk_level': risk_level
    }

def batch_analyze_emails(emails: List[Dict]) -> List[Dict]:
    """Analyze a batch of emails for security concerns.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    for email in emails:
        security_analysis = analyze_email_security(email)
        email['security_analysis'] = security_analysis
    
    return emails