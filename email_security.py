"""Email security module for validating email senders and content."""
import re
import logging
import ipaddress
from typing import Dict, List, Tuple, Optional, Union, Any
from urllib.parse import urlparse

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

# List of suspicious TLDs often used for spam/phishing
SUSPICIOUS_TLDS = [
    'xyz', 'top', 'click', 'club', 'vip', 'win', 'loan', 'online', 'gq', 'ml', 'cf', 'tk', 'ga'
]

# QMail Trust Score categories
TRUST_SCORE_CATEGORIES = {
    10: {"flag": "✅", "label": "Secure", "description": "Everything checks out. Verified sender, clean links, no suspicious signs."},
    8: {"flag": "🟢", "label": "Safe", "description": "Minor quirks, but overall looks trustworthy. Possibly a custom domain or mild formatting."},
    5: {"flag": "🟠", "label": "Cautious", "description": "Some red flags detected — proceed carefully. Medium-risk sender or questionable links/text."},
    2: {"flag": "🔴", "label": "Unsafe", "description": "High probability of phishing or scam. Multiple signs of deception present."},
    0: {"flag": "☠️", "label": "Dangerous", "description": "Definitely malicious. Known scammer, blacklisted links, fake domains, etc."}
}

# Common email patterns indicating phishing or spam
SUSPICIOUS_PATTERNS = [
    # Urgency and pressure tactics
    r'urgent.*action', 
    r'act now',
    r'immediate attention',
    r'account suspension',
    r'limited time',
    r'expir(e|ing|ed)',
    
    # Account and security issues
    r'verify.*account',
    r'confirm.*identity',
    r'suspicious.*activity',
    r'unusual.*login',
    r'password.*reset',
    r'security.*breach',
    
    # Financial hooks
    r'won.*lottery',
    r'million.*dollar',
    r'claim.*prize',
    r'unclaimed.*funds',
    r'inheritance',
    r'investment opportunity',
    
    # Action prompts
    r'click.*here',
    r'log in.*now', 
    r'sign in.*now',
    r'update.*payment',
    r'update.*account',
    r'confirm.*details',
    
    # Request for sensitive information
    r'confirm.*password',
    r'provide.*credentials',
    r'send.*information',
    r'verify.*payment',
    r'verify.*identity',
    
    # Threats
    r'account.*suspended',
    r'account.*terminated',
    r'legal.*action',
    r'failure to respond',
    r'will be closed',
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

def extract_links_from_text(text: str) -> List[str]:
    """Extract URLs from text using regex.
    
    Args:
        text: Text to search for URLs
        
    Returns:
        List of found URLs
    """
    # Basic URL regex pattern
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(url_pattern, text)

def analyze_link_safety(links: List[str]) -> Dict[str, Any]:
    """Analyze links for suspicious characteristics.
    
    Args:
        links: List of URLs to analyze
        
    Returns:
        Dict with link analysis results
    """
    if not links:
        return {"safe": True, "issues": []}
    
    issues = []
    
    for link in links:
        # Check for IP addresses in URLs
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
            issues.append(f"IP address used in URL: {link}")
        
        try:
            # Parse the URL
            parsed_url = urlparse(link)
            
            # Extract domain
            domain = parsed_url.netloc
            
            # Check for suspicious TLDs
            domain_parts = domain.split('.')
            if len(domain_parts) > 1:
                tld = domain_parts[-1].lower()
                if tld in SUSPICIOUS_TLDS:
                    issues.append(f"Suspicious TLD (.{tld}) in URL: {link}")
            
            # Check for encoded characters
            if '%' in parsed_url.path or '%' in domain:
                issues.append(f"Encoded characters in URL: {link}")
                
        except Exception as e:
            logger.warning(f"Error analyzing URL {link}: {str(e)}")
            issues.append(f"Malformed URL: {link}")
    
    return {
        "safe": len(issues) == 0,
        "issues": issues
    }

def calculate_qmail_trust_score(domain: str, is_trusted: bool, suspicious_patterns: List[str], 
                               body: str, subject: str) -> Dict[str, Any]:
    """Calculate QMail Trust Score for an email.
    
    Args:
        domain: Sender's domain
        is_trusted: Whether domain is trusted
        suspicious_patterns: List of suspicious patterns found
        body: Email body text
        subject: Email subject
        
    Returns:
        Dict with score and details
    """
    # Start with a perfect score
    score = 10
    deductions = []
    
    # Sender Email Analysis
    if not domain:
        score -= 2
        deductions.append("Missing sender domain (-2)")
    elif is_trusted:
        # It's a trusted domain, no deduction
        pass
    else:
        # Custom domain, check if it has a suspicious TLD
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            tld = domain_parts[-1].lower()
            if tld in SUSPICIOUS_TLDS:
                score -= 2
                deductions.append(f"Suspicious TLD (.{tld}) (-2)")
            else:
                # Just a non-standard domain
                score -= 1
                deductions.append("Custom domain (-1)")
    
    # Link Analysis
    links = extract_links_from_text(body)
    link_analysis = analyze_link_safety(links)
    if not link_analysis["safe"]:
        for issue in link_analysis["issues"]:
            if "IP address" in issue:
                score -= 3
                deductions.append("IP address in URL (-3)")
            elif "Suspicious TLD" in issue:
                score -= 2
                deductions.append("Link domain with suspicious TLD (-2)")
            elif "Encoded characters" in issue:
                score -= 2
                deductions.append("Encoded/obfuscated URL (-2)")
    
    # Text Analysis
    if suspicious_patterns:
        # Deduct for urgent/bait phrases
        urgent_patterns = [p for p in suspicious_patterns if 
                         any(word in p for word in ['urgent', 'act now', 'immediate', 'verify', 'confirm'])]
        if urgent_patterns:
            score -= 2
            deductions.append("Urgent/bait phrases detected (-2)")
        
        # Check for multiple suspicious patterns
        if len(suspicious_patterns) >= 3:
            score -= 3
            deductions.append("Multiple suspicious phrases detected (-3)")
        elif len(suspicious_patterns) > 0:
            score -= 1
            deductions.append("Suspicious phrasing detected (-1)")
    
    # Grammar/Formatting Check (basic)
    if body:
        # Check for ALL CAPS sections
        if re.search(r'[A-Z]{5,}', body):
            score -= 1
            deductions.append("Excessive formatting (ALL CAPS) (-1)")
            
        # Check for excessive punctuation
        if re.search(r'[!?]{3,}', body + subject):
            score -= 1
            deductions.append("Excessive punctuation (!!! or ???) (-1)")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Determine which category the score falls into
    category_threshold = None
    for threshold in sorted(TRUST_SCORE_CATEGORIES.keys(), reverse=True):
        if score >= threshold:
            category_threshold = threshold
            break
    
    if category_threshold is None:
        category_threshold = min(TRUST_SCORE_CATEGORIES.keys())
    
    category = TRUST_SCORE_CATEGORIES[category_threshold]
    
    return {
        "score": score,
        "deductions": deductions,
        "category_threshold": category_threshold,
        "flag": category["flag"],
        "label": category["label"],
        "description": category["description"]
    }

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
    
    # Calculate QMail Trust Score
    qmail_score = calculate_qmail_trust_score(domain, trusted, suspicious_patterns, body, subject)
    
    # Determine overall risk level based on QMail score
    if qmail_score["score"] >= 8:
        risk_level = "Low"
    elif qmail_score["score"] >= 5:
        risk_level = "Medium"
    else:
        risk_level = "High"
    
    return {
        'sender_domain': domain,
        'is_trusted_domain': trusted,
        'suspicious_patterns': suspicious_patterns,
        'risk_level': risk_level,
        'qmail_score': qmail_score
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