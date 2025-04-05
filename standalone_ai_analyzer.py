"""
Standalone AI Analyzer for Email Security

This module provides a self-contained email security analysis solution that doesn't
rely on external APIs. It uses advanced rule-based analysis to detect potential
security threats in emails.
"""

import re
import logging
from typing import Dict, List, Any, Tuple, Optional
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Common phishing keywords and phrases
SUSPICIOUS_KEYWORDS = [
    "urgent", "immediate action", "account suspended", "verify your account",
    "update your information", "click here", "login to verify", "confirm your identity",
    "unusual activity", "suspicious activity", "security alert", "your account has been",
    "password expired", "validate your account", "banking", "credit card", "tax refund",
    "lottery", "winner", "inheritance", "million", "prize", "claim", "urgent matter",
    "limited time", "act now", "expires", "deadline", "final notice", "wire transfer",
    "payment", "bank transfer", "western union", "money gram", "bitcoin", "cryptocurrency",
    "password reset", "access token", "login credentials", "security breach", "hack",
    "phishing", "nigerian", "foreign prince", "investor", "business proposal"
]

# Common trusted email domains (for demonstration)
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", 
    "protonmail.com", "aol.com", "zoho.com", "mail.com", "yandex.com",
    "microsoft.com", "apple.com", "amazon.com", "facebook.com", "google.com",
    "linkedin.com", "twitter.com", "instagram.com", "paypal.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citibank.com", "capitalone.com",
    "amex.com", "discover.com", "visa.com", "mastercard.com", "netflix.com",
    "hulu.com", "spotify.com", "github.com", "gitlab.com", "stackoverflow.com",
    "adobe.com", "dropbox.com", "salesforce.com", "slack.com", "zoom.us"
]

# Advanced detection patterns
SUSPICIOUS_PATTERNS = [
    # URLs with suspicious characteristics
    r'https?://(?:\d{1,3}\.){3}\d{1,3}\b',                           # IP instead of domain
    r'https?://[^/]*?\.(?:xyz|top|loan|club|work|date|kim|gq)\b',    # Suspicious TLDs
    r'https?://[^/]*?(?:url|link|site|website|web|click)\d+\.',      # Numbered domains
    
    # Misspelled domains of popular services
    r'https?://[^/]*?(?:paypa1|amaz[0o]n|g[0o]{2}g1e|faceb[0o]{2}k|netfl1x|micro[s5]oft)\.',
    
    # Urgency and fear tactics
    r'(?i)(?:urgent|immediately|alert|attention|important).*(?:action|required|needed|verify)',
    r'(?i)(?:account|security|password).*(?:suspended|compromised|hacked|at risk)',
    
    # Financial hooks
    r'(?i)(?:bank|credit\s*card|payment).*(?:verify|confirm|update|provide)',
    r'(?i)(?:inheritance|lottery|won|winner|prize|million|billion).*(?:claim|collect)',
    
    # Request for sensitive information
    r'(?i)(?:update|confirm|verify|validate).*(?:information|details|password|account)',
    r'(?i)(?:send|provide|enter).*(?:password|username|login|ssn|social security|credit card|cvv)',
    
    # Unusual sender behavior
    r'(?i)(?:foreign|prince|nigeria|investor|overseas).*(?:assistance|help|proposal|business)',
    r'(?i)(?:dear|hello|attention|greetings).*(?:customer|user|member|beneficiary)',
    
    # Grammatical tells
    r'(?i)(?:kindly|please|request).*(?:do\s*the\s*needful|revert back|reply back)'
]

# URL detection pattern
URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'

def extract_domain_from_email(email_address: str) -> str:
    """Extract the domain from an email address."""
    # Handle cases where email might contain a display name
    match = re.search(r'<([^<>]+)>', email_address)
    if match:
        email_address = match.group(1)
    
    # Extract domain using regex
    match = re.search(r'@([^@]+)$', email_address)
    
    if match:
        return match.group(1).lower()
    
    return ""

def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from a text."""
    urls = re.findall(URL_PATTERN, text)
    return urls

def analyze_url_safety(url: str) -> Tuple[bool, str]:
    """
    Analyze a URL for potential security risks.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Tuple of (is_suspicious, reason)
    """
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # Check for IP address domains
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return (True, "URL uses IP address instead of domain name")
    
    # Check for suspicious TLDs
    suspicious_tlds = ['xyz', 'top', 'loan', 'club', 'work', 'date', 'kim', 'gq']
    for tld in suspicious_tlds:
        if domain.endswith('.' + tld):
            return (True, f"URL uses suspicious top-level domain (.{tld})")
    
    # Check for misspelled popular domains
    common_misspellings = {
        'paypa1': 'paypal', 'amaz0n': 'amazon', 'g00gle': 'google', 
        'faceb00k': 'facebook', 'netfl1x': 'netflix', 'micr0soft': 'microsoft'
    }
    
    for misspelled, correct in common_misspellings.items():
        if misspelled in domain:
            return (True, f"URL contains possible misspelling of {correct}")
    
    # Check for excessively long subdomains
    if len(domain.split('.')) > 4:
        return (True, "URL contains unusually many subdomains")
    
    # Check for unusual path or query components
    if 'login' in parsed_url.path.lower() and ('redirect' in parsed_url.query.lower() or 'return' in parsed_url.query.lower()):
        return (True, "URL contains login with redirect parameters")
        
    return (False, "No obvious suspicious elements detected")

def check_email_content(subject: str, body: str) -> List[Dict[str, str]]:
    """
    Check email content for suspicious patterns and keywords.
    
    Args:
        subject: The email subject
        body: The email body
        
    Returns:
        List of detected suspicious elements with details
    """
    combined_text = (subject + " " + body).lower()
    suspicious_elements = []
    
    # Check for suspicious keywords
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in combined_text:
            found_keywords.append(keyword)
    
    if found_keywords:
        suspicious_elements.append({
            "type": "suspicious_keywords",
            "details": ", ".join(found_keywords[:10]),  # Limit to first 10 keywords
            "count": len(found_keywords)
        })
    
    # Check for suspicious patterns
    found_patterns = []
    for pattern in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            found_patterns.append({
                "pattern": pattern,
                "examples": matches[:2]  # Limit to first 2 examples
            })
    
    if found_patterns:
        suspicious_elements.append({
            "type": "suspicious_patterns",
            "details": f"Found {len(found_patterns)} suspicious patterns",
            "patterns": found_patterns[:5]  # Limit to first 5 patterns
        })
    
    # Check for URLs
    urls = extract_urls_from_text(combined_text)
    suspicious_urls = []
    
    for url in urls:
        is_suspicious, reason = analyze_url_safety(url)
        if is_suspicious:
            suspicious_urls.append({
                "url": url,
                "reason": reason
            })
    
    if suspicious_urls:
        suspicious_elements.append({
            "type": "suspicious_urls",
            "details": f"Found {len(suspicious_urls)} suspicious URLs",
            "urls": suspicious_urls[:5]  # Limit to first 5 suspicious URLs
        })
    
    # Additional checks for common phishing techniques
    grammatical_errors = 0
    grammar_patterns = [
        r'\b(?:a)\s+(?:a|e|i|o|u)\b',  # Article errors
        r'\b(?:is|are|was|were)\s+(?:is|are|was|were)\b',  # Double verbs
        r'\b(?:the|a|an)\s+(?:the|a|an)\b',  # Double articles
        r'(?<!\.)(?<!\?)\s+[a-z]',  # Capitalization errors after periods
        r'\b(?:i|we|they|he|she)\s+(?:is|has|have|am)\s+(?:is|has|have|am)\b'  # Verb agreement errors
    ]
    
    for pattern in grammar_patterns:
        matches = re.findall(pattern, body)
        grammatical_errors += len(matches)
    
    if grammatical_errors > 3:
        suspicious_elements.append({
            "type": "grammatical_errors",
            "details": f"Found {grammatical_errors} potential grammatical errors",
            "significance": "High number of grammatical errors is common in phishing emails"
        })
    
    return suspicious_elements

def calculate_risk_level(
    is_trusted_domain: bool,
    suspicious_elements: List[Dict[str, Any]]
) -> Tuple[str, float]:
    """
    Calculate the overall risk level based on analysis results.
    
    Args:
        is_trusted_domain: Whether the sender domain is trusted
        suspicious_elements: List of detected suspicious elements
        
    Returns:
        Risk level as string ("Low", "Medium", or "High")
    """
    # Start with base score
    risk_score = 0
    
    # Adjust for trusted domain
    if not is_trusted_domain:
        risk_score += 30
    
    # Adjust for suspicious elements
    for element in suspicious_elements:
        if element["type"] == "suspicious_keywords":
            risk_score += min(element["count"] * 5, 30)
            
        elif element["type"] == "suspicious_patterns":
            risk_score += min(len(element.get("patterns", [])) * 10, 40)
            
        elif element["type"] == "suspicious_urls":
            risk_score += min(len(element.get("urls", [])) * 15, 50)
            
        elif element["type"] == "grammatical_errors":
            risk_score += 20
    
    # Convert risk score to a 0-10 scale
    # Higher risk_score means more suspicious, so we invert it for our 0-10 scale
    # where 10 is most secure
    security_score = max(0, min(10, 10 - (risk_score / 10)))
    
    # Determine risk level based on the new scale
    if security_score >= 8:
        return ("Secure", security_score)
    elif security_score >= 5:
        return ("Cautious", security_score) 
    elif security_score >= 2:
        return ("Unsafe", security_score)
    else:
        return ("Dangerous", security_score)

def generate_recommendations(risk_level: str, suspicious_elements: List[Dict[str, Any]]) -> str:
    """
    Generate specific recommendations based on analysis.
    
    Args:
        risk_level: The calculated risk level
        suspicious_elements: List of detected suspicious elements
        
    Returns:
        Recommendations as a formatted string
    """
    recommendations = []
    
    # Base recommendations by risk level
    if risk_level == "Dangerous":
        recommendations.append("Do not respond to this email or click any links it contains")
        recommendations.append("Report this email as phishing to your email provider immediately")
        recommendations.append("If you've clicked any links or provided information, change your passwords immediately")
        recommendations.append("This email shows strong indicators of being a phishing attempt")
    
    elif risk_level == "Unsafe":
        recommendations.append("Do not respond to this email or click any links it contains")
        recommendations.append("Consider reporting this email as phishing to your email provider")
        recommendations.append("Contact the sender through a different, verified channel if you need to confirm")
    
    elif risk_level == "Cautious":
        recommendations.append("Exercise caution with this email")
        recommendations.append("Do not click on links or download attachments unless you're certain they're legitimate")
        recommendations.append("Contact the sender through a known, trusted channel to verify this communication if unsure")
    
    else:  # Secure
        recommendations.append("This email appears to be legitimate")
        recommendations.append("Follow standard security practices when interacting with this email")
        recommendations.append("Always verify the sender's identity if there's any doubt")
    
    # Add specific recommendations based on findings
    for element in suspicious_elements:
        if element["type"] == "suspicious_urls":
            recommendations.append("Never enter login credentials or personal information on websites accessed from email links")
            break
    
    has_keywords = any(e["type"] == "suspicious_keywords" for e in suspicious_elements)
    if has_keywords:
        recommendations.append("Be wary of urgent language or requests for sensitive information")
    
    # Format recommendations
    return "\n".join(f"• {rec}" for rec in recommendations)

def analyze_email_with_rules(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single email using advanced rule-based analysis.
    
    Args:
        email_data: Dictionary containing email data
    
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Get email details
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        
        # Extract and check sender domain
        sender_domain = extract_domain_from_email(sender)
        is_trusted_domain = sender_domain in TRUSTED_DOMAINS
        
        # Analyze email content
        suspicious_elements = check_email_content(subject, body)
        
        # Generate suspicious patterns list for display
        suspicious_patterns = []
        
        for element in suspicious_elements:
            if element["type"] == "suspicious_keywords":
                suspicious_patterns.append(f"Suspicious keywords: {element['details']}")
            elif element["type"] == "suspicious_urls":
                for url_info in element.get("urls", [])[:3]:  # Limit to 3 URLs
                    if isinstance(url_info, dict):
                        url = url_info.get("url", "unknown URL")
                        reason = url_info.get("reason", "unknown reason")
                        suspicious_patterns.append(f"Suspicious URL: {url} - {reason}")
                    else:
                        suspicious_patterns.append(f"Suspicious URL detected")
            elif element["type"] == "grammatical_errors":
                suspicious_patterns.append(f"Multiple grammatical errors detected ({element['details']})")
        
        # Calculate risk level and security score
        risk_level_and_score = calculate_risk_level(is_trusted_domain, suspicious_elements)
        risk_level, security_score = risk_level_and_score  # Unpack the tuple
        
        # Generate explanation
        explanation_parts = []
        
        if not is_trusted_domain:
            explanation_parts.append(f"The sender domain '{sender_domain}' is not recognized as a common trusted domain")
        else:
            explanation_parts.append(f"The sender domain '{sender_domain}' appears to be from a common email provider")
        
        if suspicious_patterns:
            explanation_parts.append("Suspicious elements detected in the email content:")
            for pattern in suspicious_patterns[:5]:  # Limit to 5 patterns
                explanation_parts.append(f"- {pattern}")
        else:
            explanation_parts.append("No obvious suspicious patterns detected in the email content")
            
        # Add security score explanation
        explanation_parts.append(f"Security score: {security_score:.1f}/10 - {risk_level}")
        
        explanation = "\n".join(explanation_parts)
        
        # Generate recommendations
        recommendations = generate_recommendations(risk_level, suspicious_elements)
        
        # Create security analysis result
        security_analysis = {
            "sender_domain": sender_domain,
            "is_trusted_domain": is_trusted_domain,
            "suspicious_patterns": suspicious_patterns,
            "security_score": security_score,
            "risk_level": risk_level,
            "explanation": explanation,
            "recommendations": recommendations
        }
        
        return security_analysis
    
    except Exception as e:
        logger.error(f"Error in rule-based email analysis: {str(e)}")
        # Return a basic analysis in case of error
        return {
            "sender_domain": extract_domain_from_email(email_data.get('from', '')),
            "is_trusted_domain": False,
            "suspicious_patterns": ["Analysis error - unable to process email"],
            "security_score": 5,  # Default middle score for errors
            "risk_level": "Unknown",
            "explanation": f"An error occurred during analysis: {str(e)}",
            "recommendations": "• Consider manual inspection of this email\n• Do not click on links or download attachments"
        }

def batch_analyze_emails_with_rules(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails using advanced rule-based analysis.
    
    Args:
        emails: List of email dictionaries
    
    Returns:
        List of emails with security analysis added
    """
    try:
        # Process emails one by one
        analyzed_emails = []
        
        for email in emails:
            try:
                # Add security analysis to the email
                security_analysis = analyze_email_with_rules(email)
                email["security_analysis"] = security_analysis
                analyzed_emails.append(email)
                    
            except Exception as e:
                logger.error(f"Error analyzing email: {str(e)}")
                # Add a basic error analysis
                email["security_analysis"] = {
                    "sender_domain": extract_domain_from_email(email.get('from', '')),
                    "is_trusted_domain": False,
                    "suspicious_patterns": ["Analysis error"],
                    "security_score": 5,  # Default middle score for errors
                    "risk_level": "Unknown",
                    "explanation": f"An error occurred during analysis: {str(e)}",
                    "recommendations": "• Consider manual inspection of this email"
                }
                analyzed_emails.append(email)
        
        return analyzed_emails
        
    except Exception as e:
        logger.error(f"Error in batch email analysis: {str(e)}")
        # Return original emails with basic error analysis
        for email in emails:
            email["security_analysis"] = {
                "sender_domain": extract_domain_from_email(email.get('from', '')),
                "is_trusted_domain": False,
                "suspicious_patterns": ["Batch analysis error"],
                "security_score": 5,  # Default middle score for errors
                "risk_level": "Unknown",
                "explanation": f"An error occurred during batch analysis: {str(e)}",
                "recommendations": "• Consider manual inspection of these emails"
            }
        
        return emails

# Public functions to be used by the main application
def analyze_email_security(email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze an email for security concerns.
    This is the main function to be called by the application.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    return analyze_email_with_rules(email)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns.
    This is the main function to be called by the application.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    return batch_analyze_emails_with_rules(emails)