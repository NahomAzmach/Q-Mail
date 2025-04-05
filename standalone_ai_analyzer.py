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

# Common trusted email domains
TRUSTED_DOMAINS = [
    # Google/Alphabet
    "gmail.com", "googlemail.com", "google.com",
    
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "hotmail.com",
    
    # Apple
    "apple.com", "icloud.com", "me.com",
    
    # Amazon
    "amazon.com",
    
    # Meta (Facebook)
    "facebook.com", "instagram.com", "messenger.com", 
    
    # Microsoft subsidiary
    "linkedin.com",
    
    # Twitter
    "twitter.com",
    
    # Adobe
    "adobe.com",
    
    # IBM
    "ibm.com",
    
    # Oracle
    "oracle.com",
    
    # Intel
    "intel.com",
    
    # Cisco
    "cisco.com",
    
    # Salesforce
    "salesforce.com",
    
    # PayPal
    "paypal.com",
    
    # Dropbox
    "dropbox.com",
    
    # Uber
    "uber.com",
    
    # Airbnb
    "airbnb.com",
    
    # Netflix
    "netflix.com",
    
    # Spotify
    "spotify.com",
    
    # Yahoo
    "yahoo.com",
    
    # AOL
    "aol.com",
    
    # Other popular providers
    "protonmail.com", "zoho.com", "mail.com", "yandex.com",
    
    # Telecom and Media Providers
    "verizon.com", "comcast.com", "att.com",
    
    # Other popular services
    "github.com", "gitlab.com", "stackoverflow.com", "slack.com", "zoom.us",
    
    # Financial services
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "capitalone.com",
    "amex.com", "discover.com", "visa.com", "mastercard.com",
    
    # Educational, Government and Military
    "edu", "gov", "mil"
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
    """
    Extract the domain from an email address.
    
    This function handles various email formats including:
    - Standard addresses: user@example.com
    - Display name format: "User Name <user@example.com>"
    - Multiple addresses: "primary@example.com, secondary@example.com"
    
    Args:
        email_address: The email address string to process
        
    Returns:
        The domain portion of the email address, or empty string if none found
    """
    if not email_address:
        return ""
    
    # Handle cases where email might contain a display name with angle brackets
    match = re.search(r'<([^<>]+@[^<>]+)>', email_address)
    if match:
        email_address = match.group(1)
    
    # Handle cases with multiple email addresses (use the first one)
    if ',' in email_address:
        email_address = email_address.split(',')[0].strip()
    
    # Clean up any remaining quotes or extra characters
    email_address = email_address.strip('"\'')
    
    # Extract domain using regex
    match = re.search(r'@([^@\s]+)$', email_address)
    
    if match:
        domain = match.group(1).lower()
        # Some additional cleaning in case of trailing punctuation
        domain = domain.rstrip('.')
        return domain
    
    # If we got this far and still haven't found a domain,
    # check if the entire string might be a domain (no @ symbol)
    if '.' in email_address and '@' not in email_address:
        return email_address.lower()
    
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
        r'\b(?:i|we|they|he|she)\s+(?:is|has|have|am)\s+(?:is|has|have|am)\b'  # Verb agreement errors
    ]
    
    # Only check for grammatical errors if the body has enough content
    if len(body) > 100:  # Only check substantial emails
        for pattern in grammar_patterns:
            matches = re.findall(pattern, body)
            grammatical_errors += len(matches)
        
        # Calculate error density (errors per character)
        error_density = grammatical_errors / max(1, len(body)) * 1000
        
        # Only flag if the error density is high enough (more than 1 error per 1000 chars)
        if error_density > 1.0 and grammatical_errors > 3:
            suspicious_elements.append({
                "type": "grammatical_errors",
                "details": f"Found {grammatical_errors} potential grammatical errors",
                "significance": "High density of grammatical errors is common in phishing emails"
            })
    
    return suspicious_elements

def calculate_risk_level(
    is_trusted_domain: bool,
    suspicious_elements: List[Dict[str, Any]],
    sender_domain: str = ""
) -> Tuple[str, float]:
    """
    Calculate the overall risk level based on analysis results.
    
    Args:
        is_trusted_domain: Whether the sender domain is trusted
        suspicious_elements: List of detected suspicious elements
        sender_domain: The sender's domain (for additional checks)
        
    Returns:
        Risk level as string and a security score (10 being most secure)
    """
    # Start with base score - assume neutral initially
    risk_score = 0
    
    # Major email providers get a strong trust bonus
    major_email_providers = [
        "gmail.com", "googlemail.com", "google.com", 
        "outlook.com", "hotmail.com", "live.com", "microsoft.com",
        "yahoo.com", "icloud.com", "me.com", "protonmail.com"
    ]
    
    # Check if the domain is one of the major providers, even if is_trusted_domain is False
    # This ensures we don't miss trusted providers due to implementation issues
    is_major_provider = sender_domain in major_email_providers
    
    # If the is_trusted_domain flag didn't catch it but it's a major provider, override
    if is_major_provider:
        is_trusted_domain = True
    
    # Force override for Gmail and other major Google domains
    if sender_domain in ["gmail.com", "googlemail.com", "google.com"]:
        is_trusted_domain = True
        is_major_provider = True
    
    # Apply trust bonuses
    if is_trusted_domain:
        # Give major providers a stronger bonus
        if is_major_provider:
            risk_score -= 25  # Higher trust for major email providers
        else:
            risk_score -= 15  # Standard trust for other trusted domains
    else:
        # Unknown domains start with a penalty
        risk_score += 20
    
    # Check for suspicious keywords - if keywords are common security terms, reduce penalty
    common_security_terms = ["security", "alert", "notification", "update", "verify", "confirm"]
    
    # Track whether we've applied security term adjustment
    security_term_adjusted = False
    
    # Adjust for suspicious elements
    for element in suspicious_elements:
        if element["type"] == "suspicious_keywords":
            keyword_penalty = min(element["count"] * 5, 30)
            
            # Reduce penalty if keywords contain security terms and we haven't adjusted yet
            if not security_term_adjusted and is_trusted_domain:
                for term in common_security_terms:
                    if term in element.get("details", "").lower():
                        keyword_penalty = max(0, keyword_penalty - 15)  # Reduce penalty
                        security_term_adjusted = True
                        break
                        
            risk_score += keyword_penalty
            
        elif element["type"] == "suspicious_patterns":
            pattern_penalty = min(len(element.get("patterns", [])) * 8, 30)
            
            # Reduce penalty for trusted domains
            if is_trusted_domain and is_major_provider:
                pattern_penalty = max(0, pattern_penalty - 15)
                
            risk_score += pattern_penalty
            
        elif element["type"] == "suspicious_urls":
            url_penalty = min(len(element.get("urls", [])) * 15, 50)
            
            # Reduce penalty for trusted domains
            if is_trusted_domain and is_major_provider:
                url_penalty = max(0, url_penalty - 20)
                
            risk_score += url_penalty
            
        elif element["type"] == "grammatical_errors":
            # If trusted domain, significantly reduce grammar error penalty
            if is_trusted_domain:
                if is_major_provider:
                    risk_score += 5  # Minimal penalty for major providers
                else:
                    risk_score += 10  # Reduced penalty for trusted domains
            else:
                risk_score += 20
    
    # Convert risk score to a 0-10 scale
    # Higher risk_score means more suspicious, so we invert it for our 0-10 scale
    # where 10 is most secure
    security_score = max(0, min(10, 10 - (risk_score / 10)))
    
    # For major providers, enforce higher minimum scores
    if is_major_provider:
        if sender_domain in ["gmail.com", "googlemail.com", "google.com"]:
            security_score = max(security_score, 8.0)  # Google domains get at least 8/10
        else:
            security_score = max(security_score, 7.0)  # Other major providers get at least 7/10
    
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
        
        # Check if domain is in our trusted domains list
        is_trusted_domain = sender_domain in TRUSTED_DOMAINS
        
        # Special handling for Gmail and other major providers to ensure they're always trusted
        major_email_providers = [
            "gmail.com", "googlemail.com", "google.com", 
            "outlook.com", "hotmail.com", "live.com", "microsoft.com",
            "yahoo.com", "icloud.com", "me.com", "protonmail.com"
        ]
        
        # Additional verification for major providers - force trust them
        if sender_domain in major_email_providers:
            is_trusted_domain = True
        
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
        risk_level_and_score = calculate_risk_level(is_trusted_domain, suspicious_elements, sender_domain)
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
            "domain": sender_domain,  # Add domain key for template compatibility
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
        # Extract domain even in error case
        sender_domain = extract_domain_from_email(email_data.get('from', ''))
        
        # Return a basic analysis in case of error
        return {
            "sender_domain": sender_domain,
            "domain": sender_domain,  # Add domain key for template compatibility
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
                # Extract domain
                sender_domain = extract_domain_from_email(email.get('from', ''))
                
                # Add a basic error analysis
                email["security_analysis"] = {
                    "sender_domain": sender_domain,
                    "domain": sender_domain,
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
            # Extract domain for each email
            sender_domain = extract_domain_from_email(email.get('from', ''))
            
            email["security_analysis"] = {
                "sender_domain": sender_domain,
                "domain": sender_domain,
                "is_trusted_domain": False,
                "suspicious_patterns": ["Batch analysis error"],
                "security_score": 5,  # Default middle score for errors
                "risk_level": "Unknown",
                "explanation": f"An error occurred during batch analysis: {str(e)}",
                "recommendations": "• Consider manual inspection of these emails"
            }
        
        return emails

def ensure_domain_field_and_trusted_domains(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure the security analysis has both domain fields and trusted domains are recognized.
    
    Args:
        result: The security analysis result to process
        
    Returns:
        Updated security analysis with domain field and forced trust rules applied
    """
    # Force-trusted domains with minimum security scores
    TRUSTED_DOMAINS = {
        'gmail.com': 8.0,
        'google.com': 8.0,
        'accounts.google.com': 8.0,
        'mail.google.com': 8.0,
        'drive.google.com': 8.0,
        'docs.google.com': 8.0,
        'apple.com': 8.0,
        'icloud.com': 7.5,
        'outlook.com': 7.0,
        'microsoft.com': 7.5,
        'yahoo.com': 7.0,
        'live.com': 7.0,
        'hotmail.com': 7.0,
        'aol.com': 7.0,
        'proton.me': 8.0,
        'protonmail.com': 8.0
    }
    
    # Make a copy to avoid modifying the original directly
    processed = result.copy() if result else {}
    
    # Add default values for any missing fields to ensure consistency
    defaults = {
        'sender_domain': '',
        'domain': '',
        'is_trusted_domain': False,
        'suspicious_patterns': [],
        'security_score': 5.0,
        'risk_level': 'Unknown',
        'explanation': '',
        'recommendations': ''
    }
    
    # Apply defaults for any missing fields
    for field, default_value in defaults.items():
        if field not in processed:
            processed[field] = default_value
    
    # Ensure domain fields are consistent
    if processed['sender_domain'] and not processed['domain']:
        processed['domain'] = processed['sender_domain']
    elif processed['domain'] and not processed['sender_domain']:
        processed['sender_domain'] = processed['domain']
    
    # Handle trusted domains logic
    domain = processed['sender_domain']
    
    # TLD credibility scores
    TRUSTED_TLDS = {
        'com': 0.5,    # Commercial, widely used
        'org': 0.5,    # Non-profit organizations
        'edu': 1.0,    # Educational institutions (higher trust)
        'gov': 1.0,    # Government agencies (higher trust)
        'net': 0.3,    # Network services
        'co': 0.3,     # Commercial alternative
        'io': 0.3      # Technology companies
    }
    
    # Check for exact domain match first
    trusted_match = None
    min_score = 5.0
    tld_bonus = 0
    
    # Extract TLD from domain for additional trust assessment
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        tld = domain_parts[-1].lower()
        if tld in TRUSTED_TLDS:
            tld_bonus = TRUSTED_TLDS[tld]
    
    if domain in TRUSTED_DOMAINS:
        trusted_match = domain
        min_score = TRUSTED_DOMAINS[domain]
    else:
        # Check if it's a subdomain of a trusted domain
        if len(domain_parts) > 2:
            # Try to match the main domain (e.g., "google.com" from "accounts.google.com")
            potential_main_domain = '.'.join(domain_parts[-2:])
            if potential_main_domain in TRUSTED_DOMAINS:
                trusted_match = potential_main_domain
                min_score = TRUSTED_DOMAINS[potential_main_domain]
                # Slightly reduce the score for subdomains we don't explicitly trust
                if domain not in TRUSTED_DOMAINS:
                    min_score = max(5.0, min_score - 0.5)
    
    # Apply TLD bonus if no exact domain match was found
    tld_note = ""
    if not trusted_match and tld_bonus > 0:
        # Only apply TLD bonus if the domain wasn't already trusted
        new_score = min(10.0, processed['security_score'] + tld_bonus)
        if new_score > processed['security_score']:
            processed['security_score'] = new_score
            tld_note = f" [TRUSTED TLD BONUS: +{tld_bonus}]"
    
    if trusted_match:
        # Mark as trusted
        processed['is_trusted_domain'] = True
        
        # Ensure minimum security score
        if processed['security_score'] < min_score:
            processed['security_score'] = min_score
            
            # Add trusted domain note to explanation if not already there
            if trusted_match == domain:
                trusted_prefix = f"[TRUSTED DOMAIN: {domain}]"
            else:
                trusted_prefix = f"[TRUSTED SUBDOMAIN OF {trusted_match}: {domain}]"
                
            if trusted_prefix not in processed['explanation']:
                processed['explanation'] = f"{trusted_prefix}{tld_note} {processed['explanation']}"
    elif tld_note and tld_note not in processed['explanation']:
        # Add TLD trust note if applicable
        processed['explanation'] = f"{tld_note} {processed['explanation']}"
    
    # Ensure risk level matches security score
    score = processed['security_score']
    if score >= 8:
        processed['risk_level'] = "Secure"
    elif score >= 6:
        processed['risk_level'] = "Probably Safe"
    elif score >= 4:
        processed['risk_level'] = "Suspicious"
    elif score >= 2:
        processed['risk_level'] = "Unsafe"
    else:
        processed['risk_level'] = "Dangerous"
    
    return processed

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
    result = analyze_email_with_rules(email)
    return ensure_domain_field_and_trusted_domains(result)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns.
    This is the main function to be called by the application.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    analyzed_emails = batch_analyze_emails_with_rules(emails)
    
    # Apply trusted domain logic to each email's security analysis
    for email in analyzed_emails:
        if 'security_analysis' in email:
            email['security_analysis'] = ensure_domain_field_and_trusted_domains(email['security_analysis'])
    
    return analyzed_emails