"""
Headers-only AI Email Analyzer with Hybrid Analysis.

This module provides a security analysis focusing ONLY on email headers for enhanced privacy.
It uses OpenAI for analysis but only sends the sender, subject, and date - never the email body.
It combines AI analysis with rule-based pattern detection for more comprehensive security scoring.
"""

import os
import time
import logging
import json
import re
import requests
from typing import Dict, List, Any, Optional

# Import standalone analyzer for rule-based analysis
from standalone_ai_analyzer import (
    analyze_email_with_rules, 
    batch_analyze_emails_with_rules,
    extract_domain_from_email,
    check_email_content,
    calculate_risk_level
)

# Import email security module for suspicious pattern detection
from email_security import check_for_suspicious_patterns

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_for_sketchy_patterns(text_content: str, trusted_domains: List[str] = None) -> Dict[str, Any]:
    """
    Check for sketchy patterns using the enhanced algorithm.
    
    Args:
        text_content: The text content to analyze
        trusted_domains: List of domains that should be considered trusted
        
    Returns:
        Dictionary with analysis results
    """
    # Define a list of suspicious keywords/phrases (enhanced from the provided algorithm)
    suspicious_keywords = [
        'final notice', 'last chance', 'act immediately', 'immediate attention', 'urgent action',
        'failure to pay', 'suspension', 'impoundment', 'legal actions', 'wage garnishment',
        'limited time', 'act now', 'expires soon', 'quickly', 'asap', 'emergency',
        'important notice', 'warning', 'alert', 'account suspended', 'security alert',
        'verify your account', 'confirm your identity', 'avoid penalties', 'prevent account closure',
        'official notice', 'final warning'
    ]
    
    # Set a reasonable threshold for how many keywords trigger a warning
    keyword_threshold = 2
    
    # Set default trusted domains if none provided
    if not trusted_domains:
        trusted_domains = [
            'gmail.com', 'google.com', 'apple.com', 'icloud.com', 'microsoft.com',
            'outlook.com', 'yahoo.com', 'live.com', 'hotmail.com', 'aol.com',
            'proton.me', 'protonmail.com', '.gov', '.edu'
        ]
    
    # Check for suspicious keywords in the text
    keyword_count = 0
    found_keywords = []
    for keyword in suspicious_keywords:
        if keyword.lower() in text_content.lower():
            keyword_count += 1
            found_keywords.append(keyword)
    
    # Extract URLs from the text using regex
    urls = re.findall(r'(https?://[^\s]+)', text_content)
    url_flag = False
    url_details = []
    safe_urls = []
    suspicious_urls = []
    
    for url in urls:
        # Extract the domain from the URL
        domain_match = re.search(r'https?://([^/]+)', url)
        domain = domain_match.group(1).lower() if domain_match else ''
        
        # Check if domain is trusted
        is_trusted = False
        for trusted_domain in trusted_domains:
            if trusted_domain in domain:
                is_trusted = True
                safe_urls.append(url)
                break
        
        if not is_trusted:
            url_flag = True
            suspicious_urls.append(url)
        
        url_details.append({"url": url, "domain": domain, "is_trusted": is_trusted})
    
    # Calculate a security score based on findings
    # Start with a neutral score of 5
    security_score = 5.0
    
    # Keyword penalties
    if keyword_count >= keyword_threshold:
        # Subtract 0.5 points per keyword found, up to 3 points
        security_score -= min(3.0, keyword_count * 0.5)
    
    # URL penalties
    if url_flag:
        # Subtract 1 point per suspicious URL, up to 4 points
        security_score -= min(4.0, len(suspicious_urls) * 1.0)
    
    # Urgency score adjustment - additional penalty if keywords suggest urgent action
    urgency_keywords = [
        'urgent', 'immediately', 'emergency', 'act now', 'last chance',
        'final', 'warning', 'limited time', 'expires soon'
    ]
    urgency_count = sum(1 for kw in urgency_keywords if kw.lower() in text_content.lower())
    if urgency_count > 0:
        security_score -= min(1.5, urgency_count * 0.5)
    
    # Determine if text is suspicious
    suspicious = (keyword_count >= keyword_threshold) or url_flag
    
    # Return detailed results
    return {
        "is_suspicious": suspicious,
        "security_score_adjustment": 5.0 - security_score,  # How many points to subtract
        "suspicious_keyword_count": keyword_count,
        "keywords_found": found_keywords,
        "urls_found": url_details,
        "suspicious_urls": suspicious_urls,
        "safe_urls": safe_urls,
        "suspicious_url_count": len(suspicious_urls)
    }

def hybrid_analyze_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze email using both rules-based and AI analysis, but only send headers to AI.
    This hybrid approach combines the strengths of both methods for better accuracy.
    
    Args:
        email_data: Dictionary containing email data
        
    Returns:
        Dictionary with combined security analysis results
    """
    # First, get rule-based analysis on headers and subject
    subject = email_data.get('subject', '')
    sender = email_data.get('from', '')
    sender_domain = extract_domain_from_email(sender)
    
    # Get list of trusted domains for our sketchy pattern detection
    trusted_domains = [
        'gmail.com', 'google.com', 'apple.com', 'icloud.com', 'microsoft.com',
        'outlook.com', 'yahoo.com', 'live.com', 'hotmail.com', 'aol.com',
        'proton.me', 'protonmail.com', '.gov', '.edu'
    ]
    
    # Use our enhanced sketchy pattern detection on the subject line
    # Convert trusted_domains list to non-None value to satisfy type checking
    sketchy_analysis = check_for_sketchy_patterns(subject, trusted_domains or [])
    
    # Also check for simple suspicious patterns as a backup
    rule_based_suspicious_patterns = check_for_suspicious_patterns(subject, '')
    
    # Now get AI analysis on headers only
    ai_analysis = analyze_email_with_openai_headers_only(email_data)
    
    # Combine the analyses: We'll use AI analysis as base but adjust the security score
    # based on enhanced pattern detection findings
    
    # Get original AI score
    ai_score = ai_analysis.get('security_score', 5.0)
    
    # Adjust score based on sketchy pattern findings
    sketchy_score_penalty = sketchy_analysis.get("security_score_adjustment", 0)
    
    # If sketchy analysis found nothing but simple rule-based did, use rule-based penalty as backup
    if sketchy_score_penalty == 0 and rule_based_suspicious_patterns:
        pattern_penalty = min(len(rule_based_suspicious_patterns) * 0.5, 2.0)
        adjusted_score = max(1.0, ai_score - pattern_penalty)
    else:
        # Apply sketchy analysis penalty
        adjusted_score = max(1.0, ai_score - sketchy_score_penalty)
    
    # Update the AI analysis with our hybrid findings
    ai_analysis['security_score'] = adjusted_score
    
    # Add any suspicious patterns found by rule-based system that weren't detected by AI
    ai_suspicious_patterns = ai_analysis.get('suspicious_patterns', [])
    combined_patterns = list(ai_suspicious_patterns)
    
    # Add patterns from sketchy analysis
    if sketchy_analysis.get("keywords_found"):
        keywords_found_str = ", ".join(sketchy_analysis["keywords_found"])
        pattern_description = f"Suspicious keywords in subject: {keywords_found_str}"
        if pattern_description not in combined_patterns:
            combined_patterns.append(pattern_description)
    
    # Add patterns from simple pattern detection as backup
    for pattern in rule_based_suspicious_patterns:
        pattern_description = f"Suspicious pattern in subject: {pattern}"
        if pattern_description not in combined_patterns:
            combined_patterns.append(pattern_description)
    
    ai_analysis['suspicious_patterns'] = combined_patterns
    
    # Update risk level based on adjusted score with more nuanced levels
    if adjusted_score >= 8:
        ai_analysis['risk_level'] = "Secure"
    elif adjusted_score >= 6:
        ai_analysis['risk_level'] = "Probably Safe"
    elif adjusted_score >= 4:
        ai_analysis['risk_level'] = "Suspicious"
    elif adjusted_score >= 2:
        ai_analysis['risk_level'] = "Unsafe"
    else:
        ai_analysis['risk_level'] = "Dangerous"
    
    # Add explanation about hybrid analysis
    explanation = "HYBRID ANALYSIS: "
    
    if ai_analysis.get('explanation'):
        explanation += ai_analysis['explanation']
    
    if sketchy_analysis.get("keywords_found"):
        explanation += f"\n\nSuspicious keywords detected in subject: {', '.join(sketchy_analysis['keywords_found'])}"
    
    if rule_based_suspicious_patterns and not sketchy_analysis.get("keywords_found"):
        explanation += f"\n\nAdditional suspicious patterns detected in subject: {', '.join(rule_based_suspicious_patterns)}"
    
    ai_analysis['explanation'] = explanation
    
    return ai_analysis

def analyze_email_with_openai_headers_only(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single email using OpenAI API with headers-only for privacy.
    
    Args:
        email_data: Dictionary containing email data
    
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Check if OpenAI API key is available
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not found in environment variables")
            return analyze_email_with_rules(email_data)
        
        # Get email details - ONLY headers, no body
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')
        date = email_data.get('date', '')
        
        # Extract domain for analysis
        sender_domain = extract_domain_from_email(sender)
        
        # Major email providers that should always be trusted
        major_email_providers = [
            "gmail.com", "googlemail.com", "google.com", 
            "outlook.com", "hotmail.com", "live.com", "microsoft.com",
            "yahoo.com", "icloud.com", "me.com", "protonmail.com"
        ]
        
        # Check if this is a major provider that we should always trust
        is_major_provider = sender_domain in major_email_providers
        
        # Create prompt for OpenAI using ONLY headers (no body content)
        prompt = f"""
        You are an expert email security analyst with deep knowledge of phishing tactics and email security threats.
        Analyze the following email header information for any signs of phishing, scams, or security concerns.
        DO NOT make assumptions about email content as you don't have access to the body for privacy reasons.
        
        EMAIL HEADER DETAILS:
        - From: {sender}
        - Sender Domain: {sender_domain}
        - Subject: {subject}
        - Date: {date}
        
        Analyze this email's security aspects by considering:
        1. Is the sender domain legitimate or suspicious? Look for typos, unusual TLDs, or domains known for abuse.
        2. Does the subject line contain suspicious patterns?
        3. Is this a known trusted domain (like google.com, microsoft.com, amazon.com, etc.)?
        4. Score the security from 1-10 where 10 is completely secure and 1 is definitely malicious.
        
        Return your analysis in a structured JSON format with these keys:
        - "is_trusted_sender": true/false based on sender domain legitimacy
        - "suspicious_patterns_detected": list of specific suspicious patterns found in the headers (empty if none) 
        - "security_score": a number from 1-10 (10 being most secure, 1 being most dangerous)
        - "risk_level": "Secure" (8-10), "Cautious" (5-7), "Unsafe" (2-4), or "Dangerous" (1)
        - "explanation": detailed reasoning for your assessment, focusing ONLY on the sender domain and header information
        - "recommendations": suggested actions for the recipient
        """
        
        # OpenAI is now installed by our packager_tool
        import openai
            
        # Initialize client with retry logic
        client = openai.OpenAI(api_key=api_key)
        
        try:
            # Use a shorter timeout and simpler model to avoid worker timeouts
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use a more stable model
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                timeout=3.5  # Shorter timeout
            )
            
            # Get response content
            analysis_text = response.choices[0].message.content
            
        except Exception as api_error:
            logger.warning(f"OpenAI API call failed: {str(api_error)}")
            return analyze_email_with_rules(email_data)
        
        # Parse JSON from response
        json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
        
        if json_match:
            try:
                analysis = json.loads(json_match.group(0))
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON from OpenAI response")
                return analyze_email_with_rules(email_data)
        else:
            # Try to parse as key-value pairs if no JSON is found
            try:
                analysis = {}
                lines = analysis_text.split('\n')
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        value = value.strip()
                        if key == 'security_score':
                            try:
                                analysis[key] = float(value)
                            except ValueError:
                                analysis[key] = 5  # Default
                        elif key == 'is_trusted_sender':
                            analysis[key] = value.lower() == 'true'
                        elif key == 'suspicious_patterns_detected':
                            # Try to parse as list
                            if '[' in value and ']' in value:
                                try:
                                    analysis[key] = json.loads(value)
                                except json.JSONDecodeError:
                                    analysis[key] = [x.strip() for x in value.strip('[]').split(',')]
                            else:
                                analysis[key] = [x.strip() for x in value.strip('[]').split(',')]
                        else:
                            analysis[key] = value
            except Exception as e:
                logger.warning(f"Failed to parse analysis from text: {str(e)}")
                return analyze_email_with_rules(email_data)
                
        # Ensure required fields are present
        required_fields = [
            "is_trusted_sender", 
            "suspicious_patterns_detected", 
            "security_score",
            "risk_level", 
            "explanation", 
            "recommendations"
        ]
        
        for field in required_fields:
            if field not in analysis:
                if field == "suspicious_patterns_detected":
                    analysis[field] = []
                elif field == "security_score":
                    analysis[field] = 5  # Default middle score
                else:
                    analysis[field] = "Not provided by analysis"
        
        # Determine risk level based on security score if not provided
        if "security_score" in analysis and (not analysis.get("risk_level") or analysis.get("risk_level") == "Not provided by analysis"):
            score = analysis["security_score"]
            if score >= 8:
                analysis["risk_level"] = "Secure"
            elif score >= 5:
                analysis["risk_level"] = "Cautious"
            elif score >= 2:
                analysis["risk_level"] = "Unsafe"
            else:
                analysis["risk_level"] = "Dangerous"
        
        # Create security analysis result
        # Ensure recommendations is a list or convert string to list
        recommendations = analysis.get("recommendations", "")
        if isinstance(recommendations, str):
            if recommendations and recommendations != "Not provided by analysis":
                recommendations = [recommendations]
            else:
                recommendations = ["Be cautious with emails from unfamiliar senders."]
                
        # Force-trust major email providers regardless of OpenAI analysis
        if is_major_provider:
            is_trusted = True
            # Ensure minimum security score for major providers
            security_score = max(analysis.get("security_score", 5), 8.0 if sender_domain == "gmail.com" else 7.0)
        else:
            is_trusted = analysis.get("is_trusted_sender", False)
            security_score = analysis.get("security_score", 5)
        
        # Extract sender domain
        sender_domain = extract_domain_from_email(sender)
        
        security_analysis = {
            "sender_domain": sender_domain,
            "domain": sender_domain,  # Add domain key for template compatibility
            "is_trusted_domain": is_trusted,
            "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
            "security_score": security_score,
            "risk_level": analysis.get("risk_level", "Unknown"),
            "explanation": analysis.get("explanation", ""),
            "recommendations": recommendations
        }
        
        # Add a note that this analysis is headers-only
        if security_analysis["explanation"]:
            security_analysis["explanation"] = "HEADERS-ONLY ANALYSIS: " + security_analysis["explanation"]
        
        return security_analysis
    
    except Exception as e:
        logger.error(f"Error in headers-only email analysis: {str(e)}")
        # Extract domain even when doing fallback
        sender_domain = extract_domain_from_email(email_data.get('from', ''))
        result = analyze_email_with_rules(email_data)
        
        # Ensure we have both domain fields in the fallback result
        if 'domain' not in result and 'sender_domain' in result:
            result['domain'] = result['sender_domain']
            
        # Force gmail.com to be trusted regardless of analysis
        if 'sender_domain' in result and result['sender_domain'] == 'gmail.com':
            result['is_trusted_domain'] = True
            
        return result

def batch_hybrid_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails using the hybrid approach (combining rule-based and AI).
    
    Args:
        emails: List of email dictionaries
    
    Returns:
        List of emails with hybrid security analysis added
    """
    try:
        # Check if OpenAI API key is available
        if not os.environ.get("OPENAI_API_KEY"):
            logger.warning("OPENAI_API_KEY not found in environment variables")
            return batch_analyze_emails_with_rules(emails)
        
        # Only process a limited number of emails with OpenAI to avoid timeouts
        max_ai_analysis = 3
        processed_count = 0
        analyzed_emails = []
        
        for email in emails:
            try:
                if processed_count < max_ai_analysis:
                    # Use hybrid analysis for the first few emails
                    security_analysis = hybrid_analyze_email(email)
                    processed_count += 1
                else:
                    # Use rule-based for the rest
                    security_analysis = analyze_email_with_rules(email)
                
                email["security_analysis"] = security_analysis
                analyzed_emails.append(email)
                
                # Add a small delay between API calls
                if processed_count < max_ai_analysis and processed_count < len(emails):
                    time.sleep(0.2)
                    
            except Exception as e:
                logger.error(f"Error analyzing email: {str(e)}")
                # Use rule-based analysis as fallback for this email
                email["security_analysis"] = analyze_email_with_rules(email)
                analyzed_emails.append(email)
        
        return analyzed_emails
        
    except Exception as e:
        logger.error(f"Error in batch email analysis: {str(e)}")
        # Fallback to rule-based analysis for all emails
        return batch_analyze_emails_with_rules(emails)

def batch_analyze_emails_with_openai_headers_only(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails using OpenAI API with headers-only for privacy.
    
    Args:
        emails: List of email dictionaries
    
    Returns:
        List of emails with security analysis added
    """
    try:
        # Check if OpenAI API key is available
        if not os.environ.get("OPENAI_API_KEY"):
            logger.warning("OPENAI_API_KEY not found in environment variables")
            return batch_analyze_emails_with_rules(emails)
        
        # Only process a limited number of emails with OpenAI to avoid timeouts
        # This is a limitation to keep the app responsive - only the first 3 emails use OpenAI
        max_ai_analysis = 3
        processed_count = 0
        analyzed_emails = []
        
        for email in emails:
            try:
                if processed_count < max_ai_analysis:
                    # Use OpenAI for the first few emails
                    security_analysis = analyze_email_with_openai_headers_only(email)
                    processed_count += 1
                else:
                    # Use rule-based for the rest
                    security_analysis = analyze_email_with_rules(email)
                
                email["security_analysis"] = security_analysis
                analyzed_emails.append(email)
                
                # Add a small delay between API calls
                if processed_count < max_ai_analysis and processed_count < len(emails):
                    time.sleep(0.2)
                    
            except Exception as e:
                logger.error(f"Error analyzing email: {str(e)}")
                # Use rule-based analysis as fallback for this email
                email["security_analysis"] = analyze_email_with_rules(email)
                analyzed_emails.append(email)
        
        return analyzed_emails
        
    except Exception as e:
        logger.error(f"Error in batch email analysis: {str(e)}")
        # Fallback to rule-based analysis for all emails
        return batch_analyze_emails_with_rules(emails)

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
    Analyze an email for security concerns using hybrid approach combining 
    rule-based and OpenAI API with headers-only for privacy.
    This is the main function to be called by the application.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with combined security analysis results
    """
    result = hybrid_analyze_email(email)
    return ensure_domain_field_and_trusted_domains(result)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns using hybrid approach.
    This is the main function to be called by the application.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with combined security analysis added
    """
    analyzed_emails = batch_hybrid_analyze_emails(emails)
    
    # Apply trusted domain logic to each email's security analysis
    for email in analyzed_emails:
        if 'security_analysis' in email:
            email['security_analysis'] = ensure_domain_field_and_trusted_domains(email['security_analysis'])
    
    return analyzed_emails