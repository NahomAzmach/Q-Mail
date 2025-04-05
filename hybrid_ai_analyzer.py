"""
Hybrid AI Email Analyzer - Combines rule-based analysis with OpenAI integration.

This module provides a hybrid approach that first attempts to use OpenAI for analysis,
and falls back to an advanced rule-based system if the API is unavailable or fails.
This ensures reliable operation while still utilizing AI capabilities when possible.
"""

import os
import time
import logging
import json
import re
import requests
import urllib.parse
import concurrent.futures
from typing import Dict, List, Any, Tuple, Optional

# Import standalone analyzer for fallback
from standalone_ai_analyzer import (
    analyze_email_with_rules, 
    batch_analyze_emails_with_rules,
    extract_domain_from_email
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_email_with_openai(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single email using OpenAI API directly.
    
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
        
        # Get email details
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')
        
        # Extract domain
        sender_domain = extract_domain_from_email(sender)
        
        # Create prompt for OpenAI using only domain and headers (no body content)
        prompt = f"""
        You are an expert email security analyst with deep knowledge of phishing tactics and email security threats.
        Analyze the following email header information for any signs of phishing, scams, or security concerns.
        DO NOT make assumptions about email content as you don't have access to the body for privacy reasons.
        
        EMAIL HEADER DETAILS:
        - From: {sender}
        - Sender Domain: {sender_domain}
        - Subject: {subject}
        - Date: {email_data.get('date', '')}
        
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
        
        # Direct API call using requests instead of the OpenAI client
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=5  # Even shorter timeout to avoid worker timeouts
        )
        
        if response.status_code != 200:
            logger.warning(f"OpenAI API returned status code {response.status_code}")
            return analyze_email_with_rules(email_data)
        
        response_json = response.json()
        analysis_text = response_json["choices"][0]["message"]["content"]
        
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
                        if key == 'suspicious_patterns_detected' and value.startswith('[') and value.endswith(']'):
                            # Try to parse as a list
                            items = value[1:-1].split(',')
                            analysis[key] = [item.strip().strip('"\'') for item in items if item.strip()]
                        else:
                            analysis[key] = value
                
                # If we still couldn't parse anything useful
                if not analysis or 'risk_level' not in analysis:
                    logger.warning("Could not extract structured data from OpenAI response")
                    return analyze_email_with_rules(email_data)
            except Exception:
                logger.warning("Failed to parse key-value pairs from OpenAI response")
                return analyze_email_with_rules(email_data)
        
        # Ensure required fields are present with proper types
        if 'suspicious_patterns_detected' not in analysis or not isinstance(analysis['suspicious_patterns_detected'], list):
            analysis['suspicious_patterns_detected'] = []
        
        for field in ['is_trusted_sender', 'risk_level', 'explanation', 'recommendations']:
            if field not in analysis:
                analysis[field] = "Not provided by analysis"
                
        # Handle security score
        if 'security_score' not in analysis:
            analysis['security_score'] = 5  # Default middle score
        elif isinstance(analysis['security_score'], str):
            try:
                analysis['security_score'] = int(analysis['security_score'])
            except ValueError:
                analysis['security_score'] = 5  # Default if parsing fails
        
        # Determine risk level based on security score if not provided properly
        if not analysis.get("risk_level") or analysis.get("risk_level") == "Not provided by analysis":
            score = analysis["security_score"]
            if score >= 8:
                analysis["risk_level"] = "Secure"
            elif score >= 5:
                analysis["risk_level"] = "Cautious"
            elif score >= 2:
                analysis["risk_level"] = "Unsafe"
            else:
                analysis["risk_level"] = "Dangerous"
        
        # If is_trusted_sender is a string "true"/"false", convert to boolean
        if isinstance(analysis.get('is_trusted_sender'), str):
            analysis['is_trusted_sender'] = analysis['is_trusted_sender'].lower() == 'true'
        
        # Extract domain
        sender_domain = extract_domain_from_email(sender)
        
        # Create security analysis result
        security_analysis = {
            "sender_domain": sender_domain,
            "domain": sender_domain,  # Add domain for template compatibility
            "is_trusted_domain": analysis.get("is_trusted_sender", False),
            "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
            "security_score": analysis.get("security_score", 5),
            "risk_level": analysis.get("risk_level", "Unknown"),
            "explanation": analysis.get("explanation", ""),
            "recommendations": analysis.get("recommendations", "")
        }
        
        return security_analysis
    
    except Exception as e:
        logger.error(f"Error in AI email analysis: {str(e)}")
        # Fallback to rule-based analysis
        return analyze_email_with_rules(email_data)

def process_email(args):
    """
    Process a single email with either OpenAI or rule-based analysis.
    This function is designed to be used with ThreadPoolExecutor.
    
    Args:
        args: Tuple of (email, use_openai)
        
    Returns:
        Processed email with security analysis
    """
    email, use_openai = args
    try:
        if use_openai:
            security_analysis = analyze_email_with_openai(email)
        else:
            security_analysis = analyze_email_with_rules(email)
        
        email["security_analysis"] = security_analysis
        return email
    except Exception as e:
        logger.error(f"Error processing email: {str(e)}")
        # Fallback to rule-based analysis
        email["security_analysis"] = analyze_email_with_rules(email)
        return email

def batch_analyze_emails_with_openai(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails using OpenAI API.
    
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
            
        # Only process the first 3 emails with OpenAI to avoid timeouts
        max_ai_emails = min(3, len(emails))
        
        # Prepare tasks - first few with OpenAI, rest with rule-based
        tasks = [(email, i < max_ai_emails) for i, email in enumerate(emails)]
        
        # Process emails in parallel
        analyzed_emails = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(process_email, task) for task in tasks]
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    email = future.result()
                    analyzed_emails.append(email)
                except Exception as e:
                    logger.error(f"Thread error: {str(e)}")
                    # Fallback to rule-based analysis for any failed email
                    if len(analyzed_emails) < len(emails):
                        # Get the email that failed and add it with rule-based analysis
                        failed_email = emails[len(analyzed_emails)]
                        failed_email["security_analysis"] = analyze_email_with_rules(failed_email)
                        analyzed_emails.append(failed_email)
        
        # The emails may be out of order due to parallel processing
        # Sort them based on their original order if needed
        # This assumes emails have an index or other identifier
        
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
    
    # Check for exact domain match first
    trusted_match = None
    min_score = 5.0
    
    if domain in TRUSTED_DOMAINS:
        trusted_match = domain
        min_score = TRUSTED_DOMAINS[domain]
    else:
        # Check if it's a subdomain of a trusted domain
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            # Try to match the main domain (e.g., "google.com" from "accounts.google.com")
            potential_main_domain = '.'.join(domain_parts[-2:])
            if potential_main_domain in TRUSTED_DOMAINS:
                trusted_match = potential_main_domain
                min_score = TRUSTED_DOMAINS[potential_main_domain]
                # Slightly reduce the score for subdomains we don't explicitly trust
                if domain not in TRUSTED_DOMAINS:
                    min_score = max(5.0, min_score - 0.5)
    
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
                processed['explanation'] = f"{trusted_prefix} {processed['explanation']}"
    
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
    Tries OpenAI first, falls back to rules-based if needed.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Try OpenAI analysis
        result = analyze_email_with_openai(email)
    except Exception as e:
        logger.error(f"Error in OpenAI analysis, falling back to rule-based: {str(e)}")
        result = analyze_email_with_rules(email)
    
    # Apply domain and trust logic to ensure consistent results
    return ensure_domain_field_and_trusted_domains(result)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns.
    Tries OpenAI first, falls back to rules-based if needed.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    analyzed_emails = batch_analyze_emails_with_openai(emails)
    
    # Apply domain and trust logic to each email's security analysis
    for email in analyzed_emails:
        if 'security_analysis' in email:
            email['security_analysis'] = ensure_domain_field_and_trusted_domains(email['security_analysis'])
    
    return analyzed_emails