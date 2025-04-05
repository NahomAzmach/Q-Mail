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
    
    # Check for suspicious patterns in the subject line only
    rule_based_suspicious_patterns = check_for_suspicious_patterns(subject, '')
    
    # Now get AI analysis on headers only
    ai_analysis = analyze_email_with_openai_headers_only(email_data)
    
    # Combine the analyses: We'll use AI analysis as base but adjust the security score
    # based on rule-based findings, and add any suspicious patterns found
    
    # Get original AI score
    ai_score = ai_analysis.get('security_score', 5.0)
    
    # Adjust score based on subject pattern findings (if AI missed them)
    # Each suspicious pattern reduces the score by 0.5 points, up to 2 points
    pattern_penalty = min(len(rule_based_suspicious_patterns) * 0.5, 2.0)
    adjusted_score = max(1.0, ai_score - pattern_penalty)
    
    # Update the AI analysis with our hybrid findings
    ai_analysis['security_score'] = adjusted_score
    
    # Add any suspicious patterns found by rule-based system that weren't detected by AI
    ai_suspicious_patterns = ai_analysis.get('suspicious_patterns', [])
    combined_patterns = list(ai_suspicious_patterns)
    
    for pattern in rule_based_suspicious_patterns:
        pattern_description = f"Suspicious pattern in subject: {pattern}"
        if pattern_description not in combined_patterns:
            combined_patterns.append(pattern_description)
    
    ai_analysis['suspicious_patterns'] = combined_patterns
    
    # Update risk level based on adjusted score
    if adjusted_score >= 8:
        ai_analysis['risk_level'] = "Secure"
    elif adjusted_score >= 5:
        ai_analysis['risk_level'] = "Cautious"
    elif adjusted_score >= 2:
        ai_analysis['risk_level'] = "Unsafe"
    else:
        ai_analysis['risk_level'] = "Dangerous"
    
    # Add explanation about hybrid analysis
    if ai_analysis['explanation']:
        ai_analysis['explanation'] = "HYBRID ANALYSIS: " + ai_analysis['explanation']
        if rule_based_suspicious_patterns:
            ai_analysis['explanation'] += f"\n\nAdditional suspicious patterns detected in subject: {', '.join(rule_based_suspicious_patterns)}"
    
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
        
        security_analysis = {
            "sender_domain": extract_domain_from_email(sender),
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
        # Fallback to rule-based analysis
        return analyze_email_with_rules(email_data)

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
    return hybrid_analyze_email(email)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns using hybrid approach.
    This is the main function to be called by the application.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with combined security analysis added
    """
    return batch_hybrid_analyze_emails(emails)