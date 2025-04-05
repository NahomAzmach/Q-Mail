"""
Simple AI Email Analyzer using OpenAI directly.
This module provides a more streamlined approach to email analysis using OpenAI's API directly,
without the complexity of LangChain or LangGraph.
"""
import os
import time
import logging
import json
import re
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import rules-based analysis as fallback
from email_security import batch_analyze_emails as rule_based_batch_analysis
from email_security import analyze_email_security as rule_based_analysis

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

def analyze_email_with_openai(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single email using OpenAI API directly.
    
    Args:
        email_data: Dictionary containing email data
    
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Import OpenAI library
        try:
            import openai
        except ImportError:
            logger.error("OpenAI library not installed. Please install with 'pip install openai'")
            return rule_based_analysis(email_data)
        
        # Get email details
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        
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
        
        # Call OpenAI API with retries and error handling
        max_retries = 2
        retry_delay = 1.0
        success = False
        analysis_text = ""
        
        for attempt in range(max_retries + 1):
            try:
                # Simple direct call to OpenAI API
                api_key = os.environ.get("OPENAI_API_KEY")
                if not api_key:
                    logger.error("OPENAI_API_KEY not found in environment variables")
                    return rule_based_analysis(email_data)
                
                client = openai.OpenAI(api_key=api_key)
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",  # Use a more stable model
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    timeout=3.5  # Shorter timeout
                )
                
                # Get response content
                analysis_text = response.choices[0].message.content
                success = True
                break
            except Exception as e:
                logger.warning(f"OpenAI API call failed (attempt {attempt+1}/{max_retries+1}): {str(e)}")
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error(f"All OpenAI API call attempts failed: {str(e)}")
                    raise
        
        if not success:
            return rule_based_analysis(email_data)
        
        # Parse JSON from response
        json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
        
        if json_match:
            try:
                analysis = json.loads(json_match.group(0))
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON from OpenAI response")
                return rule_based_analysis(email_data)
        else:
            logger.warning("No JSON found in OpenAI response")
            return rule_based_analysis(email_data)
        
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
        if "security_score" in analysis and not analysis.get("risk_level") or analysis.get("risk_level") == "Not provided by analysis":
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
                
        security_analysis = {
            "sender_domain": extract_domain_from_email(sender),
            "is_trusted_domain": analysis.get("is_trusted_sender", False),
            "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
            "security_score": analysis.get("security_score", 5),
            "risk_level": analysis.get("risk_level", "Unknown"),
            "explanation": analysis.get("explanation", ""),
            "recommendations": recommendations
        }
        
        return security_analysis
    
    except Exception as e:
        logger.error(f"Error in AI email analysis: {str(e)}")
        # Fallback to rule-based analysis
        return rule_based_analysis(email_data)

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
            return rule_based_batch_analysis(emails)
        
        # Only process a limited number of emails with OpenAI to avoid timeouts
        # This is a limitation to keep the app responsive - only the first 3 emails use OpenAI
        max_ai_analysis = 3
        processed_count = 0
        analyzed_emails = []
        
        for i, email in enumerate(emails):
            try:
                if processed_count < max_ai_analysis:
                    # Use OpenAI for the first few emails
                    security_analysis = analyze_email_with_openai(email)
                    processed_count += 1
                else:
                    # Use rule-based for the rest
                    security_analysis = rule_based_analysis(email)
                
                email["security_analysis"] = security_analysis
                analyzed_emails.append(email)
                
                # Add a small delay between API calls to avoid rate limits
                if processed_count < max_ai_analysis and i < len(emails) - 1:
                    time.sleep(0.2)
                    
            except Exception as e:
                logger.error(f"Error analyzing email {i+1}: {str(e)}")
                # Use rule-based analysis as fallback for this email
                email["security_analysis"] = rule_based_analysis(email)
                analyzed_emails.append(email)
        
        return analyzed_emails
        
    except Exception as e:
        logger.error(f"Error in batch email analysis: {str(e)}")
        # Fallback to rule-based analysis for all emails
        return rule_based_batch_analysis(emails)

# Public functions to be used by the main application
def analyze_email_security(email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze an email for security concerns using OpenAI API.
    This is the main function to be called by the application.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    return analyze_email_with_openai(email)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns using OpenAI API.
    This is the main function to be called by the application.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    return batch_analyze_emails_with_openai(emails)