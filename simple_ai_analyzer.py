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
        import openai
        
        # Get email details
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        
        # Create prompt for OpenAI
        prompt = f"""
        You are an expert email security analyst with deep knowledge of phishing tactics and email security threats.
        Analyze the following email for any signs of phishing, scams, or security concerns.
        
        EMAIL DETAILS:
        - From: {sender}
        - Subject: {subject}
        - Body:
        {body}
        
        Analyze this email's security aspects by considering:
        1. Does the sender look legitimate? Check the domain and sender details.
        2. Is the content suspicious with urgent calls to action, requests for sensitive information, or unusual language?
        3. Are there suspicious patterns like urgent requests, fear tactics, grammatical errors, or unusual requests?
        4. What is the overall risk level (Low, Medium, High) and why?
        
        Return your analysis in a structured JSON format with these keys:
        - "is_trusted_sender": true/false based on sender legitimacy
        - "suspicious_patterns_detected": list of specific suspicious patterns found (empty if none)
        - "risk_level": "Low", "Medium", or "High"
        - "explanation": detailed reasoning for your assessment
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
                client = openai.OpenAI()
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0
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
            "risk_level", 
            "explanation", 
            "recommendations"
        ]
        
        for field in required_fields:
            if field not in analysis:
                if field == "suspicious_patterns_detected":
                    analysis[field] = []
                else:
                    analysis[field] = "Not provided by analysis"
        
        # Create security analysis result
        security_analysis = {
            "sender_domain": extract_domain_from_email(sender),
            "is_trusted_domain": analysis.get("is_trusted_sender", False),
            "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
            "risk_level": analysis.get("risk_level", "Unknown"),
            "explanation": analysis.get("explanation", ""),
            "recommendations": analysis.get("recommendations", "")
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
        
        # Process emails one by one to avoid timeout issues
        analyzed_emails = []
        
        for i, email in enumerate(emails):
            try:
                # Add security analysis to the email
                security_analysis = analyze_email_with_openai(email)
                email["security_analysis"] = security_analysis
                analyzed_emails.append(email)
                
                # Add a small delay between API calls to avoid rate limits
                if i < len(emails) - 1:
                    time.sleep(0.5)
                    
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