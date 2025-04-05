"""
Text Message Analyzer for security concerns.

This module provides functionality to analyze text messages for phishing attempts,
scams, and other security concerns using both AI and rule-based approaches.
"""

import os
import time
import logging
import re
from typing import Dict, Any, List, Optional

import openai
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize OpenAI client
client = None

def initialize_openai_client():
    """Initialize the OpenAI client with API key from environment."""
    global client
    try:
        if not client and os.environ.get("OPENAI_API_KEY"):
            client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
            return True
    except Exception as e:
        logger.error(f"Error initializing OpenAI client: {e}")
    return False

def analyze_text_with_openai(text_content: str, sender: str = None) -> Dict[str, Any]:
    """
    Analyze a text message using OpenAI API.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information (phone number or contact name)
    
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Check if OpenAI API key is available
        if not os.environ.get("OPENAI_API_KEY"):
            logger.warning("OPENAI_API_KEY not found in environment variables")
            return rule_based_analysis(text_content, sender)
        
        # Initialize the client if needed
        if not initialize_openai_client():
            return rule_based_analysis(text_content, sender)
            
        # Prepare message content
        sender_info = f"Sender: {sender}\n" if sender else ""
        message_content = f"{sender_info}Message: {text_content}"
        
        # Call OpenAI API with a timeout to prevent hanging
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """
                You are a cybersecurity expert specialized in detecting phishing and scam attempts in text messages.
                Analyze the provided message for security concerns and provide your assessment.
                You must respond in this specific JSON format:
                {
                    "is_suspicious": true/false,
                    "security_score": 1-10 (1=dangerous, 10=secure),
                    "risk_level": "Dangerous/Unsafe/Cautious/Secure",
                    "suspicious_patterns_detected": ["pattern1", "pattern2"],
                    "explanation": "Brief explanation of analysis",
                    "recommendations": ["recommendation1", "recommendation2"]
                }
                """
                },
                {"role": "user", "content": message_content}
            ],
            max_tokens=800,
            timeout=3.5
        )
        
        # Extract analysis from response
        analysis_text = response.choices[0].message.content.strip()
        
        # Try to parse the response as JSON
        import json
        try:
            analysis = json.loads(analysis_text)
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract structured data from text
            analysis = extract_analysis_from_text(analysis_text)
            
        # Set security score and risk level based on the score
        if "security_score" not in analysis:
            analysis["security_score"] = 5
            
        if "risk_level" not in analysis:
            score = analysis["security_score"]
            if score >= 8:
                analysis["risk_level"] = "Secure"
            elif score >= 6:
                analysis["risk_level"] = "Cautious"
            elif score >= 3:
                analysis["risk_level"] = "Unsafe"
            else:
                analysis["risk_level"] = "Dangerous"
        
        # Ensure recommendations is a list
        if "recommendations" in analysis:
            recommendations = analysis["recommendations"]
            if isinstance(recommendations, str):
                if recommendations and recommendations != "Not provided by analysis":
                    analysis["recommendations"] = [recommendations]
                else:
                    analysis["recommendations"] = ["Be cautious with unexpected messages from unknown sources."]
        else:
            analysis["recommendations"] = ["Be cautious with unexpected messages from unknown sources."]
            
        return {
            "is_suspicious": analysis.get("is_suspicious", False),
            "security_score": analysis.get("security_score", 5),
            "risk_level": analysis.get("risk_level", "Unknown"),
            "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
            "explanation": analysis.get("explanation", ""),
            "recommendations": analysis.get("recommendations", [])
        }
    
    except Exception as e:
        logger.error(f"Error in AI text analysis: {str(e)}")
        # Fallback to rule-based analysis
        return rule_based_analysis(text_content, sender)

def extract_analysis_from_text(text: str) -> Dict[str, Any]:
    """
    Parse a non-JSON analysis text into a structured format.
    
    Args:
        text: The analysis text from the LLM
        
    Returns:
        A structured analysis dictionary
    """
    analysis = {
        "is_suspicious": False,
        "security_score": 5,
        "risk_level": "Cautious",
        "suspicious_patterns_detected": [],
        "recommendations": []
    }
    
    # Extract security score
    score_match = re.search(r'security_score["\s:]+(\d+)', text)
    if score_match:
        try:
            analysis["security_score"] = int(score_match.group(1))
        except ValueError:
            pass
    
    # Extract risk level
    if "dangerous" in text.lower():
        analysis["risk_level"] = "Dangerous"
    elif "unsafe" in text.lower():
        analysis["risk_level"] = "Unsafe"
    elif "secure" in text.lower():
        analysis["risk_level"] = "Secure"
    else:
        analysis["risk_level"] = "Cautious"
    
    # Extract is_suspicious
    analysis["is_suspicious"] = "suspicious" in text.lower() or analysis["risk_level"] in ["Dangerous", "Unsafe"]
    
    # Extract patterns - look for list-like patterns
    patterns_section = re.search(r'suspicious_patterns_detected["\s:]+\[(.*?)\]', text, re.DOTALL)
    if patterns_section:
        patterns_text = patterns_section.group(1)
        patterns = re.findall(r'"([^"]+)"', patterns_text)
        if patterns:
            analysis["suspicious_patterns_detected"] = patterns
    
    # Extract recommendations
    recommendations_section = re.search(r'recommendations["\s:]+\[(.*?)\]', text, re.DOTALL)
    if recommendations_section:
        recommendations_text = recommendations_section.group(1)
        recommendations = re.findall(r'"([^"]+)"', recommendations_text)
        if recommendations:
            analysis["recommendations"] = recommendations
    
    # Extract explanation
    explanation_match = re.search(r'explanation["\s:]+["\'](.*?)["\']', text, re.DOTALL)
    if explanation_match:
        analysis["explanation"] = explanation_match.group(1).strip()
    
    return analysis

def rule_based_analysis(text_content: str, sender: str = None) -> Dict[str, Any]:
    """
    Analyze a text message using rule-based approach.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information
    
    Returns:
        Dictionary with security analysis results
    """
    text_lower = text_content.lower()
    
    # Initialize analysis result
    analysis = {
        "is_suspicious": False,
        "security_score": 8,  # Start with a relatively safe score
        "risk_level": "Secure",
        "suspicious_patterns": [],
        "explanation": "",
        "recommendations": []
    }
    
    # Check for common phishing/scam patterns
    suspicious_patterns = []
    
    # Check for urgency language
    urgency_phrases = [
        "urgent", "immediately", "alert", "act now", "expires soon", 
        "limited time", "quickly", "asap", "emergency", "important notice"
    ]
    
    for phrase in urgency_phrases:
        if phrase in text_lower:
            suspicious_patterns.append(f"Urgency language: '{phrase}'")
            analysis["security_score"] -= 1
    
    # Check for financial/personal info requests
    financial_phrases = [
        "account", "password", "credit card", "ssn", "social security", 
        "bank", "verify", "confirm payment", "authorize", "billing", 
        "payment", "pin", "login", "credentials", "update your information"
    ]
    
    for phrase in financial_phrases:
        if phrase in text_lower:
            suspicious_patterns.append(f"Request for sensitive information: '{phrase}'")
            analysis["security_score"] -= 1
    
    # Check for suspicious URLs
    url_patterns = [
        r'https?://bit\.ly', r'https?://goo\.gl', 
        r'https?://t\.co', r'https?://tinyurl\.com',
        r'click here', r'login here', r'sign in here'
    ]
    
    for pattern in url_patterns:
        if re.search(pattern, text_lower):
            suspicious_patterns.append("Contains suspicious URL or URL shortener")
            analysis["security_score"] -= 2
            break
    
    # Check for grammatical errors and unusual formatting
    grammar_issues = []
    if text_content.isupper():
        grammar_issues.append("ALL CAPS text")
    
    if text_content.count("!") > 2:
        grammar_issues.append("Excessive exclamation marks")
    
    if grammar_issues:
        suspicious_patterns.append("Suspicious formatting: " + ", ".join(grammar_issues))
        analysis["security_score"] -= 1
    
    # Check for common scam offers
    scam_offers = [
        "won", "winner", "lottery", "prize", "inherited", "free gift", 
        "claim", "offer", "congrats", "million", "cash prize",
        "selected", "promotion", "reward", "discount"
    ]
    
    for offer in scam_offers:
        if offer in text_lower:
            suspicious_patterns.append(f"Potential scam offer: '{offer}'")
            analysis["security_score"] -= 1
            break
    
    # Set final analysis based on security score
    analysis["suspicious_patterns"] = suspicious_patterns
    
    # Ensure score stays in valid range
    analysis["security_score"] = max(1, min(10, analysis["security_score"]))
    
    # Set risk level based on security score
    score = analysis["security_score"]
    if score >= 8:
        analysis["risk_level"] = "Secure"
    elif score >= 6:
        analysis["risk_level"] = "Cautious"
    elif score >= 3:
        analysis["risk_level"] = "Unsafe"
    else:
        analysis["risk_level"] = "Dangerous"
    
    # Set analysis narrative
    if suspicious_patterns:
        analysis["is_suspicious"] = True
        analysis["explanation"] = f"This message contains {len(suspicious_patterns)} suspicious patterns that may indicate a phishing attempt or scam."
        
        # Add recommendations based on specific patterns
        if any("URL" in pattern for pattern in suspicious_patterns):
            analysis["recommendations"].append("Do not click on any links in this message.")
        
        if any("sensitive information" in pattern for pattern in suspicious_patterns):
            analysis["recommendations"].append("Never share personal or financial information via text message.")
        
        if any("urgency" in pattern for pattern in suspicious_patterns):
            analysis["recommendations"].append("Be skeptical of messages creating a false sense of urgency.")
        
        if any("scam offer" in pattern for pattern in suspicious_patterns):
            analysis["recommendations"].append("Be wary of offers that seem too good to be true.")
    else:
        analysis["explanation"] = "No suspicious patterns detected in this message."
        analysis["recommendations"].append("Always remain vigilant with unexpected messages.")
    
    return analysis

def analyze_text(text_content: str, sender: str = None, use_ai: bool = True) -> Dict[str, Any]:
    """
    Analyze a text message for security concerns.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information
        use_ai: Whether to use AI analysis or just rule-based
        
    Returns:
        Dictionary with security analysis results
    """
    if use_ai:
        try:
            return analyze_text_with_openai(text_content, sender)
        except Exception as e:
            logger.error(f"Error in AI text analysis: {str(e)}")
            return rule_based_analysis(text_content, sender)
    else:
        return rule_based_analysis(text_content, sender)