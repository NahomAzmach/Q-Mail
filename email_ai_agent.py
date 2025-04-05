"""
Email AI Agent module for intelligent email analysis and phishing detection.
This module creates an AI agent using LangChain and LangGraph to analyze emails
for security concerns, replacing the simple rule-based detection with LLM-powered analysis.
"""
import os
import time
import logging
from typing import Dict, List, Any, TypedDict, Optional

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a schema for our state
class EmailAgentState(TypedDict):
    email: Dict[str, Any]
    security_analysis: Optional[Dict[str, Any]]

# Initialize the OpenAI model - GPT-4o Mini
# We'll initialize this lazily later to avoid startup errors
model = None

# Define the email analysis prompt template
EMAIL_ANALYSIS_PROMPT = """
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

class EmailAnalyzerAgent:
    """
    AI agent for analyzing emails for security concerns.
    This agent uses LangChain and OpenAI's GPT-4o Mini to analyze email content
    and detect phishing attempts or other security threats.
    """
    
    def __init__(self):
        """Initialize the email analyzer agent with the necessary components."""
        # Check if API key is available
        if not os.environ.get("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY environment variable is not set")
        
        # Create the workflow graph
        self.graph = self._build_agent_graph()
    
    def _build_agent_graph(self) -> StateGraph:
        """
        Build the LangGraph workflow for email analysis.
        
        Returns:
            StateGraph: The agent workflow graph
        """
        # Build a simple graph for email analysis with proper state schema
        builder = StateGraph(EmailAgentState)
        
        # Define the email analysis node
        builder.add_node("analyze_email", self._analyze_email)
        
        # Define the entry point
        builder.set_entry_point("analyze_email")
        
        # Compile the graph
        return builder.compile()
    
    def _analyze_email(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze an email for security concerns using the LLM.
        
        Args:
            state: The current state containing email data
            
        Returns:
            Updated state with analysis results
        """
        email = state.get("email", {})
        
        # Create the prompt for analysis
        prompt = ChatPromptTemplate.from_template(EMAIL_ANALYSIS_PROMPT)
        
        # Format the prompt with email data
        formatted_messages = prompt.format_messages(
            sender=email.get("from", ""),
            subject=email.get("subject", ""),
            body=email.get("body", "")
        )
        
        try:
            # Generate the analysis using the LLM
            if model is None:
                raise ValueError("OpenAI model not available")
            response = model.invoke(formatted_messages)
            
            # Extract the analysis from the response
            analysis_text = response.content
            
            # Process the analysis (assuming it's in JSON-like format)
            # Note: In a production environment, we'd need more robust parsing
            import json
            import re
            
            # Try to find JSON-like content in the response
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            
            if json_match:
                try:
                    analysis = json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    # If JSON parsing fails, create a structured analysis manually
                    logger.warning("Failed to parse JSON from LLM response")
                    analysis = self._parse_analysis_from_text(analysis_text)
            else:
                # If no JSON-like content found, create a structured analysis manually
                analysis = self._parse_analysis_from_text(analysis_text)
            
            # Ensure the analysis has all required fields
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
            
            # Update state with the analysis
            state["security_analysis"] = {
                "sender_domain": self._extract_domain(email.get("from", "")),
                "is_trusted_domain": analysis.get("is_trusted_sender", False),
                "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
                "risk_level": analysis.get("risk_level", "Unknown"),
                "explanation": analysis.get("explanation", ""),
                "recommendations": analysis.get("recommendations", "")
            }
            
            return state
            
        except Exception as e:
            logger.error(f"Error in email analysis: {str(e)}")
            # Provide a fallback analysis
            state["security_analysis"] = {
                "sender_domain": self._extract_domain(email.get("from", "")),
                "is_trusted_domain": False,
                "suspicious_patterns": ["Error in analysis"],
                "risk_level": "Unknown",
                "explanation": f"Error during analysis: {str(e)}",
                "recommendations": "Please try again or contact support"
            }
            
            return state
    
    def _parse_analysis_from_text(self, text: str) -> Dict[str, Any]:
        """
        Parse a non-JSON analysis text into a structured format.
        
        Args:
            text: The analysis text from the LLM
            
        Returns:
            A structured analysis dictionary
        """
        analysis = {
            "is_trusted_sender": False,
            "suspicious_patterns_detected": [],
            "risk_level": "Medium",  # Default to medium as a precaution
            "explanation": "",
            "recommendations": ""
        }
        
        # Extract trusted status
        if "trusted" in text.lower() and not ("not trusted" in text.lower() or "untrusted" in text.lower()):
            analysis["is_trusted_sender"] = True
        
        # Extract risk level
        if "risk" in text.lower():
            if "low risk" in text.lower():
                analysis["risk_level"] = "Low"
            elif "high risk" in text.lower():
                analysis["risk_level"] = "High"
            elif "medium risk" in text.lower():
                analysis["risk_level"] = "Medium"
        
        # Extract suspicious patterns
        patterns = []
        lines = text.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ["suspicious", "concern", "red flag", "warning"]):
                patterns.append(line.strip())
        
        if patterns:
            analysis["suspicious_patterns_detected"] = patterns
        
        # Extract explanation and recommendations
        explanation_section = ""
        recommendations_section = ""
        
        if "explanation" in text.lower():
            parts = text.lower().split("explanation")
            if len(parts) > 1:
                explanation_section = parts[1].split("recommendations")[0] if "recommendations" in parts[1] else parts[1]
        
        if "recommendation" in text.lower():
            parts = text.lower().split("recommendation")
            if len(parts) > 1:
                recommendations_section = parts[1]
        
        analysis["explanation"] = explanation_section.strip() or text
        analysis["recommendations"] = recommendations_section.strip() or "Exercise caution with this email."
        
        return analysis
    
    def _extract_domain(self, email_address: str) -> str:
        """
        Extract the domain from an email address.
        
        Args:
            email_address: The full email address string
            
        Returns:
            The domain portion of the email address
        """
        import re
        
        # Handle cases where email might contain a display name
        match = re.search(r'<([^<>]+)>', email_address)
        if match:
            email_address = match.group(1)
        
        # Extract domain using regex
        match = re.search(r'@([^@]+)$', email_address)
        
        if match:
            return match.group(1).lower()
        
        return ""
    
    def analyze_email(self, email: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single email for security concerns.
        
        Args:
            email: Dictionary containing email data
            
        Returns:
            Dictionary with email data and security analysis
        """
        # Prepare the initial state with proper schema
        initial_state = {"email": email, "security_analysis": None}
        
        # Run the agent graph
        try:
            final_state = self.graph.invoke(initial_state)
            
            # Add the security analysis to the email
            email["security_analysis"] = final_state.get("security_analysis", {})
            
            return email
        except Exception as e:
            logger.error(f"Error running email analysis agent: {str(e)}")
            # Return the email with a basic error analysis
            email["security_analysis"] = {
                "sender_domain": self._extract_domain(email.get("from", "")),
                "is_trusted_domain": False,
                "suspicious_patterns": ["Agent error"],
                "risk_level": "Unknown",
                "explanation": f"Error in analysis agent: {str(e)}",
                "recommendations": "Please try again or contact support"
            }
            
            return email
    
    def batch_analyze_emails(self, emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of emails for security concerns.
        
        Args:
            emails: List of email dictionaries
            
        Returns:
            List of emails with security analysis added
        """
        analyzed_emails = []
        
        for email in emails:
            analyzed_email = self.analyze_email(email)
            analyzed_emails.append(analyzed_email)
        
        return analyzed_emails


# Create a singleton instance of the agent
try:
    email_agent = EmailAnalyzerAgent()
except ValueError as e:
    logger.error(f"Failed to initialize email agent: {str(e)}")
    email_agent = None


def _initialize_openai_model():
    """
    Lazily initialize the OpenAI model only when needed.
    This helps prevent startup errors and timeouts.
    
    Returns:
        True if initialization succeeded, False otherwise
    """
    global model
    
    if model is not None:
        return True
    
    # Only initialize if not already done
    try:
        from langchain_openai import ChatOpenAI
        
        model = ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0.0,  # Keep it deterministic for security analysis
            request_timeout=30.0,  # Increased timeout
            max_retries=2,  # Add retries for transient errors
        )
        logger.info("Successfully initialized OpenAI model")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize OpenAI model: {str(e)}")
        return False


def analyze_email_security(email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze an email for security concerns using the AI agent.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    # Initialize the model
    model_initialized = _initialize_openai_model()
    
    if not model_initialized or email_agent is None:
        # Fallback to the original rule-based analysis if agent initialization failed
        from email_security import analyze_email_security as rule_based_analysis
        return rule_based_analysis(email)
    
    try:
        analyzed_email = email_agent.analyze_email(email)
        return analyzed_email.get("security_analysis", {})
    except Exception as e:
        logger.error(f"Error in AI email analysis, falling back to rule-based: {str(e)}")
        from email_security import analyze_email_security as rule_based_analysis
        return rule_based_analysis(email)


def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails for security concerns using the AI agent.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    # Initialize the model
    model_initialized = _initialize_openai_model()
    
    if not model_initialized or email_agent is None:
        # Fallback to the original rule-based analysis if agent initialization failed
        from email_security import batch_analyze_emails as rule_based_batch_analysis
        return rule_based_batch_analysis(emails)
    
    try:
        # Process emails in batches to avoid long-running operations
        analyzed_emails = []
        batch_size = 3  # Process in small batches to avoid timeouts
        
        for i in range(0, len(emails), batch_size):
            batch = emails[i:i+batch_size]
            try:
                analyzed_batch = email_agent.batch_analyze_emails(batch)
                analyzed_emails.extend(analyzed_batch)
                # Add a small delay between batches to avoid rate limits
                time.sleep(0.5)
            except Exception as e:
                logger.error(f"Error analyzing batch {i//batch_size + 1}, falling back to rule-based: {str(e)}")
                from email_security import batch_analyze_emails as rule_based_batch_analysis
                analyzed_batch = rule_based_batch_analysis(batch)
                analyzed_emails.extend(analyzed_batch)
        
        return analyzed_emails
    except Exception as e:
        logger.error(f"Error in AI email batch analysis, falling back to rule-based: {str(e)}")
        from email_security import batch_analyze_emails as rule_based_batch_analysis
        return rule_based_batch_analysis(emails)