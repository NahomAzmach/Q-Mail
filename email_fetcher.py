import imaplib
import email
import email.message
import logging
from email.header import decode_header
import html
import re
import os
from typing import List, Dict, Any, Tuple, Optional

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def decode_mime_header(header: str) -> str:
    """Decode MIME-encoded email headers.
    
    Args:
        header: The MIME-encoded header to decode
        
    Returns:
        A decoded and normalized string
    """
    if not header:
        return ""
    
    try:
        decoded_header = ""
        for value, charset in decode_header(header):
            if isinstance(value, bytes):
                if charset:
                    try:
                        decoded_value = value.decode(charset)
                    except UnicodeDecodeError:
                        # Fallback to utf-8 if the specified charset fails
                        try:
                            decoded_value = value.decode('utf-8')
                        except UnicodeDecodeError:
                            # Last resort
                            decoded_value = value.decode('latin-1', errors='replace')
                else:
                    # No charset specified, try common encodings
                    try:
                        decoded_value = value.decode('utf-8')
                    except UnicodeDecodeError:
                        decoded_value = value.decode('latin-1', errors='replace')
            else:
                decoded_value = str(value)
                
            decoded_header += decoded_value
        
        return decoded_header
    except Exception as e:
        logger.warning(f"Error decoding header: {e}")
        # Return the original header if decoding fails
        return header

def get_email_body(msg: email.message.Message) -> str:
    """Extract email body from an email message object.
    
    Args:
        msg: The email message object
        
    Returns:
        The email body as plain text
    """
    body = ""
    
    if msg.is_multipart():
        # If the message has multiple parts, check each part
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
                
            # Get the body text
            if content_type in ["text/plain", "text/html"]:
                try:
                    # Get the payload and decode it
                    charset = part.get_content_charset() or 'utf-8'
                    payload = part.get_payload(decode=True)
                    
                    if payload:
                        try:
                            decoded_payload = payload.decode(charset)
                        except UnicodeDecodeError:
                            # Fallback if charset doesn't work
                            decoded_payload = payload.decode('utf-8', errors='replace')
                        
                        # If it's HTML, try to convert to plain text
                        if content_type == "text/html":
                            # Basic HTML to text conversion
                            decoded_payload = html.unescape(decoded_payload)
                            decoded_payload = re.sub(r'<.*?>', ' ', decoded_payload)
                            decoded_payload = re.sub(r'\s+', ' ', decoded_payload)
                        
                        body += decoded_payload
                        
                        # If we found text/plain, we can stop (it's preferred)
                        if content_type == "text/plain":
                            break
                
                except Exception as e:
                    logger.warning(f"Error processing email part: {e}")
    else:
        # Not multipart - just get the body
        content_type = msg.get_content_type()
        
        if content_type in ["text/plain", "text/html"]:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                payload = msg.get_payload(decode=True)
                
                if payload:
                    try:
                        body = payload.decode(charset)
                    except UnicodeDecodeError:
                        body = payload.decode('utf-8', errors='replace')
                    
                    # If it's HTML, convert to plain text
                    if content_type == "text/html":
                        body = html.unescape(body)
                        body = re.sub(r'<.*?>', ' ', body)
                        body = re.sub(r'\s+', ' ', body)
            
            except Exception as e:
                logger.warning(f"Error processing email body: {e}")
    
    return body.strip()

def connect_to_server(email_address: str, password: str, imap_server: str) -> Tuple[Optional[imaplib.IMAP4_SSL], str]:
    """Connect to the IMAP server and login.
    
    Args:
        email_address: User's email address
        password: User's password or app password
        imap_server: IMAP server address
        
    Returns:
        Tuple of (IMAP connection object, error message)
        If connection fails, IMAP object will be None
    """
    try:
        # Connect to the IMAP server
        mail = imaplib.IMAP4_SSL(imap_server)
        
        # Login to the account
        mail.login(email_address, password)
        
        return mail, ""
    except imaplib.IMAP4.error as e:
        error_msg = f"Authentication failed: {str(e)}"
        logger.error(error_msg)
        return None, error_msg
    except ConnectionRefusedError:
        error_msg = f"Connection refused to {imap_server}. Please check the server address."
        logger.error(error_msg)
        return None, error_msg
    except Exception as e:
        error_msg = f"Failed to connect: {str(e)}"
        logger.error(error_msg)
        return None, error_msg

def fetch_emails(email_address: str, password: str, imap_server: str, 
                max_emails: int = 10, folder: str = "INBOX") -> List[Dict[str, Any]]:
    """Fetch emails from an IMAP server.
    
    Args:
        email_address: User's email address
        password: User's password or app password
        imap_server: IMAP server address
        max_emails: Maximum number of emails to fetch
        folder: Email folder to fetch from
        
    Returns:
        List of dictionaries containing email data
    """
    emails = []
    
    # Connect to the server
    mail, error_msg = connect_to_server(email_address, password, imap_server)
    
    if not mail:
        # Return empty list with error info if connection failed
        emails.append({
            "error": True,
            "message": error_msg
        })
        return emails
    
    try:
        # Select the mailbox/folder to fetch emails from
        status, messages = mail.select(folder)
        
        if status != "OK":
            error_msg = f"Failed to select folder '{folder}': {messages[0].decode() if messages and messages[0] else 'Unknown error'}"
            logger.error(error_msg)
            emails.append({
                "error": True,
                "message": error_msg
            })
            return emails
        
        # Get total number of emails
        message_count = int(messages[0].decode() if messages and messages[0] else 0)
        
        if message_count == 0:
            logger.info(f"No emails found in folder: {folder}")
            return emails
        
        # Search for ALL emails - this will get both read and unread
        status, search_data = mail.search(None, "ALL")
        
        if status != "OK" or not search_data or not search_data[0]:
            # If ALL search fails, try more specific search
            logger.warning("ALL search failed, trying alternative search")
            status, search_data = mail.search(None, "(OR SEEN UNSEEN)")
            
            if status != "OK" or not search_data or not search_data[0]:
                error_msg = "Failed to search emails: No emails found"
                logger.error(error_msg)
                emails.append({
                    "error": True,
                    "message": error_msg
                })
                return emails
        
        # Get message IDs as a list 
        message_ids = search_data[0].split()
        
        # Sort in reverse order (newest first)
        message_ids = sorted(message_ids, reverse=True)
        
        # Limit to max_emails
        message_ids = message_ids[:max_emails]
        
        logger.info(f"Found {len(message_ids)} emails to process")
        
        # Fetch and process each email by ID
        for msg_id in message_ids:
            try:
                # Fetch the email using its ID
                status, msg_data = mail.fetch(msg_id, "(RFC822)")
                
                if status != "OK" or not msg_data:
                    logger.warning(f"Failed to fetch email ID {msg_id.decode() if hasattr(msg_id, 'decode') else msg_id}")
                    continue
                
                # Find the email data in the response
                raw_email = None
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]
                        break
                
                if not raw_email:
                    logger.warning(f"No email data found for ID {msg_id.decode() if hasattr(msg_id, 'decode') else msg_id}")
                    continue
                
                # Parse the email data
                email_msg = email.message_from_bytes(raw_email)
                
                # Extract email details
                subject = decode_mime_header(email_msg["Subject"])
                from_address = decode_mime_header(email_msg["From"])
                date = decode_mime_header(email_msg["Date"])
                
                # Get email body
                body = get_email_body(email_msg)
                
                # Create email data dictionary
                email_data = {
                    "subject": subject,
                    "from": from_address,
                    "date": date,
                    "body": body,
                }
                
                emails.append(email_data)
                
            except Exception as e:
                logger.error(f"Error processing email ID {msg_id}: {str(e)}")
                continue
        
    except Exception as e:
        error_msg = f"Error fetching emails: {str(e)}"
        logger.error(error_msg)
        emails.append({
            "error": True,
            "message": error_msg
        })
    
    finally:
        # Close and logout
        try:
            mail.close()
            mail.logout()
        except:
            pass
    
    return emails

def get_imap_server(email_provider: str) -> str:
    """Get the IMAP server address for common email providers.
    
    Args:
        email_provider: Email provider name (gmail, outlook, yahoo, etc.)
        
    Returns:
        IMAP server address
    """
    providers = {
        'gmail': 'imap.gmail.com',
        'google': 'imap.gmail.com',
        'outlook': 'outlook.office365.com',
        'hotmail': 'outlook.office365.com',
        'live': 'outlook.office365.com',
        'yahoo': 'imap.mail.yahoo.com',
        'aol': 'imap.aol.com',
        'icloud': 'imap.mail.me.com',
        'zoho': 'imap.zoho.com',
        'protonmail': 'imap.protonmail.ch',  # Requires ProtonMail Bridge
        'yandex': 'imap.yandex.com',
        'mail.ru': 'imap.mail.ru',
        'gmx': 'imap.gmx.com',
    }
    
    # Normalize the provider name
    email_provider = email_provider.lower().strip()
    
    return providers.get(email_provider, '')

def auto_detect_provider(email_address: str) -> str:
    """Try to detect email provider from email address.
    
    Args:
        email_address: User's email address
        
    Returns:
        IMAP server address if detected, empty string otherwise
    """
    if not email_address or '@' not in email_address:
        return ''
    
    # Extract domain from email
    domain = email_address.split('@')[1].lower()
    
    # Check domain and return corresponding IMAP server
    if domain.endswith('gmail.com') or domain.endswith('googlemail.com'):
        return 'imap.gmail.com'
    elif any(domain.endswith(d) for d in ['outlook.com', 'hotmail.com', 'live.com', 'msn.com']):
        return 'outlook.office365.com'
    elif domain.endswith('yahoo.com') or domain.endswith('ymail.com'):
        return 'imap.mail.yahoo.com'
    elif domain.endswith('aol.com'):
        return 'imap.aol.com'
    elif domain.endswith('icloud.com') or domain.endswith('me.com') or domain.endswith('mac.com'):
        return 'imap.mail.me.com'
    elif domain.endswith('zoho.com'):
        return 'imap.zoho.com'
    elif domain.endswith('protonmail.com') or domain.endswith('protonmail.ch'):
        return 'imap.protonmail.ch'  # Requires ProtonMail Bridge
    elif domain.endswith('yandex.com') or domain.endswith('yandex.ru'):
        return 'imap.yandex.com'
    elif domain.endswith('mail.ru'):
        return 'imap.mail.ru'
    elif domain.endswith('gmx.com') or domain.endswith('gmx.net'):
        return 'imap.gmx.com'
    else:
        return ''
