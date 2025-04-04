from datetime import datetime
from main import db
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship

class EmailSession(db.Model):
    """Represents a fetching session with its results."""
    __tablename__ = 'email_sessions'
    
    id = Column(Integer, primary_key=True)
    email_address = Column(String(255), nullable=False)
    provider = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    emails = relationship("Email", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<EmailSession(id={self.id}, email_address={self.email_address}, provider={self.provider})>"


class Email(db.Model):
    """Represents an individual email."""
    __tablename__ = 'emails'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('email_sessions.id'), nullable=False)
    subject = Column(String(1000))
    sender = Column(String(1000))
    date = Column(String(255))
    body = Column(Text)
    error = Column(Boolean, default=False)
    error_message = Column(Text)
    
    # Relationship
    session = relationship("EmailSession", back_populates="emails")
    
    def __repr__(self):
        return f"<Email(id={self.id}, subject={self.subject})>"
    
    def to_dict(self):
        """Convert to dictionary format."""
        return {
            'id': self.id,
            'subject': self.subject,
            'from': self.sender,
            'date': self.date,
            'body': self.body,
            'error': self.error,
            'message': self.error_message if self.error else None
        }