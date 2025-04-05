from datetime import datetime
from db_setup import db
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin

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


class TextMessage(db.Model):
    """Model to store individual text messages for analysis."""
    __tablename__ = 'text_messages'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    content = Column(Text, nullable=False)
    sender = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Store analysis results
    security_score = Column(Integer)
    risk_level = Column(String(50))
    explanation = Column(Text)
    
    # Relationship
    user = relationship("User", back_populates="text_messages")
    
    def __repr__(self):
        return f"<TextMessage(id={self.id}, risk_level={self.risk_level})>"
    
    def to_dict(self):
        """Convert to dictionary format for analysis."""
        return {
            'id': self.id,
            'content': self.content,
            'sender': self.sender,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class User(UserMixin, db.Model):
    """User model for authentication."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    profile_pic = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    text_messages = relationship("TextMessage", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"