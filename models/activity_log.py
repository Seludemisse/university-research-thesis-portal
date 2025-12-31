"""
Activity Log Model - Tracks user actions and system events.

"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class ActivityLog(Base):
    """
    Stores user activity logs (login, logout, data access, modifications).
    Security: Sensitive data should be encrypted using the LogEncryption service.
    """

    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )  # Nullable for system events
    action = Column(
        String(100), nullable=False
    )  # e.g., "LOGIN", "VIEW_THESIS", "UPDATE_USER"
    resource_type = Column(
        String(50), nullable=True
    )  # e.g., "thesis", "user", "system"
    resource_id = Column(Integer, nullable=True)  # ID of the resource being accessed
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(255), nullable=True)
    details = Column(
        Text, nullable=True
    )  # JSON or encrypted text with additional details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_encrypted = Column(
        Boolean, default=False
    )  # Flag to indicate if details are encrypted

    # Relationship
    user = relationship("User", back_populates="activity_logs")

    def __repr__(self):
        return (
            f"<ActivityLog(id={self.id}, user_id={self.user_id}, action={self.action})>"
        )


class SystemEventLog(Base):
    """
    Stores system-level events (startup, shutdown, errors, configuration changes).
    """

    __tablename__ = "system_event_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(
        String(100), nullable=False
    )  # e.g., "STARTUP", "SHUTDOWN", "ERROR", "CONFIG_CHANGE"
    severity = Column(
        String(20), nullable=False
    )  # "INFO", "WARNING", "ERROR", "CRITICAL"
    message = Column(Text, nullable=False)
    details = Column(Text, nullable=True)  # Additional context (JSON format)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_encrypted = Column(Boolean, default=False)

    def __repr__(self):
        return f"<SystemEventLog(id={self.id}, event_type={self.event_type}, severity={self.severity})>"


class SecurityAlert(Base):
    """
    Stores security alerts for suspicious activities.
    """

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(
        String(100), nullable=False
    )  # e.g., "MULTIPLE_FAILED_LOGINS", "UNAUTHORIZED_ACCESS"
    severity = Column(String(20), nullable=False)  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    message = Column(Text, nullable=False)
    details = Column(Text, nullable=True)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship(
        "User", foreign_keys=[user_id], back_populates="security_alerts"
    )
    resolver = relationship("User", foreign_keys=[resolved_by])

    def __repr__(self):
        return f"<SecurityAlert(id={self.id}, alert_type={self.alert_type}, severity={self.severity})>"
