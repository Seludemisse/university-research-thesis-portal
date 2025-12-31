"""
User model for authentication and authorization.
Supports RBAC (roles) and MAC (clearance levels).
"""

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class User(Base):
    """
    User model with authentication and authorization fields.

    Security features:
    - Password hash (never store plaintext)
    - Role-based access control (RBAC)
    - Clearance level for Mandatory Access Control (MAC)
    - Account lockout mechanism
    - Email verification placeholder
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # RBAC - Role-based access control
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

    # Department assignment
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)

    # MAC - Mandatory Access Control clearance level
    # 1 = Public, 2 = Internal, 3 = Confidential
    clearance_level = Column(Integer, default=1, nullable=False)

    # Account security
    is_locked = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # Email verification (placeholder - TODO: Implement email sending)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(255), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    role = relationship("Role", back_populates="users")
    department = relationship("Department", back_populates="users")
    theses = relationship("Thesis", back_populates="student")

    activity_logs = relationship("ActivityLog", back_populates="user")
    security_alerts = relationship(
        "SecurityAlert", foreign_keys="SecurityAlert.user_id", back_populates="user"
    )
