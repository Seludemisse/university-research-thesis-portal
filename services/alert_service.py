"""
Alert Service - Sends email alerts for suspicious activities.

"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from typing import List, Optional
from sqlalchemy.orm import Session
from models.activity_log import SecurityAlert
from models.user import User  # Add this import
from datetime import datetime, timedelta

load_dotenv()


class AlertService:
    """
    Service for sending security alerts via email.
    """

    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.alert_email = os.getenv("ALERT_EMAIL", "admin@university.edu")

    def send_email_alert(
        self, subject: str, body: str, recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send an email alert.

        Args:
            subject: Email subject
            body: Email body (can be HTML)
            recipients: List of recipient emails (defaults to ALERT_EMAIL)

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.smtp_username or not self.smtp_password:
            print("[WARNING] SMTP credentials not configured. Email not sent.")
            return False

        if recipients is None:
            recipients = [self.alert_email]

        try:
            # Create message
            msg = MIMEMultipart()
            msg["From"] = self.smtp_username
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject

            # Attach body
            msg.attach(MIMEText(body, "html"))

            # Connect and send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

            print(f"[INFO] Alert email sent: {subject}")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to send alert email: {e}")
            return False

    def check_and_alert_failed_logins(self, db: Session, user_id: int) -> None:
        """
        Check for multiple failed login attempts and send alert if threshold exceeded.
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return

        # Alert if user is locked
        if user.is_locked:
            subject = f"[SECURITY ALERT] Account Locked - {user.email}"
            body = f"""
            <html>
            <body>
                <h2>Security Alert: Account Locked</h2>
                <p><strong>User:</strong> {user.email} (ID: {user.id})</p>
                <p><strong>Failed Login Attempts:</strong> {user.failed_login_attempts}</p>
                <p><strong>Locked Until:</strong> {user.locked_until}</p>
                <p><strong>Time:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                <p>This account has been locked due to multiple failed login attempts.</p>
            </body>
            </html>
            """
            self.send_email_alert(subject, body)

    def check_and_alert_unauthorized_access(
        self,
        db: Session,
        user_id: int,
        resource_type: str,
        resource_id: int,
        action: str,
    ) -> None:
        """
        Alert on unauthorized access attempts.
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return

        subject = f"[SECURITY ALERT] Unauthorized Access Attempt"
        body = f"""
        <html>
        <body>
            <h2>Security Alert: Unauthorized Access Attempt</h2>
            <p><strong>User:</strong> {user.email} (ID: {user.id})</p>
            <p><strong>Role:</strong> {user.role.role_name if user.role else "Unknown"}</p>
            <p><strong>Resource Type:</strong> {resource_type}</p>
            <p><strong>Resource ID:</strong> {resource_id}</p>
            <p><strong>Action:</strong> {action}</p>
            <p><strong>Time:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </body>
        </html>
        """
        self.send_email_alert(subject, body)

    def send_daily_security_summary(self, db: Session) -> None:
        """
        Send a daily summary of security events.
        This should be called by a scheduled task.
        """
        # Get unresolved alerts from last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        alerts = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.timestamp >= yesterday, SecurityAlert.is_resolved == False
            )
            .all()
        )

        if not alerts:
            return

        # Group by severity
        critical = [a for a in alerts if a.severity == "CRITICAL"]
        high = [a for a in alerts if a.severity == "HIGH"]
        medium = [a for a in alerts if a.severity == "MEDIUM"]
        low = [a for a in alerts if a.severity == "LOW"]

        subject = f"[DAILY SUMMARY] Security Alerts - {len(alerts)} Unresolved"
        body = f"""
        <html>
        <body>
            <h2>Daily Security Summary</h2>
            <p><strong>Date:</strong> {datetime.utcnow().strftime("%Y-%m-%d")}</p>
            <p><strong>Total Unresolved Alerts:</strong> {len(alerts)}</p>
            
            <h3>Breakdown by Severity:</h3>
            <ul>
                <li><strong>CRITICAL:</strong> {len(critical)}</li>
                <li><strong>HIGH:</strong> {len(high)}</li>
                <li><strong>MEDIUM:</strong> {len(medium)}</li>
                <li><strong>LOW:</strong> {len(low)}</li>
            </ul>
            
            <h3>Recent Critical Alerts:</h3>
            <ul>
        """

        for alert in critical[:5]:  # Show top 5 critical alerts
            body += f"<li>{alert.alert_type} - {alert.message}</li>"

        body += """
            </ul>
            <p>Please review the alerts in the admin dashboard.</p>
        </body>
        </html>
        """

        self.send_email_alert(subject, body)


# Singleton instance
alert_service = AlertService()
