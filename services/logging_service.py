"""
Logging Service - Centralized logging for user activities and system events.

"""

from sqlalchemy.orm import Session
from models.activity_log import ActivityLog, SystemEventLog, SecurityAlert

# Make encryption optional so this module can import/run even if the key/service is broken.
try:
    from services.log_encryption import log_encryption_service  # type: ignore
except Exception as e:
    log_encryption_service = None  # type: ignore[assignment]
    print(f"[WARNING] LogEncryptionService unavailable: {e}")

from datetime import datetime
import json
from typing import Optional, Dict, Any, Union


class LoggingService:
    @staticmethod
    def log_user_activity(
        db: Session,
        user_id: Optional[int] = None,
        action: str = "",
        details: Optional[Dict[str, Any]] = None,
        encrypt_details: bool = True,
        **kwargs: Any,
    ) -> ActivityLog:
        """
        Persist a user activity log entry; encrypt `details` when configured and available.
        """
        payload: Union[str, None] = None
        is_encrypted = False

        if details is not None:
            payload = json.dumps(details, ensure_ascii=False)

            if encrypt_details and log_encryption_service is not None:
                try:
                    payload = log_encryption_service.encrypt(payload)  # type: ignore[union-attr]
                    is_encrypted = True
                except Exception:
                    # Fall back to plaintext if encryption fails.
                    is_encrypted = False

        log = ActivityLog(
            user_id=user_id,
            action=action,
            details=payload,
            is_encrypted=is_encrypted,
            timestamp=datetime.utcnow(),
            **kwargs,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    @staticmethod
    def log_system_event(
        db: Session,
        event_type: str = "",
        details: Optional[Dict[str, Any]] = None,
        encrypt_details: bool = True,
        **kwargs: Any,
    ) -> SystemEventLog:
        """
        Persist a system event log entry; encrypt `details` when configured and available.
        """
        payload: Union[str, None] = None
        is_encrypted = False

        if details is not None:
            payload = json.dumps(details, ensure_ascii=False)

            if encrypt_details and log_encryption_service is not None:
                try:
                    payload = log_encryption_service.encrypt(payload)  # type: ignore[union-attr]
                    is_encrypted = True
                except Exception:
                    is_encrypted = False

        log = SystemEventLog(
            event_type=event_type,
            details=payload,
            is_encrypted=is_encrypted,
            timestamp=datetime.utcnow(),
            **kwargs,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    @staticmethod
    def create_security_alert(
        db: Session,
        alert_type: str = "",
        severity: str = "low",
        message: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        encrypt_details: bool = True,
        **kwargs: Any,
    ) -> SecurityAlert:
        """
        Persist a security alert entry; encrypt `details` when configured and available.
        """
        payload: Union[str, None] = None

        if details is not None:
            payload = json.dumps(details, ensure_ascii=False)

            if encrypt_details and log_encryption_service is not None:
                try:
                    payload = log_encryption_service.encrypt(payload)  # type: ignore[union-attr]

                except Exception:
                    pass

        alert = SecurityAlert(
            alert_type=alert_type,
            severity=severity.upper(),
            message=kwargs.get("message", "Security alert"),
            user_id=kwargs.get("user_id"),
            details=payload,
            timestamp=datetime.utcnow(),
            **{
                k: v for k, v in kwargs.items() if k not in ["message", "user_id", "db"]
            },
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def get_decrypted_details(
        log: Union[ActivityLog, SystemEventLog],
    ) -> Optional[Dict[str, Any]]:
        """
        Return details as a dict.
        - If encrypted: decrypt when possible; otherwise return an error payload.
        - If plaintext: JSON-decode when possible.
        """
        raw = getattr(log, "details", None)
        if raw in (None, ""):
            return None

        # If already a dict-like payload, return it directly.
        if isinstance(raw, dict):
            return raw

        # Normalize bytes -> str
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")

        # Decrypt when flagged encrypted
        if getattr(log, "is_encrypted", False):
            if log_encryption_service is None:
                return {
                    "error": "encrypted details present but LogEncryptionService is unavailable"
                }
            try:
                raw = log_encryption_service.decrypt(raw)  # type: ignore[union-attr]
            except Exception as e:
                return {"error": f"decryption failed: {type(e).__name__}"}

        # JSON decode best-effort
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}


# Fallback instance when encryption is unavailable: force encrypt_details=False.
class FallbackLoggingService:
    @staticmethod
    def log_user_activity(**kwargs):
        """Log user activity without encrypting details when encryption is unavailable."""
        kwargs["encrypt_details"] = False
        return LoggingService.log_user_activity(**kwargs)  # type: ignore[attr-defined]

    @staticmethod
    def log_system_event(**kwargs):
        """Log a system event using the primary LoggingService implementation."""
        return LoggingService.log_system_event(**kwargs)  # type: ignore[attr-defined]

    @staticmethod
    def create_security_alert(**kwargs):
        """Create a security alert using the primary LoggingService implementation."""
        return LoggingService.create_security_alert(**kwargs)  # type: ignore[attr-defined]

    @staticmethod
    def get_decrypted_details(log):
        return LoggingService.get_decrypted_details(log)


# Singleton instance
logging_service = (
    LoggingService() if log_encryption_service is not None else FallbackLoggingService()
)
