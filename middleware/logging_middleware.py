"""
Logging Middleware - Automatically logs HTTP requests.

"""

from fastapi import Request
from sqlalchemy.orm import Session
from services.logging_service import logging_service
from database import SessionLocal
import time


async def log_request_middleware(request: Request, call_next):
    """
    Middleware to log all HTTP requests.
    Captures IP address, user agent, and request duration.
    """
    start_time = time.time()

    # Get request info
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    method = request.method
    path = request.url.path

    # Process request
    response = await call_next(request)

    # Calculate duration
    duration_ms = (time.time() - start_time) * 1000

    # Log to database (in a separate DB session)
    try:
        db: Session = SessionLocal()

        # Extract user_id from request.state (set by your auth dependency)
        user_id = getattr(request.state, "user_id", None)

        # Determine action
        action = f"{method} {path}"

        # Log the activity
        logging_service.log_user_activity(
            db=db,
            user_id=user_id,
            action=action,
            resource_type="http_request",
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "query_params": dict(request.query_params),
                "path_params": dict(request.path_params),
            },
            encrypt_details=False,  # Non-sensitive
        )

    except Exception as e:
        # Never break the app due to logging failure
        print(f"[ERROR] Failed to log request: {e}")
    finally:
        if "db" in locals():
            db.close()

    return response
