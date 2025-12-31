"""
Backup Service - Automated database backups.

"""

import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from typing import List
from urllib.parse import urlparse

load_dotenv()


class BackupService:
    """
    Service for automated database backups.
    Uses pg_dump for PostgreSQL/Neon backups.
    """

    def __init__(self):
        self.database_url = os.getenv("DATABASE_URL")
        if not self.database_url:
            raise ValueError("DATABASE_URL not found in environment variables")

        self.backup_dir = Path(os.getenv("BACKUP_DIR", "./backups"))
        self.retention_days = int(os.getenv("BACKUP_RETENTION_DAYS", "30"))

        # Create backup directory if it doesn't exist
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self) -> str:
        """
        Create a database backup using pg_dump.

        Returns:
            Path to the backup file
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}.sql"
        backup_path = self.backup_dir / backup_filename

        try:
            from urllib.parse import urlparse

            # Parse DATABASE_URL
            parsed = urlparse(self.database_url)

            pg_dump_exe = r"C:\Program Files\PostgreSQL\18\bin\pg_dump.exe"
            # Build pg_dump command
            if not os.path.isfile(pg_dump_exe):
                raise FileNotFoundError(f"pg_dump.exe not found at: {pg_dump_exe}")
            cmd = [
                pg_dump_exe,
                "-h",
                parsed.hostname or "",  # Neon host
                "-p",
                str(parsed.port or 5432),
                "-U",
                parsed.username or "",
                "-d",
                parsed.path.lstrip("/"),  # db name
                "-F",
                "c",  # Custom format (compressed)
                "-f",
                str(backup_path),
            ]

            # Set password via environment variable
            env = os.environ.copy()
            env["PGPASSWORD"] = parsed.password or ""

            # Execute backup
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            if result.returncode != 0:
                raise Exception(f"pg_dump failed: {result.stderr.strip()}")

            print(f"[INFO] Backup created successfully: {backup_path}")

            # Clean up old backups
            self.cleanup_old_backups()

            return str(backup_path)

        except Exception as e:
            print(f"[ERROR] Backup failed: {e}")
            raise

    def cleanup_old_backups(self) -> None:
        """
        Delete backups older than retention_days.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)

        for backup_file in self.backup_dir.glob("backup_*.sql"):
            try:
                timestamp_str = backup_file.stem.replace("backup_", "")
                file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                if file_date < cutoff_date:
                    backup_file.unlink()
                    print(f"[INFO] Deleted old backup: {backup_file.name}")
            except Exception as e:
                print(f"[WARNING] Could not process {backup_file.name}: {e}")

    def list_backups(self) -> List[dict]:
        """
        List all available backups with details.

        Returns:
            List of backup info dictionaries
        """
        backups = []

        for backup_file in sorted(self.backup_dir.glob("backup_*.sql"), reverse=True):
            try:
                timestamp_str = backup_file.stem.replace("backup_", "")
                file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                backups.append(
                    {
                        "filename": backup_file.name,
                        "path": str(backup_file),
                        "timestamp": file_date.isoformat(),
                        "size_mb": round(backup_file.stat().st_size / (1024 * 1024), 2),
                    }
                )
            except Exception as e:
                print(
                    f"[WARNING] Could not process backup file {backup_file.name}: {e}"
                )

        return backups

    def test_restore(self, backup_path: str) -> bool:
        """
        Test if a backup file is valid without restoring it.

        Args:
            backup_path: Path to the backup file

        Returns:
            True if valid, False otherwise
        """
        try:
            result = subprocess.run(
                ["pg_restore", "--list", backup_path], capture_output=True, text=True
            )

            if result.returncode == 0:
                print(f"[INFO] Backup validation successful: {backup_path}")
                return True
            else:
                print(f"[WARNING] Backup validation failed: {result.stderr.strip()}")
                return False
        except Exception as e:
            print(f"[ERROR] Backup validation failed: {e}")
            return False


# Singleton instance
backup_service = BackupService()
