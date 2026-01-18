"""
Secure session management for Monarch Money MCP Server.

Uses file-based token storage as primary method (works in MCP subprocess),
with keyring as secondary option for interactive use.

Includes session health monitoring and metadata tracking.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from monarchmoney import MonarchMoney

logger = logging.getLogger(__name__)

TOKEN_DIR = Path.home() / ".monarch-mcp"
TOKEN_FILE = TOKEN_DIR / "token"
SESSION_FILE = TOKEN_DIR / "session.json"
SESSION_METADATA_FILE = TOKEN_DIR / "session_metadata.json"
KEYRING_SERVICE = "com.mcp.monarch-mcp-server"
KEYRING_USERNAME = "monarch-token"

# Session age thresholds
SESSION_MAX_AGE_DAYS = 14  # Sessions typically last ~2 weeks
SESSION_WARNING_AGE_DAYS = 10  # Warn when approaching expiry


@dataclass
class SessionMetadata:
    """Metadata about the current session for health monitoring."""

    created_at: str  # ISO format datetime
    last_validated_at: Optional[str] = None
    last_successful_call_at: Optional[str] = None
    validation_failure_count: int = 0
    token_prefix: Optional[str] = None  # First 8 chars for identification

    @classmethod
    def create_new(cls, token: Optional[str] = None) -> "SessionMetadata":
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            created_at=now,
            last_validated_at=now,
            token_prefix=token[:8] if token else None,
        )

    @property
    def age_days(self) -> float:
        try:
            created = datetime.fromisoformat(self.created_at)
            return (datetime.now(timezone.utc) - created).total_seconds() / 86400
        except (ValueError, TypeError):
            return 0.0

    @property
    def is_approaching_expiry(self) -> bool:
        return self.age_days > SESSION_WARNING_AGE_DAYS

    @property
    def is_likely_expired(self) -> bool:
        return self.age_days > SESSION_MAX_AGE_DAYS

    def record_validation_success(self) -> None:
        self.last_validated_at = datetime.now(timezone.utc).isoformat()
        self.validation_failure_count = 0

    def record_validation_failure(self) -> None:
        self.validation_failure_count += 1

    def record_successful_call(self) -> None:
        self.last_successful_call_at = datetime.now(timezone.utc).isoformat()


class SecureMonarchSession:

    def _ensure_token_dir(self) -> None:
        TOKEN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Tighten perms best-effort in case the directory already existed.
        try:
            TOKEN_DIR.chmod(0o700)
        except Exception:
            pass

    def _save_token_file(self, token: str) -> None:
        """
        Save token to ~/.monarch-mcp/token with permissions 0600.

        Avoid Path.write_text() so the file is created with 0600 (rather than
        default umask perms and then chmod'd).
        """
        self._ensure_token_dir()
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(token)
        finally:
            # Ensure perms even if the file already existed with broader mode.
            try:
                TOKEN_FILE.chmod(0o600)
            except Exception:
                pass

    def session_file_path(self) -> Path:
        """
        Path to a stable, long-lived MonarchMoney session file.

        We prefer this over the token because MonarchMoney can refresh sessions.
        """
        self._ensure_token_dir()
        return SESSION_FILE

    def delete_session_file(self) -> None:
        """Delete the saved MonarchMoney session file (best-effort)."""
        try:
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
        except Exception:
            pass

    def save_token(self, token: str) -> None:
        try:
            self._save_token_file(token)
            logger.info(f"Token saved to {TOKEN_FILE}")
            try:
                import keyring

                keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, token)
                logger.info("Token saved securely to keyring")
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
            raise

    def load_token(self) -> Optional[str]:
        try:
            if TOKEN_FILE.exists():
                token = TOKEN_FILE.read_text().strip()
                if token:
                    return token
        except Exception:
            pass
        try:
            import keyring

            token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if token:
                # Best-effort: copy keyring token into the file so a sandboxed MCP
                # subprocess can use it even if it can't access macOS Keychain.
                try:
                    self._save_token_file(token)
                except Exception:
                    pass
                return token
        except Exception:
            pass
        return None

    def delete_token(self) -> None:
        try:
            if TOKEN_FILE.exists():
                TOKEN_FILE.unlink()
        except Exception:
            pass
        try:
            import keyring

            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
        except Exception:
            pass

    def get_authenticated_client(self) -> Optional[MonarchMoney]:
        token = self.load_token()
        if not token:
            return None
        try:
            return MonarchMoney(token=token)
        except Exception:
            return None

    def save_authenticated_session(self, mm: MonarchMoney) -> None:
        if mm.token:
            self.save_token(mm.token)

            # Create or update metadata
            metadata = self.load_session_metadata()
            if metadata is None or metadata.token_prefix != mm.token[:8]:
                # New session
                metadata = SessionMetadata.create_new(mm.token)
            else:
                metadata.record_successful_call()

            self.save_session_metadata(metadata)

        # Best-effort tighten perms on the session file if MonarchMoney wrote it.
        try:
            sf = self.session_file_path()
            if sf.exists():
                sf.chmod(0o600)
        except Exception:
            pass

    # Session metadata management

    def save_session_metadata(self, metadata: SessionMetadata) -> None:
        """Save session metadata to file."""
        try:
            self._ensure_token_dir()
            fd = os.open(
                SESSION_METADATA_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(asdict(metadata), f, indent=2)
            finally:
                try:
                    SESSION_METADATA_FILE.chmod(0o600)
                except Exception:
                    pass
        except Exception as e:
            logger.warning("Failed to save session metadata: %s", e)

    def load_session_metadata(self) -> Optional[SessionMetadata]:
        """Load session metadata from file."""
        try:
            if SESSION_METADATA_FILE.exists():
                data = json.loads(SESSION_METADATA_FILE.read_text())
                return SessionMetadata(**data)
        except Exception as e:
            logger.warning("Failed to load session metadata: %s", e)
        return None

    def delete_session_metadata(self) -> None:
        """Delete session metadata file."""
        try:
            if SESSION_METADATA_FILE.exists():
                SESSION_METADATA_FILE.unlink()
        except Exception:
            pass

    def get_session_health_report(self) -> Dict[str, Any]:
        """Generate a health report for the current session."""
        metadata = self.load_session_metadata()
        token = self.load_token()
        session_file = self.session_file_path()

        report: Dict[str, Any] = {
            "has_token": token is not None,
            "has_session_file": session_file.exists(),
            "has_metadata": metadata is not None,
            "status": "unknown",
            "recommendations": [],
        }

        if not token and not session_file.exists():
            report["status"] = "not_authenticated"
            report["recommendations"].append("Run login_setup.py to authenticate")
            return report

        if metadata:
            report["session_age_days"] = round(metadata.age_days, 1)
            report["validation_failures"] = metadata.validation_failure_count
            report["last_successful_call"] = metadata.last_successful_call_at

            if metadata.is_likely_expired:
                report["status"] = "likely_expired"
                report["recommendations"].append(
                    f"Session is {round(metadata.age_days)} days old and likely expired. "
                    "Run login_setup.py to re-authenticate."
                )
            elif metadata.is_approaching_expiry:
                report["status"] = "approaching_expiry"
                report["recommendations"].append(
                    f"Session is {round(metadata.age_days)} days old. "
                    "Consider re-authenticating soon."
                )
            elif metadata.validation_failure_count >= 3:
                report["status"] = "degraded"
                report["recommendations"].append(
                    "Multiple validation failures detected. Session may be invalid."
                )
            else:
                report["status"] = "healthy"
        else:
            report["status"] = "unknown_health"
            report["recommendations"].append(
                "No session metadata found. Session health cannot be determined."
            )

        return report

    async def validate_session(self) -> bool:
        """
        Perform a lightweight validation of the current session.
        Updates metadata based on result.
        Returns True if session is valid.
        """
        metadata = self.load_session_metadata()

        try:
            client = self.get_authenticated_client()
            if client is None:
                # Try session file
                session_file = self.session_file_path()
                if not session_file.exists():
                    return False
                client = MonarchMoney(session_file=str(session_file))
                await client.login(use_saved_session=True, save_session=False)

            # Test with accounts call (lightweight)
            await client.get_accounts()

            # Success - update metadata
            if metadata:
                metadata.record_validation_success()
                metadata.record_successful_call()
            else:
                metadata = SessionMetadata.create_new(client.token)

            self.save_session_metadata(metadata)
            return True

        except Exception as e:
            logger.warning("Session validation failed: %s", e)
            if metadata:
                metadata.record_validation_failure()
                self.save_session_metadata(metadata)
            return False


secure_session = SecureMonarchSession()
