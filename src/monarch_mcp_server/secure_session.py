"""
Secure session management for Monarch Money MCP Server using keyring.
"""

import keyring
import logging
import os
import sys
from pathlib import Path
from typing import Optional
from monarchmoney import MonarchMoney

logger = logging.getLogger(__name__)

# Keyring service identifiers
KEYRING_SERVICE = "com.mcp.monarch-mcp-server"
KEYRING_USERNAME = "monarch-token"


def _app_support_dir() -> Path:
    """
    Stable per-user location for storing a refreshable Monarch session file.

    macOS: ~/Library/Application Support/monarch-mcp-server/
    else:  ~/.monarch-mcp-server/
    """
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "monarch-mcp-server"
    return home / ".monarch-mcp-server"


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except Exception:
        pass


def _ensure_private_file(path: Path) -> None:
    try:
        path.chmod(0o600)
    except Exception:
        pass


class SecureMonarchSession:
    """Manages Monarch Money sessions securely using the system keyring."""

    def session_file_path(self) -> Path:
        """Absolute path where the refreshable Monarch session is stored."""
        d = _app_support_dir()
        _ensure_private_dir(d)
        return d / "mm_session.pickle"

    def save_token(self, token: str) -> None:
        """Save the authentication token to the system keyring."""
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, token)
            logger.info("✅ Token saved securely to keyring")

        except Exception as e:
            logger.error(f"❌ Failed to save token to keyring: {e}")
            raise

    def load_token(self) -> Optional[str]:
        """Load the authentication token from the system keyring."""
        try:
            token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if token:
                logger.info("✅ Token loaded from keyring")
                return token
            else:
                logger.info("🔍 No token found in keyring")
                return None
        except Exception as e:
            logger.error(f"❌ Failed to load token from keyring: {e}")
            return None

    def delete_token(self) -> None:
        """Delete the authentication token from the system keyring."""
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
            logger.info("🗑️ Token deleted from keyring")

        except keyring.errors.PasswordDeleteError:
            logger.info("🔍 No token found in keyring to delete")
        except Exception as e:
            logger.error(f"❌ Failed to delete token from keyring: {e}")

    def delete_session_file(self) -> None:
        """Delete the refreshable session file (if present)."""
        try:
            p = self.session_file_path()
            if p.exists():
                p.unlink()
                logger.info("🗑️ Session file deleted: %s", p)
        except Exception as e:
            logger.warning("⚠️  Failed to delete session file: %s", e)

    def get_authenticated_client(self) -> Optional[MonarchMoney]:
        """Get an authenticated MonarchMoney client (best-effort, no network)."""
        # Prefer refreshable session file if present.
        try:
            session_file = self.session_file_path()
            if session_file.exists():
                client = MonarchMoney(session_file=str(session_file))
                logger.info("✅ MonarchMoney client created with saved session file")
                return client
        except Exception as e:
            logger.warning("⚠️  Could not use session file: %s", e)

        # Fallback to keyring token.
        token = self.load_token()
        if not token:
            return None

        try:
            client = MonarchMoney(token=token)
            logger.info("✅ MonarchMoney client created with stored token")
            return client
        except Exception as e:
            logger.error(f"❌ Failed to create MonarchMoney client: {e}")
            return None

    def save_authenticated_session(self, mm: MonarchMoney) -> None:
        """Save the session from an authenticated MonarchMoney instance."""
        # Ensure the session file (if present) stays private.
        try:
            session_file = self.session_file_path()
            if session_file.exists():
                _ensure_private_file(session_file)
        except Exception:
            pass

        if mm.token:
            self.save_token(mm.token)
        else:
            logger.warning("⚠️  MonarchMoney instance has no token to save")

    def _cleanup_old_session_files(self) -> None:
        """Clean up old insecure session files."""
        cleanup_paths = [
            "monarch_session.json",
        ]

        for path in cleanup_paths:
            try:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        os.remove(path)
                        logger.info(f"🗑️ Cleaned up old insecure session file: {path}")
                    elif os.path.isdir(path) and not os.listdir(path):
                        os.rmdir(path)
                        logger.info(f"🗑️ Cleaned up empty session directory: {path}")
            except Exception as e:
                logger.warning(f"⚠️  Could not clean up {path}: {e}")


# Global session manager instance
secure_session = SecureMonarchSession()
