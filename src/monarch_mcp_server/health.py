"""
Proactive health monitoring for Monarch Money MCP Server.

Provides:
- Startup health checks to validate session before serving requests
- Library version monitoring to alert when updates are available
- Health report persistence for ecosystem integration
"""

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

HEALTH_REPORT_FILE = Path.home() / ".monarch-mcp" / "health_report.json"


class HealthStatus(Enum):
    """Overall health status of the Monarch connection."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"  # Working but with issues (e.g., session aging)
    UNHEALTHY = "unhealthy"  # Not working, needs intervention
    UNKNOWN = "unknown"  # Cannot determine status


@dataclass
class HealthCheckResult:
    """Result of a comprehensive health check."""

    status: HealthStatus
    session_valid: bool
    session_age_days: Optional[float]
    api_reachable: bool
    last_check: str  # ISO format datetime
    error_message: Optional[str] = None
    recommendation: Optional[str] = None
    library_version: Optional[str] = None
    latest_library_version: Optional[str] = None
    update_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["status"] = self.status.value
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HealthCheckResult":
        """Create from dictionary."""
        data = data.copy()
        data["status"] = HealthStatus(data["status"])
        return cls(**data)


async def perform_health_check(
    session_manager: Any, skip_api_check: bool = False
) -> HealthCheckResult:
    """
    Perform a comprehensive health check.

    Args:
        session_manager: SecureMonarchSession instance
        skip_api_check: If True, skip the API reachability test (faster but less thorough)

    Returns:
        HealthCheckResult with current status
    """
    now = datetime.now(timezone.utc).isoformat()

    # Get session metadata
    metadata = session_manager.load_session_metadata()
    session_age_days = metadata.age_days if metadata else None

    # Check if we have credentials
    token = session_manager.load_token()
    session_file = session_manager.session_file_path()
    has_credentials = token is not None or session_file.exists()

    if not has_credentials:
        return HealthCheckResult(
            status=HealthStatus.UNHEALTHY,
            session_valid=False,
            session_age_days=None,
            api_reachable=False,
            last_check=now,
            error_message="No saved session or token found",
            recommendation="Run login_setup.py to authenticate",
        )

    # Check session age warnings
    session_warning = None
    if metadata:
        if metadata.is_likely_expired:
            session_warning = (
                f"Session is {round(metadata.age_days)} days old and likely expired"
            )
        elif metadata.is_approaching_expiry:
            session_warning = (
                f"Session is {round(metadata.age_days)} days old, consider re-authenticating soon"
            )

    # Test API reachability if requested
    api_reachable = False
    api_error = None

    if not skip_api_check:
        try:
            from monarchmoney import MonarchMoney

            client = session_manager.get_authenticated_client()
            if client is None and session_file.exists():
                client = MonarchMoney(session_file=str(session_file))
                await client.login(use_saved_session=True, save_session=False)

            if client:
                # Lightweight test call
                await client.get_accounts()
                api_reachable = True

                # Update metadata on successful validation
                if metadata:
                    metadata.record_validation_success()
                    metadata.record_successful_call()
                    session_manager.save_session_metadata(metadata)

        except Exception as e:
            api_error = str(e)
            logger.warning("API health check failed: %s", e)

            # Update failure count
            if metadata:
                metadata.record_validation_failure()
                session_manager.save_session_metadata(metadata)

    # Determine overall status
    if api_reachable:
        if session_warning and metadata and metadata.is_likely_expired:
            status = HealthStatus.DEGRADED
        elif session_warning:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
    elif skip_api_check:
        # Can't determine without API check
        if metadata and metadata.is_likely_expired:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.UNKNOWN
    else:
        status = HealthStatus.UNHEALTHY

    # Build recommendation
    recommendation = None
    if status == HealthStatus.UNHEALTHY:
        if api_error and "401" in api_error or "403" in api_error:
            recommendation = "Session expired. Run login_setup.py to re-authenticate"
        elif api_error and "525" in api_error:
            recommendation = "SSL/Cloudflare error. This may be temporary - retry later or check monarchmoneycommunity for updates"
        else:
            recommendation = session_warning or "Run login_setup.py to re-authenticate"
    elif status == HealthStatus.DEGRADED:
        recommendation = session_warning

    return HealthCheckResult(
        status=status,
        session_valid=api_reachable or (has_credentials and skip_api_check),
        session_age_days=session_age_days,
        api_reachable=api_reachable,
        last_check=now,
        error_message=api_error,
        recommendation=recommendation,
    )


async def check_library_version() -> Dict[str, Any]:
    """
    Check if a newer version of monarchmoneycommunity is available on PyPI.

    Returns:
        Dict with current_version, latest_version, update_available, and any error
    """
    import importlib.metadata

    result: Dict[str, Any] = {
        "current_version": None,
        "latest_version": None,
        "update_available": False,
        "error": None,
    }

    # Get installed version
    try:
        result["current_version"] = importlib.metadata.version("monarchmoneycommunity")
    except importlib.metadata.PackageNotFoundError:
        # Try the old package name as fallback
        try:
            result["current_version"] = importlib.metadata.version("monarchmoney")
            result["error"] = "Using old 'monarchmoney' package. Consider upgrading to 'monarchmoneycommunity'"
            result["update_available"] = True
            return result
        except importlib.metadata.PackageNotFoundError:
            result["error"] = "monarchmoneycommunity package not found"
            return result

    # Check PyPI for latest version
    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://pypi.org/pypi/monarchmoneycommunity/json",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    result["latest_version"] = data.get("info", {}).get("version")

                    # Compare versions
                    if result["latest_version"] and result["current_version"]:
                        try:
                            from packaging.version import parse

                            current = parse(result["current_version"])
                            latest = parse(result["latest_version"])
                            result["update_available"] = latest > current
                        except Exception:
                            # Simple string comparison as fallback
                            result["update_available"] = (
                                result["latest_version"] != result["current_version"]
                            )
                else:
                    result["error"] = f"PyPI returned status {response.status}"

    except Exception as e:
        result["error"] = f"Failed to check PyPI: {e}"

    return result


async def startup_health_check(session_manager: Any) -> HealthCheckResult:
    """
    Perform health check at server startup.

    Logs results clearly and saves health report for ecosystem integration.
    Non-blocking: logs warnings but doesn't prevent server from starting.

    Args:
        session_manager: SecureMonarchSession instance

    Returns:
        HealthCheckResult
    """
    logger.info("Performing startup health check...")

    # Perform the health check
    result = await perform_health_check(session_manager, skip_api_check=False)

    # Check for library updates
    version_info = await check_library_version()
    result.library_version = version_info.get("current_version")
    result.latest_library_version = version_info.get("latest_version")
    result.update_available = version_info.get("update_available", False)

    # Log results
    status_emoji = {
        HealthStatus.HEALTHY: "✅",
        HealthStatus.DEGRADED: "⚠️",
        HealthStatus.UNHEALTHY: "❌",
        HealthStatus.UNKNOWN: "❓",
    }

    emoji = status_emoji.get(result.status, "❓")
    logger.info(f"{emoji} Monarch connection status: {result.status.value}")

    if result.session_age_days is not None:
        logger.info(f"   Session age: {result.session_age_days:.1f} days")

    if result.api_reachable:
        logger.info("   API reachable: Yes")
    elif result.error_message:
        logger.warning(f"   API error: {result.error_message}")

    if result.recommendation:
        logger.warning(f"   Recommendation: {result.recommendation}")

    if result.update_available:
        logger.info(
            f"   Library update available: {result.library_version} → {result.latest_library_version}"
        )

    # Save health report for ecosystem integration
    save_health_report(result)

    return result


def save_health_report(result: HealthCheckResult) -> None:
    """Save health report to file for ecosystem integration."""
    try:
        HEALTH_REPORT_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        fd = os.open(
            HEALTH_REPORT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)
        finally:
            try:
                HEALTH_REPORT_FILE.chmod(0o600)
            except Exception:
                pass

        logger.debug(f"Health report saved to {HEALTH_REPORT_FILE}")

    except Exception as e:
        logger.warning(f"Failed to save health report: {e}")


def load_health_report() -> Optional[HealthCheckResult]:
    """Load health report from file."""
    try:
        if HEALTH_REPORT_FILE.exists():
            data = json.loads(HEALTH_REPORT_FILE.read_text())
            return HealthCheckResult.from_dict(data)
    except Exception as e:
        logger.warning(f"Failed to load health report: {e}")
    return None
