"""
Resilient API wrapper with retry logic and error classification for Monarch Money.

This module provides:
- Error classification to distinguish transient vs permanent failures
- Retry with exponential backoff for transient network errors
- Session refresh attempts before requiring manual re-authentication
"""

import asyncio
import logging
import random
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Dict, Optional, TypeVar

from aiohttp.client_exceptions import (
    ClientConnectorError,
    ClientResponseError,
    ClientSSLError,
    ServerDisconnectedError,
    ServerTimeoutError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


def run_async(coro: Any) -> Any:
    """Run async function in a new thread with its own event loop."""

    def _run() -> Any:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    with ThreadPoolExecutor() as executor:
        future = executor.submit(_run)
        return future.result()


class ErrorCategory(Enum):
    """Classification of errors for handling strategy."""

    TRANSIENT_NETWORK = auto()  # 525, 502, 503, 504, SSL errors - retry with backoff
    AUTH_EXPIRED = auto()  # 401, 403 - try refresh, then re-auth
    RATE_LIMITED = auto()  # 429 - respect Retry-After, longer backoff
    PERMANENT = auto()  # 400, 404, etc - fail immediately
    UNKNOWN = auto()  # Unknown errors - log and retry once


@dataclass
class ClassifiedError:
    """Wrapper around an exception with classification metadata."""

    category: ErrorCategory
    original_error: Exception
    status_code: Optional[int] = None
    retry_after: Optional[float] = None
    message: str = ""

    @property
    def is_retryable(self) -> bool:
        return self.category in (
            ErrorCategory.TRANSIENT_NETWORK,
            ErrorCategory.RATE_LIMITED,
            ErrorCategory.UNKNOWN,
        )

    @property
    def requires_reauth(self) -> bool:
        return self.category == ErrorCategory.AUTH_EXPIRED


def classify_error(error: Exception) -> ClassifiedError:
    """Classify an exception into an error category for handling."""
    status_code = None
    retry_after = None

    # Check for HTTP status codes in various error types
    if isinstance(error, ClientResponseError):
        status_code = error.status
    elif hasattr(error, "code"):
        status_code = getattr(error, "code", None)
    elif hasattr(error, "status"):
        status_code = getattr(error, "status", None)

    # Extract status from error message as fallback
    error_str = str(error).lower()
    if status_code is None:
        for code in [525, 502, 503, 504, 401, 403, 429, 400, 404]:
            if str(code) in error_str:
                status_code = code
                break

    # Classify based on status code
    if status_code:
        if status_code in (525, 502, 503, 504):
            return ClassifiedError(
                category=ErrorCategory.TRANSIENT_NETWORK,
                original_error=error,
                status_code=status_code,
                message=f"Transient server error ({status_code}): Cloudflare/origin issue",
            )
        elif status_code in (401, 403):
            return ClassifiedError(
                category=ErrorCategory.AUTH_EXPIRED,
                original_error=error,
                status_code=status_code,
                message="Authentication expired or invalid",
            )
        elif status_code == 429:
            # Try to extract Retry-After header
            if hasattr(error, "headers") and error.headers:
                retry_after_val = error.headers.get("Retry-After")
                if retry_after_val:
                    try:
                        retry_after = float(retry_after_val)
                    except ValueError:
                        retry_after = 60.0
            return ClassifiedError(
                category=ErrorCategory.RATE_LIMITED,
                original_error=error,
                status_code=status_code,
                retry_after=retry_after or 60.0,
                message="Rate limited by API",
            )
        elif 400 <= status_code < 500:
            return ClassifiedError(
                category=ErrorCategory.PERMANENT,
                original_error=error,
                status_code=status_code,
                message=f"Client error ({status_code}): Request is invalid",
            )

    # Classify by exception type
    if isinstance(error, (ClientSSLError, ssl.SSLError)):
        return ClassifiedError(
            category=ErrorCategory.TRANSIENT_NETWORK,
            original_error=error,
            message="SSL/TLS handshake failure - likely Cloudflare issue",
        )

    if isinstance(error, (ServerDisconnectedError, ServerTimeoutError)):
        return ClassifiedError(
            category=ErrorCategory.TRANSIENT_NETWORK,
            original_error=error,
            message="Connection interrupted - network or server issue",
        )

    if isinstance(error, ClientConnectorError):
        return ClassifiedError(
            category=ErrorCategory.TRANSIENT_NETWORK,
            original_error=error,
            message="Failed to establish connection",
        )

    # Check for auth-related keywords in error message
    if any(
        keyword in error_str
        for keyword in ["unauthorized", "authentication", "token", "expired", "login"]
    ):
        return ClassifiedError(
            category=ErrorCategory.AUTH_EXPIRED,
            original_error=error,
            message="Authentication issue detected in error message",
        )

    # Default to unknown
    return ClassifiedError(
        category=ErrorCategory.UNKNOWN,
        original_error=error,
        message=f"Unclassified error: {type(error).__name__}",
    )


class AuthenticationRequiredError(Exception):
    """Raised when manual re-authentication is required."""

    pass


class MonarchAPIError(Exception):
    """Wrapper for Monarch API errors with classification info."""

    def __init__(self, message: str, last_error: Optional[ClassifiedError] = None):
        super().__init__(message)
        self.last_error = last_error


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True

    def get_delay(self, attempt: int, retry_after: Optional[float] = None) -> float:
        """Calculate delay for a given attempt number."""
        if retry_after:
            return min(retry_after, self.max_delay)

        delay = self.base_delay * (self.exponential_base**attempt)
        delay = min(delay, self.max_delay)

        if self.jitter:
            delay = delay * (0.5 + random.random())

        return delay


DEFAULT_RETRY_CONFIG = RetryConfig()


async def retry_with_backoff(
    coro_factory: Callable[[], Any],
    config: RetryConfig = DEFAULT_RETRY_CONFIG,
    on_retry: Optional[Callable[[int, ClassifiedError, float], None]] = None,
    on_auth_expired: Optional[Callable[[], Any]] = None,
) -> Any:
    """
    Execute an async operation with retry logic and exponential backoff.

    Args:
        coro_factory: Callable that creates the coroutine to execute
        config: Retry configuration
        on_retry: Callback for retry events (attempt, error, delay)
        on_auth_expired: Async callback when auth expires, returns True if refresh succeeded

    Returns:
        Result of the successful operation

    Raises:
        The last error if all retries exhausted, or a permanent error
    """
    last_error: Optional[ClassifiedError] = None

    for attempt in range(config.max_attempts):
        try:
            return await coro_factory()
        except Exception as e:
            classified = classify_error(e)
            last_error = classified

            logger.warning(
                "API call failed (attempt %d/%d): %s [%s]",
                attempt + 1,
                config.max_attempts,
                classified.message,
                type(e).__name__,
            )

            # Handle permanent errors immediately
            if classified.category == ErrorCategory.PERMANENT:
                logger.error("Permanent error, not retrying: %s", classified.message)
                raise e

            # Handle auth expiration
            if classified.requires_reauth:
                if on_auth_expired:
                    logger.info("Attempting session refresh...")
                    try:
                        refresh_result = on_auth_expired()
                        # Handle both sync and async callbacks
                        if asyncio.iscoroutine(refresh_result):
                            refresh_success = await refresh_result
                        else:
                            refresh_success = refresh_result

                        if refresh_success:
                            logger.info("Session refreshed, retrying request")
                            continue  # Retry immediately after refresh
                    except Exception as refresh_err:
                        logger.warning("Session refresh failed: %s", refresh_err)

                    logger.error("Session refresh failed, manual re-auth required")

                raise AuthenticationRequiredError(
                    "Session expired and refresh failed. Run: python login_setup.py"
                ) from e

            # Check if we have retries left
            if attempt + 1 >= config.max_attempts:
                logger.error(
                    "All %d retry attempts exhausted for: %s",
                    config.max_attempts,
                    classified.message,
                )
                break

            # Calculate delay
            delay = config.get_delay(attempt, classified.retry_after)

            if on_retry:
                on_retry(attempt + 1, classified, delay)

            logger.info("Retrying in %.1f seconds...", delay)
            await asyncio.sleep(delay)

    # All retries exhausted
    if last_error:
        raise MonarchAPIError(
            f"API call failed after {config.max_attempts} attempts: {last_error.message}",
            last_error=last_error,
        ) from last_error.original_error

    raise MonarchAPIError("API call failed with no error information")


class ResilientMonarchClient:
    """
    Wrapper around MonarchMoney that adds retry logic and session health monitoring.
    """

    def __init__(
        self,
        client: Any,  # MonarchMoney
        session_manager: Any,  # SecureMonarchSession
        retry_config: RetryConfig = DEFAULT_RETRY_CONFIG,
    ):
        self._client = client
        self._session_manager = session_manager
        self._retry_config = retry_config
        self._last_successful_call: Optional[float] = None
        self._consecutive_failures: int = 0

    @property
    def is_healthy(self) -> bool:
        """Check if the client appears to be in a healthy state."""
        return self._consecutive_failures < 3

    @property
    def underlying_client(self) -> Any:
        """Access the underlying MonarchMoney client."""
        return self._client

    def _update_client(self, new_client: Any) -> None:
        """Update the underlying client (used after session refresh)."""
        self._client = new_client

    async def _try_refresh_session(self) -> bool:
        """
        Attempt to refresh the session without user intervention.
        Returns True if successful.
        """
        try:
            from monarchmoney import MonarchMoney

            # Try to reload from session file (may have been refreshed by library)
            session_file = self._session_manager.session_file_path()
            if session_file.exists():
                new_client = MonarchMoney(session_file=str(session_file))
                await new_client.login(use_saved_session=True, save_session=True)

                # Test with a simple call
                await new_client.get_accounts()

                # Success - update our client
                self._client = new_client
                self._session_manager.save_authenticated_session(new_client)
                logger.info("Session refresh successful")
                return True
        except Exception as e:
            logger.warning("Session refresh attempt failed: %s", e)

        return False

    async def call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """
        Execute a method on the MonarchMoney client with retry logic.

        Args:
            method_name: Name of the method to call on the client
            *args, **kwargs: Arguments to pass to the method

        Returns:
            Result of the API call
        """
        method = getattr(self._client, method_name)

        def on_retry(attempt: int, error: ClassifiedError, delay: float) -> None:
            self._consecutive_failures += 1
            logger.info(
                "Retry %d for %s: %s (waiting %.1fs)",
                attempt,
                method_name,
                error.message,
                delay,
            )

        try:
            result = await retry_with_backoff(
                coro_factory=lambda: method(*args, **kwargs),
                config=self._retry_config,
                on_retry=on_retry,
                on_auth_expired=self._try_refresh_session,
            )

            # Success - reset failure counter
            self._consecutive_failures = 0
            self._last_successful_call = time.time()

            return result

        except AuthenticationRequiredError:
            raise
        except Exception:
            self._consecutive_failures += 1
            raise

    # Convenience methods for common operations
    async def get_accounts(self) -> Dict[str, Any]:
        return await self.call("get_accounts")

    async def get_transactions(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.call("get_transactions", **kwargs)

    async def get_budgets(self) -> Dict[str, Any]:
        return await self.call("get_budgets")

    async def get_cashflow(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.call("get_cashflow", **kwargs)

    async def get_account_holdings(self, account_id: str) -> Dict[str, Any]:
        return await self.call("get_account_holdings", account_id)

    async def create_transaction(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.call("create_transaction", **kwargs)

    async def update_transaction(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.call("update_transaction", **kwargs)

    async def request_accounts_refresh(self) -> Dict[str, Any]:
        return await self.call("request_accounts_refresh")
