"""Monarch Money MCP Server - Main server implementation."""

import json
import logging
import os
from typing import Any, Dict, Optional

import aiohttp
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from monarchmoney import MonarchMoney
from pydantic import BaseModel, Field

from monarch_mcp_server.health import (
    HealthStatus,
    check_library_version,
    load_health_report,
    perform_health_check,
    startup_health_check,
)
from monarch_mcp_server.resilience import (
    AuthenticationRequiredError,
    MonarchAPIError,
    ResilientMonarchClient,
    RetryConfig,
    classify_error,
    run_async,
)
from monarch_mcp_server.secure_session import secure_session
from monarch_mcp_server.security import enforce_gql_aiohttp_tls_verification

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security hardening: verify TLS certificates for HTTPS by default.
enforce_gql_aiohttp_tls_verification()

# Load environment variables
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("Monarch Money MCP Server")

# Global resilient client instance
_resilient_client: Optional[ResilientMonarchClient] = None


class MonarchConfig(BaseModel):
    """Configuration for Monarch Money connection."""

    email: Optional[str] = Field(default=None, description="Monarch Money email")
    password: Optional[str] = Field(
        default=None, description="Monarch Money password"
    )
    session_file: str = Field(
        default="monarch_session.json", description="Session file path"
    )


async def get_monarch_client() -> MonarchMoney:
    """
    Get or create MonarchMoney client instance using secure session storage.

    Uses monarchmoneycommunity library with updated API endpoint.

    Returns:
        Authenticated MonarchMoney client.

    Raises:
        RuntimeError: If no valid session exists and no credentials available.
    """
    session_file = secure_session.session_file_path()

    # 1) Try saved session file (preferred method)
    if session_file.exists():
        try:
            client = MonarchMoney(
                session_file=str(session_file),
                timeout=30
            )
            # Load and validate the saved session
            await client.login(use_saved_session=True, save_session=True)
            logger.info("Using authenticated client from saved session file")
            # Also keep token in keyring as a fallback.
            secure_session.save_authenticated_session(client)
            return client
        except Exception as e:
            logger.warning(
                "Failed to use saved session file; will try token fallback: %s", e
            )

    # 2) Fallback to keyring token.
    client = secure_session.get_authenticated_client()
    if client is not None:
        logger.info("Using authenticated client from secure keyring storage")
        return client

    # 2) Fallback to keyring token
    token = secure_session.load_token()
    if token:
        try:
            client = MonarchMoney(
                session_file=str(session_file),
                token=token,
                timeout=30
            )
            # Validate the token works
            await client.login(use_saved_session=True, save_session=True)
            logger.info("✅ Using authenticated client from keyring token")
            return client
        except Exception as e:
            logger.warning("⚠️  Keyring token failed: %s", e)

    # 3) Try environment credentials as last resort
    email = os.getenv("MONARCH_EMAIL")
    password = os.getenv("MONARCH_PASSWORD")

    if email and password:
        try:
            client = MonarchMoney(
                session_file=str(secure_session.session_file_path())
            )
            await client.login(email, password)
            logger.info(
                "Successfully logged into Monarch Money with environment credentials"
            )
            await client.login(email, password, save_session=True)
            logger.info("✅ Logged in with environment credentials")

            # Save token as backup
            if client.token:
                secure_session.save_token(client.token)
            return client
        except Exception as e:
            logger.error(f"❌ Failed to login with env credentials: {e}")
            raise

    raise RuntimeError(
        "Authentication needed! Run: python login_setup.py"
    )


async def get_resilient_client() -> ResilientMonarchClient:
    """Get or create a resilient MonarchMoney client with retry logic."""
    global _resilient_client

    if _resilient_client is not None and _resilient_client.is_healthy:
        return _resilient_client

    # Get the underlying client
    raw_client = await get_monarch_client()

    # Wrap in resilient client
    _resilient_client = ResilientMonarchClient(
        client=raw_client,
        session_manager=secure_session,
        retry_config=RetryConfig(
            max_attempts=5,
            base_delay=1.0,
            max_delay=60.0,
        ),
    )

    return _resilient_client


def _format_auth_error() -> str:
    """Format a helpful authentication error message."""
    return """Authentication Required

Your Monarch Money session has expired and could not be refreshed automatically.

To fix this:
1. Open Terminal
2. Navigate to your monarch-mcp-server directory
3. Run: python login_setup.py
4. Follow the prompts to re-authenticate

This typically happens every 2-3 weeks."""


def _format_api_error(e: MonarchAPIError) -> str:
    """Format an API error with helpful context."""
    error_info = {
        "error": "API Error",
        "message": str(e),
        "category": e.last_error.category.name if e.last_error else "UNKNOWN",
        "status_code": e.last_error.status_code if e.last_error else None,
        "suggestion": "Try again in a few moments. If the problem persists, run: python login_setup.py",
    }
    return json.dumps(error_info, indent=2)


@mcp.tool()
def setup_authentication() -> str:
    """Get instructions for setting up secure authentication with Monarch Money."""
    return """Monarch Money - One-Time Setup

1. Open Terminal and run:
   python login_setup.py

2. Enter your Monarch Money credentials when prompted
   - Email and password
   - 2FA code if you have MFA enabled

3. Session will be saved automatically and last for weeks

4. Start using Monarch tools in Claude Desktop:
   - get_accounts - View all accounts
   - get_transactions - Recent transactions
   - get_budgets - Budget information

Session persists across Claude restarts.
No need to re-authenticate frequently.
All credentials stay secure in terminal."""


@mcp.tool()
def check_auth_status() -> str:
    """Check if already authenticated with Monarch Money."""
    try:
        # Check if we have a token in the keyring
        token = secure_session.load_token()
        if token:
            status = "Authentication token found in secure storage\n"
        else:
            status = "No authentication token found\n"

        email = os.getenv("MONARCH_EMAIL")
        if email:
            status += f"Environment email: {email}\n"

        status += (
            "\nTry get_accounts to test connection or run login_setup.py if needed."
        )

        return status
    except Exception as e:
        return f"Error checking auth status: {str(e)}"


@mcp.tool()
def check_session_health() -> str:
    """
    Check the health of the current Monarch Money session.
    Provides diagnostics about session age, recent failures, and recommendations.
    """
    try:
        report = secure_session.get_session_health_report()

        status_indicator = {
            "healthy": "[OK]",
            "approaching_expiry": "[WARN]",
            "likely_expired": "[ERROR]",
            "degraded": "[WARN]",
            "not_authenticated": "[ERROR]",
            "unknown_health": "[WARN]",
            "unknown": "[WARN]",
        }.get(report.get("status", "unknown"), "[WARN]")

        output = [
            "Session Health Report",
            "=" * 40,
            f"Status: {status_indicator} {report.get('status', 'unknown').replace('_', ' ').title()}",
            "",
        ]

        if report.get("has_token"):
            output.append("Token: Present in secure storage")
        else:
            output.append("Token: Not found")

        if report.get("has_session_file"):
            output.append("Session file: Present")
        else:
            output.append("Session file: Not found")

        if "session_age_days" in report:
            output.append(f"Session age: {report['session_age_days']} days")

        if "validation_failures" in report:
            output.append(f"Recent validation failures: {report['validation_failures']}")

        if "last_successful_call" in report and report["last_successful_call"]:
            output.append(f"Last successful API call: {report['last_successful_call']}")

        if report.get("recommendations"):
            output.append("")
            output.append("Recommendations:")
            for rec in report["recommendations"]:
                output.append(f"  - {rec}")

        return "\n".join(output)
    except Exception as e:
        return f"Error checking session health: {str(e)}"


@mcp.tool()
def validate_session() -> str:
    """
    Actively validate the current session by making a test API call.
    This will update session health metrics and may trigger automatic refresh.
    """
    try:

        async def _validate():
            return await secure_session.validate_session()

        is_valid = run_async(_validate())

        if is_valid:
            return """Session Validation: SUCCESS

Your Monarch Money session is valid and working correctly.
Session health metrics have been updated."""
        else:
            return """Session Validation: FAILED

Your session could not be validated. This may indicate:
- Session has expired
- Network connectivity issues
- Monarch Money service is temporarily unavailable

Recommendations:
1. Wait a few minutes and try again (may be temporary)
2. Check your internet connection
3. If problem persists, run: python login_setup.py"""
    except Exception as e:
        return f"""Session Validation: ERROR

An error occurred during validation: {str(e)}

If this persists, run: python login_setup.py"""


@mcp.tool()
def diagnose_connection() -> str:
    """
    Run comprehensive connection diagnostics.
    Tests network connectivity, SSL, and authentication in sequence.
    """
    try:

        async def _diagnose():
            results = []

            # Test 1: Basic HTTPS connectivity
            results.append("Test 1: HTTPS Connectivity to Monarch")
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://api.monarchmoney.com",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        results.append(f"  - Status: {resp.status}")
                        if resp.status < 500:
                            results.append("  - Result: OK")
                        else:
                            results.append("  - Result: SERVER ERROR")
            except aiohttp.ClientSSLError as e:
                results.append(f"  - SSL Error: {str(e)}")
                results.append("  - Result: SSL FAILURE (525 error likely)")
            except Exception as e:
                results.append(f"  - Error: {str(e)}")
                results.append("  - Result: CONNECTION FAILURE")

            # Test 2: Session file check
            results.append("")
            results.append("Test 2: Session Storage")
            session_file = secure_session.session_file_path()
            token = secure_session.load_token()
            results.append(
                f"  - Session file: {'EXISTS' if session_file.exists() else 'MISSING'}"
            )
            results.append(f"  - Token: {'PRESENT' if token else 'MISSING'}")

            # Test 3: API authentication (if we have credentials)
            results.append("")
            results.append("Test 3: API Authentication")
            if not token and not session_file.exists():
                results.append("  - Skipped: No credentials available")
            else:
                try:
                    is_valid = await secure_session.validate_session()
                    results.append(f"  - Result: {'OK' if is_valid else 'FAILED'}")
                except Exception as e:
                    classified = classify_error(e)
                    results.append(f"  - Error: {classified.message}")
                    results.append(f"  - Category: {classified.category.name}")
                    results.append("  - Result: FAILED")

            return "\n".join(results)

        return run_async(_diagnose())
    except Exception as e:
        return f"Diagnostic error: {str(e)}"


@mcp.tool()
def debug_session_loading() -> str:
    """Debug keyring session loading issues."""
    try:
        # Check keyring access
        token = secure_session.load_token()
        if token:
            return f"Token found in storage (length: {len(token)})"
        else:
            return "No token found. Run login_setup.py to authenticate."
    except Exception as e:
        import traceback

        error_details = traceback.format_exc()
        return f"Session loading failed:\nError: {str(e)}\nType: {type(e)}\nTraceback:\n{error_details}"


@mcp.tool()
def get_health_report() -> str:
    """
    Get the current health report for the Monarch Money connection.
    Includes session status, API reachability, and library version info.
    """
    try:

        async def _get_health():
            result = await perform_health_check(secure_session, skip_api_check=False)
            # Also check for library updates
            version_info = await check_library_version()
            result.library_version = version_info.get("current_version")
            result.latest_library_version = version_info.get("latest_version")
            result.update_available = version_info.get("update_available", False)
            return result

        result = run_async(_get_health())

        status_emoji = {
            HealthStatus.HEALTHY: "✅",
            HealthStatus.DEGRADED: "⚠️",
            HealthStatus.UNHEALTHY: "❌",
            HealthStatus.UNKNOWN: "❓",
        }

        output = [
            "Monarch Money Health Report",
            "=" * 40,
            f"Status: {status_emoji.get(result.status, '❓')} {result.status.value.upper()}",
            "",
        ]

        output.append(f"Session valid: {'Yes' if result.session_valid else 'No'}")
        if result.session_age_days is not None:
            output.append(f"Session age: {result.session_age_days:.1f} days")
        output.append(f"API reachable: {'Yes' if result.api_reachable else 'No'}")

        if result.error_message:
            output.append(f"Last error: {result.error_message}")

        if result.recommendation:
            output.append("")
            output.append(f"Recommendation: {result.recommendation}")

        output.append("")
        output.append("Library Info:")
        output.append(f"  Installed: {result.library_version or 'Unknown'}")
        if result.latest_library_version:
            output.append(f"  Latest: {result.latest_library_version}")
        if result.update_available:
            output.append("  ⚠️ Update available! Run: pip install --upgrade monarchmoneycommunity")

        output.append("")
        output.append(f"Last check: {result.last_check}")

        return "\n".join(output)

    except Exception as e:
        logger.error(f"Failed to get health report: {e}")
        return f"Error getting health report: {str(e)}"


@mcp.tool()
def check_library_updates() -> str:
    """
    Check if there are updates available for the monarchmoneycommunity library.
    Newer versions may include bug fixes, API endpoint updates, and new features.
    """
    try:

        async def _check():
            return await check_library_version()

        version_info = run_async(_check())

        output = [
            "Library Version Check",
            "=" * 40,
        ]

        if version_info.get("error"):
            output.append(f"Warning: {version_info['error']}")
            output.append("")

        current = version_info.get("current_version")
        latest = version_info.get("latest_version")

        output.append(f"Installed version: {current or 'Not found'}")
        if latest:
            output.append(f"Latest version: {latest}")

        if version_info.get("update_available"):
            output.append("")
            output.append("⚠️ UPDATE AVAILABLE")
            output.append("")
            output.append("To update, run:")
            output.append("  pip install --upgrade monarchmoneycommunity")
            output.append("")
            output.append("After updating, restart Claude Desktop to use the new version.")
        elif current and latest:
            output.append("")
            output.append("✅ You are running the latest version.")

        return "\n".join(output)

    except Exception as e:
        logger.error(f"Failed to check library updates: {e}")
        return f"Error checking library updates: {str(e)}"


@mcp.tool()
def get_accounts() -> str:
    """Get all financial accounts from Monarch Money."""
    try:

        async def _get_accounts():
            client = await get_resilient_client()
            return await client.get_accounts()

        accounts = run_async(_get_accounts())

        # Format accounts for display
        account_list = []
        for account in accounts.get("accounts", []):
            account_info = {
                "id": account.get("id"),
                "name": account.get("displayName") or account.get("name"),
                "type": (account.get("type") or {}).get("name"),
                "balance": account.get("currentBalance"),
                "institution": (account.get("institution") or {}).get("name"),
                "is_active": account.get("isActive")
                if "isActive" in account
                else not account.get("deactivatedAt"),
            }
            account_list.append(account_info)

        return json.dumps(account_list, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to get accounts: {e}")
        return f"Error getting accounts: {str(e)}"


@mcp.tool()
def get_transactions(
    limit: int = 100,
    offset: int = 0,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    account_id: Optional[str] = None,
) -> str:
    """
    Get transactions from Monarch Money.

    Args:
        limit: Number of transactions to retrieve (default: 100)
        offset: Number of transactions to skip (default: 0)
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        account_id: Specific account ID to filter by
    """
    try:

        async def _get_transactions():
            client = await get_resilient_client()

            # Build filters
            filters: Dict[str, Any] = {}
            if start_date:
                filters["start_date"] = start_date
            if end_date:
                filters["end_date"] = end_date
            if account_id:
                filters["account_id"] = account_id

            return await client.call(
                "get_transactions", limit=limit, offset=offset, **filters
            )

        transactions = run_async(_get_transactions())

        # Format transactions for display
        transaction_list = []
        for txn in transactions.get("allTransactions", {}).get("results", []):
            transaction_info = {
                "id": txn.get("id"),
                "date": txn.get("date"),
                "amount": txn.get("amount"),
                "description": txn.get("description"),
                "category": txn.get("category", {}).get("name")
                if txn.get("category")
                else None,
                "account": txn.get("account", {}).get("displayName"),
                "merchant": txn.get("merchant", {}).get("name")
                if txn.get("merchant")
                else None,
                "is_pending": txn.get("isPending", False),
            }
            transaction_list.append(transaction_info)

        return json.dumps(transaction_list, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to get transactions: {e}")
        return f"Error getting transactions: {str(e)}"


@mcp.tool()
def get_budgets() -> str:
    """Get budget information from Monarch Money."""
    try:

        async def _get_budgets():
            client = await get_resilient_client()
            return await client.get_budgets()

        budgets = run_async(_get_budgets())

        # Format budgets for display
        budget_list = []
        for budget in budgets.get("budgets", []):
            budget_info = {
                "id": budget.get("id"),
                "name": budget.get("name"),
                "amount": budget.get("amount"),
                "spent": budget.get("spent"),
                "remaining": budget.get("remaining"),
                "category": budget.get("category", {}).get("name"),
                "period": budget.get("period"),
            }
            budget_list.append(budget_info)

        return json.dumps(budget_list, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to get budgets: {e}")
        return f"Error getting budgets: {str(e)}"


@mcp.tool()
def get_cashflow(
    start_date: Optional[str] = None, end_date: Optional[str] = None
) -> str:
    """
    Get cashflow analysis from Monarch Money.

    Args:
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
    """
    try:

        async def _get_cashflow():
            client = await get_resilient_client()

            filters: Dict[str, Any] = {}
            if start_date:
                filters["start_date"] = start_date
            if end_date:
                filters["end_date"] = end_date

            return await client.get_cashflow(**filters)

        cashflow = run_async(_get_cashflow())

        return json.dumps(cashflow, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to get cashflow: {e}")
        return f"Error getting cashflow: {str(e)}"


@mcp.tool()
def get_account_holdings(account_id: str) -> str:
    """
    Get investment holdings for a specific account.

    Args:
        account_id: The ID of the investment account
    """
    try:

        async def _get_holdings():
            client = await get_resilient_client()
            return await client.get_account_holdings(account_id)

        holdings = run_async(_get_holdings())

        return json.dumps(holdings, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to get account holdings: {e}")
        return f"Error getting account holdings: {str(e)}"


@mcp.tool()
def create_transaction(
    account_id: str,
    amount: float,
    description: str,
    date: str,
    category_id: Optional[str] = None,
    merchant_name: Optional[str] = None,
) -> str:
    """
    Create a new transaction in Monarch Money.

    Args:
        account_id: The account ID to add the transaction to
        amount: Transaction amount (positive for income, negative for expenses)
        description: Transaction description
        date: Transaction date in YYYY-MM-DD format
        category_id: Optional category ID
        merchant_name: Optional merchant name
    """
    try:

        async def _create_transaction():
            client = await get_resilient_client()

            transaction_data: Dict[str, Any] = {
                "account_id": account_id,
                "amount": amount,
                "description": description,
                "date": date,
            }

            if category_id:
                transaction_data["category_id"] = category_id
            if merchant_name:
                transaction_data["merchant_name"] = merchant_name

            return await client.create_transaction(**transaction_data)

        result = run_async(_create_transaction())

        return json.dumps(result, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to create transaction: {e}")
        return f"Error creating transaction: {str(e)}"


@mcp.tool()
def update_transaction(
    transaction_id: str,
    amount: Optional[float] = None,
    description: Optional[str] = None,
    category_id: Optional[str] = None,
    date: Optional[str] = None,
) -> str:
    """
    Update an existing transaction in Monarch Money.

    Args:
        transaction_id: The ID of the transaction to update
        amount: New transaction amount
        description: New transaction description
        category_id: New category ID
        date: New transaction date in YYYY-MM-DD format
    """
    try:

        async def _update_transaction():
            client = await get_resilient_client()

            update_data: Dict[str, Any] = {"transaction_id": transaction_id}

            if amount is not None:
                update_data["amount"] = amount
            if description is not None:
                update_data["description"] = description
            if category_id is not None:
                update_data["category_id"] = category_id
            if date is not None:
                update_data["date"] = date

            return await client.update_transaction(**update_data)

        result = run_async(_update_transaction())

        return json.dumps(result, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to update transaction: {e}")
        return f"Error updating transaction: {str(e)}"


@mcp.tool()
def refresh_accounts() -> str:
    """Request account data refresh from financial institutions."""
    try:

        async def _refresh_accounts():
            client = await get_resilient_client()
            return await client.request_accounts_refresh()

        result = run_async(_refresh_accounts())

        return json.dumps(result, indent=2, default=str)

    except AuthenticationRequiredError:
        return _format_auth_error()
    except MonarchAPIError as e:
        return _format_api_error(e)
    except Exception as e:
        logger.error(f"Failed to refresh accounts: {e}")
        return f"Error refreshing accounts: {str(e)}"


def main():
    """Main entry point for the server."""
    logger.info("Starting Monarch Money MCP Server...")

    # Run startup health check (non-blocking)
    try:
        logger.info("Running startup health check...")
        health_result = run_async(startup_health_check(secure_session))

        if health_result.status == HealthStatus.UNHEALTHY:
            logger.warning(
                "⚠️ Monarch connection is UNHEALTHY. "
                "Some tools may not work until re-authenticated."
            )
        elif health_result.status == HealthStatus.DEGRADED:
            logger.warning(
                "⚠️ Monarch connection is DEGRADED. "
                "Consider re-authenticating soon."
            )
        else:
            logger.info("✅ Startup health check passed")

    except Exception as e:
        # Don't prevent server from starting on health check failure
        logger.warning(f"Startup health check failed (non-fatal): {e}")

    try:
        mcp.run()
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


# Export for mcp run
app = mcp

if __name__ == "__main__":
    main()
