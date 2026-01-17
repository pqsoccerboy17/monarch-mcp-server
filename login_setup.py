#!/usr/bin/env python3
"""
Standalone script to perform interactive Monarch Money login with MFA support.
Run this script to authenticate and save a session file that the MCP server can use.

Uses monarchmoneycommunity library (community fork with updated API endpoint).
"""

import asyncio
import getpass
import sys
from pathlib import Path

# Add the src directory to the Python path for imports
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from monarchmoney import MonarchMoney, RequireMFAException
from dotenv import load_dotenv
from monarch_mcp_server.secure_session import secure_session
from monarch_mcp_server.security import enforce_gql_aiohttp_tls_verification


async def main() -> None:
    """
    Interactive login flow for Monarch Money.

    Authenticates user and saves session for MCP server use.
    """
    load_dotenv()
    # Security hardening: verify TLS certificates for HTTPS by default.
    enforce_gql_aiohttp_tls_verification()

    print("\n🏦 Monarch Money - Claude Desktop Setup")
    print("=" * 45)
    print("This will authenticate you once and save a session")
    print("for seamless access through Claude Desktop.\n")

    # Check the version first
    try:
        import monarchmoney
        version = getattr(monarchmoney, '__version__', 'unknown')
        print(f"📦 MonarchMoney Community version: {version}")
    except Exception as e:
        print(f"⚠️  Could not check version: {e}")

    # Get session file path from secure_session module
    session_path = secure_session.session_file_path()
    print(f"📁 Session will be saved to: {session_path}")

    # Create MonarchMoney instance
    mm = MonarchMoney(
        session_file=str(session_path),
        timeout=30
    )

    try:
        # Clear any existing sessions
        secure_session.delete_session_file()
        secure_session.delete_token()
        print("🗑️  Cleared existing sessions")

        # Ask about MFA setup
        print("\n🔐 Security Check:")
        has_mfa = input("Do you have MFA enabled on your Monarch Money account? (y/n): ").strip().lower()

        if has_mfa not in ['y', 'yes']:
            print("\n⚠️  SECURITY RECOMMENDATION:")
            print("=" * 50)
            print("You should enable MFA for your Monarch Money account.")
            print("MFA adds an extra layer of security to protect your financial data.")
            print("\nTo enable MFA:")
            print("1. Log into Monarch Money at https://monarchmoney.com")
            print("2. Go to Settings → Security")
            print("3. Enable Two-Factor Authentication")
            print("4. Follow the setup instructions\n")

            proceed = input("Continue with login anyway? (y/n): ").strip().lower()
            if proceed not in ['y', 'yes']:
                print("Login cancelled. Please set up MFA and try again.")
                return

        print("\nStarting login...")
        email = input("Email: ")
        password = getpass.getpass("Password: ")

        # Try login - enhanced library handles MFA detection
        try:
            await mm.login(email, password, use_saved_session=False, save_session=True)
            print("✅ Login successful!")

        except RequireMFAException:
            print("🔐 MFA code required")
            mfa_code = input("Two Factor Code: ")

            # Use the same instance for MFA
            await mm.multi_factor_authenticate(email, password, mfa_code)
            print("✅ MFA authentication successful")
            mm.save_session()

        # Test the connection
        print("\nTesting connection...")
        accounts = await mm.get_accounts()

        if accounts and isinstance(accounts, dict):
            account_count = len(accounts.get("accounts", []))
            print(f"✅ Found {account_count} accounts")

            # Show first account as proof of connection
            if account_count > 0:
                first = accounts["accounts"][0]
                name = first.get("displayName") or first.get("name", "Unknown")
                print(f"   First account: {name}")
        else:
            print("❌ Unexpected response format")
            return

        # Also save token to keyring as backup (optional, may fail on some systems)
        if mm.token:
            try:
                secure_session.save_token(mm.token)
                print("✅ Token backed up to system keyring")
            except Exception as e:
                print(f"⚠️  Could not backup token to keyring (non-critical): {e}")

        print("\n🎉 Setup complete! You can now use these tools in Claude Desktop:")
        print("   • get_accounts - View all your accounts")
        print("   • get_transactions - Recent transactions")
        print("   • get_budgets - Budget information")
        print("   • get_cashflow - Income/expense analysis")
        print("\n💡 Session will persist across restarts!")

    except Exception as e:
        print(f"\n❌ Login failed: {e}")
        print("\nPlease check your credentials and try again.")
        print(f"Error type: {type(e).__name__}")


if __name__ == "__main__":
    asyncio.run(main())