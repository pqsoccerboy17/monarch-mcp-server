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
from monarch_mcp_server.secure_session import secure_session, SessionMetadata
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
        secure_session.delete_session_metadata()
        print("Cleared existing secure sessions")
        
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
        try:
            # Try a simple test call that should work
            print("Calling get_accounts()...")
            accounts = await mm.get_accounts()
            print(f"Response received: {type(accounts)}")
            if accounts and isinstance(accounts, dict):
                account_count = len(accounts.get("accounts", []))
                print(f"✅ Found {account_count} accounts")
            else:
                print("❌ No accounts data returned or unexpected format")
                print(f"Response type: {type(accounts)}")
                print(f"Response content: {accounts}")
                return
        except Exception as test_error:
            print(f"❌ Connection test failed: {test_error}")
            print(f"Error type: {type(test_error)}")
            
            # Check if it's a session issue
            if "session" in str(test_error).lower() or "expired" in str(test_error).lower():
                print("Session may be expired. Clearing old session and trying fresh login...")
                
                # Clear old session and try fresh login
                if os.path.exists(".mm"):
                    shutil.rmtree(".mm")
                    print("🗑️ Cleared expired session files")
                
                # Try fresh login
                mm_fresh = MonarchMoney()
                try:
                    await mm_fresh.login(email, password)
                    print("✅ Fresh login successful (no MFA required)")
                    mm = mm_fresh
                    
                    # Test connection again
                    accounts = await mm.get_accounts()
                    if accounts and isinstance(accounts, dict):
                        account_count = len(accounts.get("accounts", []))
                        print(f"✅ Found {account_count} accounts")
                    
                except RequireMFAException:
                    print("🔐 MFA required for fresh login")
                    mfa_code = input("Two Factor Code: ")
                    
                    mm_mfa_fresh = MonarchMoney()
                    await mm_mfa_fresh.multi_factor_authenticate(email, password, mfa_code)
                    print("✅ Fresh MFA authentication successful")
                    mm = mm_mfa_fresh
                    
                    # Test connection again
                    accounts = await mm.get_accounts()
                    if accounts and isinstance(accounts, dict):
                        account_count = len(accounts.get("accounts", []))
                        print(f"✅ Found {account_count} accounts")
            else:
                print("This appears to be an API compatibility issue.")
                print("The MonarchMoney library API may have changed.")
                print("Try updating the library: pip install --upgrade monarchmoney")
                return
        
        # Save session securely to keyring
        try:
            print(f"\nSaving session securely...")
            secure_session.save_authenticated_session(mm)

            # Initialize session metadata for health monitoring
            metadata = SessionMetadata.create_new(mm.token)
            secure_session.save_session_metadata(metadata)
            print(f"Session saved with health tracking enabled!")

        except Exception as save_error:
            print(f"Could not save session: {save_error}")
            print("You may need to run the login again.")

        print("\nSetup complete! You can now use these tools in Claude Desktop:")
        print("   - get_accounts: View all your accounts")
        print("   - get_transactions: Recent transactions")
        print("   - get_budgets: Budget information")
        print("   - get_cashflow: Income/expense analysis")
        print("   - check_session_health: Monitor session status")
        print("   - diagnose_connection: Troubleshoot issues")
        print("\nSession will persist across Claude restarts!")
        
    except Exception as e:
        print(f"\n❌ Login failed: {e}")
        print("\nPlease check your credentials and try again.")
        print(f"Error type: {type(e).__name__}")


if __name__ == "__main__":
    asyncio.run(main())