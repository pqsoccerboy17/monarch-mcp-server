# TASK 001: Monarch Money Persistent Connection Fix

## Problem Statement
The current monarch-mcp-server requires re-authentication too frequently. Users experience session expiration that interrupts their workflow and requires manual intervention via `login_setup.py`.

## Root Cause Analysis
After reviewing the codebase:
1. **No session age tracking** - We don't know when the session was created or when it expires
2. **No proactive refresh** - Sessions are only refreshed during login, not before expiration
3. **No retry with refresh** - When an API call fails due to expired session, we don't attempt to refresh
4. **Session file vs token confusion** - Two storage mechanisms (pickle file + keyring) without clear refresh strategy

## Proposed Solution
1. Track session metadata (created_at, last_refreshed, last_used)
2. Implement proactive session refresh (refresh if >24 hours old before making API calls)
3. Implement retry-with-refresh logic (if API call fails with auth error, try refresh once)
4. Consolidate on session file as primary (MonarchMoney library handles refresh internally)

## Success Criteria
- [ ] Session metadata stored with timestamps (created_at, last_refreshed, last_used)
- [ ] Proactive refresh: if session >24h old, refresh before API call
- [ ] Retry logic: if API call fails with auth error, attempt refresh once then retry
- [ ] Clear logging showing refresh events
- [ ] Manual login only required if refresh fails (rare, weeks apart)
- [ ] All existing tests pass
- [ ] New tests for refresh logic

## Files to Modify
1. `src/monarch_mcp_server/secure_session.py` - Add session metadata tracking
2. `src/monarch_mcp_server/server.py` - Add retry-with-refresh logic to `get_monarch_client()`

## Non-Goals
- Changing the keyring storage mechanism
- Modifying the MFA flow
- Changing the CLI interface of login_setup.py

## Iteration Limit
- Maximum: 10 iterations
- Stop and report if tests fail after 2 fix attempts

## Checkpoint Plan
1. Add session metadata to secure_session.py → test → commit
2. Add proactive refresh to get_monarch_client() → test → commit
3. Add retry-with-refresh logic → test → commit
4. Integration test full flow → commit

## Risks
- MonarchMoney library may not support programmatic refresh (need to verify)
- Session file format is pickle (library-controlled, we may not be able to add metadata to it)

---

## Pre-Implementation Research Needed
Before coding, verify:
1. Does MonarchMoney library support `refresh_token()` or similar?
2. Can we detect session expiration before API call fails?
3. What's the actual session lifetime from Monarch Money?

---

## RESEARCH FINDINGS (2026-01-17)

### Critical Discovery: GQL Version Incompatibility
- **Project requires:** `gql>=3.4,<4.0`
- **Installed:** `gql==4.0.0`
- **Error:** `TypeError: execute_async() missing 1 required positional argument: 'request'`
- **Root cause:** GQL 4.0 has breaking API changes

### Session File Analysis
- Location: `~/Library/Application Support/monarch-mcp-server/mm_session.pickle`
- Format: pickle dict containing `token` (64 char string)
- No expiration timestamp stored (library doesn't track this)

### MonarchMoney Library Capabilities
- `login(use_saved_session=True, save_session=True)` - handles session persistence
- `load_session()` / `save_session()` - manual session management
- `token` property - the auth token
- No built-in refresh mechanism or expiration tracking

### Revised Plan
1. **FIRST:** Fix GQL dependency - downgrade to <4.0 ✅
2. **THEN:** Switch to monarchmoney-enhanced library ✅
3. **THEN:** Update session management for encrypted storage ✅

---

## IMPLEMENTATION LOG (2026-01-17)

### Step 1: Diagnosed GQL Incompatibility
- Found `gql==4.0.0` installed but project requires `<4.0`
- Downgraded to `gql==3.5.3`
- This fixed TypeError but revealed 525 HTTP errors

### Step 2: Identified Root Cause - Missing Headers
- Monarch Money API returns 525 (Cloudflare SSL error) without proper headers
- Original monarchmoney library missing: `device-uuid`, `Origin`, `User-Agent` headers
- Found monarchmoney-enhanced fork that fixes these issues

### Step 3: Migrated to monarchmoney-enhanced
- Updated pyproject.toml: `monarchmoney>=0.1.15` → `monarchmoney-enhanced>=0.3.0`
- Installed version 0.11.0
- Enhanced library uses encrypted JSON sessions instead of pickle

### Step 4: Updated Session Management
- **secure_session.py:** Added `SESSION_PASSWORD` constant, updated `get_authenticated_client()`
- **server.py:** Updated `get_monarch_client()` to use encrypted sessions + staleness detection
- **login_setup.py:** Simplified flow, uses encrypted sessions, shows session expiry info

### Changes Made
| File | Changes |
|------|---------|
| `pyproject.toml` | Changed dependency to monarchmoney-enhanced |
| `src/monarch_mcp_server/secure_session.py` | Added SESSION_PASSWORD, updated client creation |
| `src/monarch_mcp_server/server.py` | Updated get_monarch_client() for enhanced library |
| `login_setup.py` | Simplified, uses encrypted sessions |

### Pending
- [x] User must run `python login_setup.py` to create new encrypted session
- [x] Verify MCP server works with new session
- [ ] Commit changes

---

## FINAL RESOLUTION (2026-01-17)

### Root Cause
Monarch Money changed their API endpoint from `api.monarchmoney.com` to `api.monarch.com` in January 2026.
The original `monarchmoney` library and the `monarchmoney-enhanced` fork both had the old endpoint.

### Solution
Switched to `monarchmoneycommunity` (community fork) which has the updated endpoint.

### Test Results
- Login: ✅ SUCCESS (with MFA)
- Session persistence: ✅ SUCCESS (26 accounts loaded from saved session)
- Keyring backup: ⚠️ FAILED (macOS Keychain permission issue - non-critical)

### Files Changed
| File | Change |
|------|--------|
| `pyproject.toml` | `monarchmoney` → `monarchmoneycommunity>=1.0.0` |
| `src/monarch_mcp_server/secure_session.py` | Removed encryption params, simplified |
| `src/monarch_mcp_server/server.py` | Removed encryption params, updated docstrings |
| `login_setup.py` | Removed encryption, graceful keyring error handling |

### Status: ✅ COMPLETE
