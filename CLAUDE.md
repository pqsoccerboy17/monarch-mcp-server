# Monarch MCP Server

Personal finance MCP server providing read/write access to Monarch Money accounts, transactions, budgets, and cashflow analytics.

## Session Management Architecture

**Multi-layer authentication cascade:**
1. Primary: `~/.mm/mm_session.pickle` (MonarchMoney library manages)
2. Secondary: OS keyring (macOS Keychain) as backup
3. Fallback: Environment variables (`MONARCH_EMAIL`, `MONARCH_PASSWORD`)
4. Falls through cascade if any layer fails

**Session lifecycle:**
- Sessions last ~2-3 weeks (Monarch Money API limitation)
- Library doesn't expose expiration timestamps
- Result: Must re-authenticate when expired (automatic detection)

## MFA Security Pattern

**Why handled outside Claude Desktop:**
- Credentials never passed through Claude (security requirement)
- Interactive MFA flow in [login_setup.py](login_setup.py) (separate terminal script)
- Session saved locally after successful auth
- Claude Desktop only uses pre-authenticated session file

**Setup process:**
```bash
uv run login_setup.py  # Interactive auth with MFA
# Session saved to ~/.mm/mm_session.pickle
# Then Claude Desktop can use the session
```

## Resilience Layer

**Error classification** ([resilience.py](src/monarch_mcp_server/resilience.py)):
- **Transient**: 502/503/504, SSL errors → Retry with exponential backoff
- **Auth expired**: 401/403 → Attempt session refresh, then fail
- **Rate limited**: 429 → Respect Retry-After header
- **Permanent**: 400/4xx → Fail immediately, no retry

**Retry configuration:**
- Default: 5 attempts with 1-60s exponential backoff
- Configurable via `ResilientMonarchClient` constructor

## Health Monitoring

**Tools for session diagnostics:**
- `check_session_health()` - Session age, API reachability, library version
- `validate_session()` - Test API call to verify session validity
- `get_health_report()` - Comprehensive status with recommendations

## Dependencies

**Critical:** Must use `monarchmoneycommunity>=1.0.0` (community fork)
- Official library outdated (wrong API endpoint)
- Jan 2026 endpoint migration: `api.monarchmoney.com` → `api.monarch.com`
- Community fork maintained by @hammem with updated endpoint

See [README.md](README.md) for setup and [resilience.py](src/monarch_mcp_server/resilience.py) for error handling details.
