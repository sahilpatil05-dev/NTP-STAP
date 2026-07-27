# Next Task — NTP-SCTAP

> Contains only the immediate next objective.  
> **Updated after every completed task.**

---

## Current Task

API Rate Limiting and Endpoint Authentication

## Objective

Implement API rate limiting and basic token authentication on control endpoints to secure the REST API:

1. **Token Authentication:** Secure the POST `/api/receiver/control` and POST `/api/messages/send` endpoints using a static API key / token (e.g. read from settings.py config).
2. **Rate Limiting:** Protect endpoint routes against brute-force or flooding by implementing a simple in-memory IP-based rate limiter (or using Flask-Limiter if a light-weight wrapper is preferred).
3. **Tests:** Update existing `tests/test_app_factory.py` or write new test cases verifying that unauthenticated requests receive a 401 Unauthorized status, and rate-limited requests receive a 429 Too Many Requests status.

## Expected Files

| File | Action |
|---|---|
| `backend/routes.py` | MODIFY — Add auth decorators and rate limit logic |
| `config/settings.py` | MODIFY — Add API token config options |
| `tests/test_app_factory.py` | MODIFY — Add auth / rate limit tests |
| `docs/SECURITY.md` | UPDATE — Document API access controls |
| `docs/AI_HANDOVER.md` | UPDATE — Update tasks and statuses |

## Success Criteria

- [ ] Unauthenticated requests to restricted API endpoints return 401 Unauthorized
- [ ] Excessive requests beyond the rate limit threshold return 429 Too Many Requests
- [ ] No regressions in existing 145 tests
- [ ] Test isolation maintained

## Dependencies

- No external binary dependencies required (can use simple Python in-memory cache or dictionary for IP tracking to avoid external Redis/Memcached dependencies)

## Estimated Complexity

Medium — requires designing auth decorator pattern in Flask.
