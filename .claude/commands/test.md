Run the test suite and report results. If tests fail, diagnose and fix.

Steps:
1. Run: docker compose -f docker-compose.prod.yml exec api python -m pytest tests/ -v --tb=short 2>&1
2. If specific test file requested, run that: docker compose -f docker-compose.prod.yml exec api python -m pytest tests/$ARGUMENTS -v 2>&1
3. Report: total tests, passed, failed, errors
4. For any failures: read the test file, read the source file, identify the bug, propose a fix
5. After fixing, re-run the failing test to confirm
