---
description: "Run full quality gate — lint, type check, and tests"
---

Run the complete quality gate for CloudGuardIQ:

1. Run ruff linter: `ruff check cloudguardiq/ --fix`
2. Run mypy type checker: `mypy cloudguardiq/ --ignore-missing-imports`
3. Run pytest with coverage:
   `python -m pytest tests/ -v --cov=cloudguardiq --cov-report=term-missing --cov-fail-under=80`
4. Report results:
   - Lint: PASS/FAIL (N issues)
   - Types: PASS/FAIL (N errors)
   - Tests: PASS/FAIL (N passed, N failed, coverage %)
5. If anything fails, fix it before reporting PASS.