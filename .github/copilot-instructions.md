# CloudGuardIQ — Copilot Instructions

## Project overview
CloudGuardIQ is a unified Azure-native SaaS combining CSPM (Cloud Security Posture
Management) and FinOps cost governance with AI-generated remediation. It uses a tiered
data source strategy — no hard dependency on Microsoft Defender for Cloud.

## Tech stack
- Python 3.12, FastAPI, Pydantic v2
- Azure Cosmos DB (serverless), Azure OpenAI GPT-4o
- React 18 + TypeScript + Tailwind CSS
- Terraform for all infrastructure
- pytest, ruff, mypy for quality

## Architecture rules (CRITICAL — never violate)
- AdapterBase is the ONLY interface that touches external cloud APIs
- PolicyEngine rules evaluate ResourceSnapshot objects ONLY — never import Azure SDK
- ResourceSnapshot has a data_tier field: TIER1_NATIVE | TIER2_FREE_CSPM | TIER3_PAID
- Every Defender for Cloud API call MUST be in try/except — graceful degradation always
- GPT-4o receives structured FindingResult JSON — never raw API data
- All secrets via environment variables or Azure Key Vault — never hardcoded

## Code standards
- Type hints on every function signature
- Pydantic v2 BaseModel for all data structures
- Async/await throughout (FastAPI + asyncio)
- Use Python logging module — never print()
- Every public method has a docstring
- Test coverage minimum: 80%

## Testing
- Run: python -m pytest tests/ -v --tb=short
- Lint: ruff check .
- Types: mypy cloudguardiq/
- Always run tests after editing any .py file
- Mock all external APIs in tests (Azure, OpenAI, Cosmos)
- Use pytest fixtures for ResourceSnapshot creation

## File locations
- Data models: cloudguardiq/core/models.py
- Enums: cloudguardiq/core/enums.py
- Adapter base: cloudguardiq/adapters/base.py
- Native scanner rules: cloudguardiq/adapters/rules/*.py
- Policy engine: cloudguardiq/policy/engine.py
- AI engine: cloudguardiq/ai/remediation_engine.py
- API routes: cloudguardiq/api/main.py

## Build and test commands
- Install: pip install -e ".[dev]"
- Test: python -m pytest tests/ -v --cov=cloudguardiq --cov-fail-under=80
- Lint: ruff check cloudguardiq/
- Type check: mypy cloudguardiq/
- Run API: uvicorn cloudguardiq.api.main:app --reload
- Terraform: cd infra && terraform validate

## What NOT to do
- Do NOT make Defender for Cloud a hard dependency
- Do NOT import azure SDK inside cloudguardiq/policy/
- Do NOT use print() for logging
- Do NOT hardcode subscription IDs or credentials
- Do NOT skip writing tests