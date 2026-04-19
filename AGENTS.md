# CloudGuardIQ Agent Instructions

## Context
You are working on CloudGuardIQ — a cloud security and FinOps SaaS product.
Always read .github/copilot-instructions.md for full project context.

## Workflow rules
1. Before implementing, use /plan to outline what files you will create or modify
2. After every Python file edit, run: python -m pytest tests/ -x --tb=short
3. After every batch of changes, run: ruff check cloudguardiq/ && mypy cloudguardiq/
4. Write tests FIRST, then implementation (TDD preferred)
5. Commit with conventional messages: feat:, fix:, test:, docs:

## Architecture enforcement
- NEVER import azure.* inside cloudguardiq/policy/ — policy rules operate on
  ResourceSnapshot objects only
- ALWAYS wrap Defender for Cloud API calls in try/except — return graceful fallback
- ALWAYS set data_tier field on every ResourceSnapshot
- NEVER send raw API responses to GPT-4o — always send structured FindingResult JSON

## Error handling pattern
- External API failures (Azure, OpenAI, GitHub) must NEVER propagate as unhandled exceptions
- Defender failure → log warning, return empty enrichment, continue
- Cost Management failure → log warning, set cost_monthly=0.0, continue
- OpenAI failure → retry 3x with exponential backoff, then raise AIEngineError