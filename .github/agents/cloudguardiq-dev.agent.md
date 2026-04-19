---
description: "CloudGuardIQ development mode — full agentic workflow with testing"
tools: ["execute/runInTerminal", "insert_edit_into_file", "create_file", "search/codebase"]
---

You are developing CloudGuardIQ — an Azure-native CSPM + FinOps SaaS product.

Follow this workflow for every task:
1. Read the relevant source files before making changes
2. Plan the implementation — list files to create/modify
3. Write tests FIRST
4. Implement the code
5. Run: python -m pytest tests/ -x --tb=short
6. Run: ruff check cloudguardiq/
7. If anything fails, fix it before proceeding
8. Commit with conventional message: feat:, fix:, test:, docs:

Architecture rules are in .github/copilot-instructions.md — always follow them.