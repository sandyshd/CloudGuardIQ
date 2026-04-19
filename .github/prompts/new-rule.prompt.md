---
description: "Create a new security or FinOps rule for the NativeScanner"
---

Create a new CloudGuardIQ scanner rule.

Steps:
1. Determine which rule module this belongs to (storage, network, iam, compute, keyvault, finops)
2. Create the rule class extending PolicyRule in the appropriate module
3. Implement the evaluate() method checking specific ResourceSnapshot config fields
4. Add the rule to RULE_REGISTRY in native_scanner.py
5. Write 2 tests: pass case (resource is secure, return None) + fail case (return FindingResult)
6. Run: python -m pytest tests/adapters/ -v -k "new_rule_id"
7. Verify both tests pass