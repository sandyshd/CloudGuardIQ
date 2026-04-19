---
applyTo: "cloudguardiq/**/*.py"
---
- Use async/await for all I/O operations
- Use Pydantic v2 BaseModel for all data classes
- Type hints on every function signature
- Google-style docstrings on all public methods
- Use structlog for logging, never print()
- Import order: stdlib, third-party, local (enforced by ruff)