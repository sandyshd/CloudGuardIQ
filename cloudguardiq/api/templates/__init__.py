"""Bundled ARM/Bicep deployment templates shipped with the API.

Files in this package (``*.json``) are served verbatim by the
:mod:`cloudguardiq.api.subscriptions` router so the Azure Portal
Deploy-to-Azure blade can fetch them anonymously without depending on
the GitHub repository being public. The package is the single source
of truth — do not duplicate templates elsewhere in the repo.
"""
