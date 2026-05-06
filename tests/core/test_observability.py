"""Tests for the request-scoped logging context."""

from __future__ import annotations

import logging

from cloudguardiq.core.observability import (
    ContextFilter,
    bind_context,
    current_context,
    install_context_filter,
    request_id_var,
    scan_id_var,
    subscription_id_var,
    tenant_id_var,
)


def _make_record() -> logging.LogRecord:
    return logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )


def test_bind_context_only_sets_provided_fields() -> None:
    request_id_var.set(None)
    tenant_id_var.set(None)
    bind_context(request_id="req-1")
    assert request_id_var.get() == "req-1"
    assert tenant_id_var.get() is None


def test_current_context_omits_empty_fields() -> None:
    request_id_var.set(None)
    tenant_id_var.set("t1")
    subscription_id_var.set(None)
    scan_id_var.set(None)
    snapshot = current_context()
    assert snapshot == {"tenant_id": "t1"}


def test_filter_attaches_custom_dimensions() -> None:
    request_id_var.set("req-x")
    tenant_id_var.set("tenant-7")
    subscription_id_var.set(None)
    scan_id_var.set(None)
    flt = ContextFilter()
    rec = _make_record()
    assert flt.filter(rec) is True
    assert rec.custom_dimensions == {
        "request_id": "req-x",
        "tenant_id": "tenant-7",
    }
    assert rec.tenant_id == "tenant-7"
    assert rec.subscription_id == ""


def test_filter_preserves_existing_custom_dimensions() -> None:
    request_id_var.set("req-1")
    tenant_id_var.set(None)
    flt = ContextFilter()
    rec = _make_record()
    rec.custom_dimensions = {"caller_set": "value"}
    flt.filter(rec)
    assert rec.custom_dimensions == {
        "caller_set": "value",
        "request_id": "req-1",
    }


def test_install_context_filter_is_idempotent() -> None:
    logger = logging.getLogger("cguardiq.test.observability")
    logger.filters = []
    install_context_filter(logger)
    install_context_filter(logger)
    matching = [f for f in logger.filters if isinstance(f, ContextFilter)]
    assert len(matching) == 1
