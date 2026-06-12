"""Unit tests for results_ledger.py (Phase 7 results persistence).

Covers:
  * result_filename() format with an injected `when` (deterministic timestamp),
  * write_result() writes valid JSON persisting the `captures` verbatim (raw
    values + keys) alongside the rest of the envelope,
  * write_result() does not mutate the input envelope,
  * append_ledger() creates the header exactly once then appends rows with the
    EXACT columns and values.

All tests are hermetic: RESULTS_DIR is monkeypatched to a tmp_path so nothing
touches the real package `results/` dir.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone

import pytest

import results_ledger


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def results_dir(tmp_path, monkeypatch):
    """Redirect RESULTS_DIR to a hermetic tmp dir for every test."""
    d = tmp_path / "results"
    monkeypatch.setattr(results_ledger, "RESULTS_DIR", d)
    return d


def _envelope(status="fail", n_fail=2):
    """A minimal envelope shaped like check_param_parity's output."""
    return {
        "status": status,
        "summary": {"n_total": 5, "n_ok": 3, "n_fail": n_fail, "n_warn": 0},
        "per_param": [{"name": "url", "state": "VALUE_MISMATCH", "verdict": "fail"}],
        "captures": {
            "integration": {"url": "https://dummy.example.com", "token": "real-secret-123"},
            "connector": {"domain": "test.salesforce.com", "api_key": "abc123"},
        },
        "inputs": {"integration_id": "Salesforce IAM", "connector_id": "salesforce"},
    }


# ── result_filename ───────────────────────────────────────────────────────────


def test_result_filename_format_with_injected_when():
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    name = results_ledger.result_filename("Salesforce", "Salesforce IAM", when=when)
    assert name == "salesforce__salesforce-iam__20260607T170006Z.json"


def test_result_filename_slugifies_both_ids():
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    name = results_ledger.result_filename("My Connector", "Some Integration", when=when)
    assert name == "my-connector__some-integration__20260102T030405Z.json"


def test_result_filename_naive_when_treated_as_utc():
    when = datetime(2026, 6, 7, 17, 0, 6)  # naive
    name = results_ledger.result_filename("c", "i", when=when)
    assert name.endswith("20260607T170006Z.json")


# ── write_result (persists RAW captures — scrubbing intentionally removed) ─────


def test_write_result_persists_raw_captures(results_dir):
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    env = _envelope()

    path = results_ledger.write_result(
        env, connector_id="Salesforce", integration_id="Salesforce IAM", when=when
    )

    assert path == results_dir / "salesforce__salesforce-iam__20260607T170006Z.json"
    assert path.exists()

    written = json.loads(path.read_text())

    # captures keys preserved AND raw values persisted verbatim (no redaction)
    assert set(written["captures"]["integration"]) == {"url", "token"}
    assert set(written["captures"]["connector"]) == {"domain", "api_key"}
    assert written["captures"]["integration"]["url"] == "https://dummy.example.com"
    assert written["captures"]["integration"]["token"] == "real-secret-123"
    assert written["captures"]["connector"]["domain"] == "test.salesforce.com"
    assert written["captures"]["connector"]["api_key"] == "abc123"

    # rest of the envelope is untouched
    assert written["status"] == "fail"
    assert written["summary"]["n_fail"] == 2
    assert written["per_param"] == env["per_param"]
    assert written["inputs"] == env["inputs"]


def test_write_result_does_not_mutate_input_envelope(results_dir):
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    env = _envelope()
    results_ledger.write_result(
        env, connector_id="c", integration_id="i", when=when
    )
    # the ORIGINAL envelope is unchanged after the write (no in-place mutation)
    assert env["captures"]["integration"]["token"] == "real-secret-123"
    assert env["captures"]["connector"]["api_key"] == "abc123"


def test_write_result_creates_results_dir_lazily(results_dir):
    assert not results_dir.exists()
    results_ledger.write_result(
        _envelope(), connector_id="c", integration_id="i",
        when=datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc),
    )
    assert results_dir.is_dir()


# ── append_ledger ─────────────────────────────────────────────────────────────


def test_append_ledger_creates_header_once_then_appends(results_dir):
    when1 = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    when2 = datetime(2026, 6, 7, 18, 30, 0, tzinfo=timezone.utc)

    results_ledger.append_ledger(
        _envelope(status="fail", n_fail=2),
        integration_id="Salesforce IAM",
        connector_id="Salesforce",
        result_file="salesforce__salesforce-iam__20260607T170006Z.json",
        when=when1,
    )
    results_ledger.append_ledger(
        _envelope(status="pass", n_fail=0),
        integration_id="Other Integration",
        connector_id="Other Connector",
        result_file="other-connector__other-integration__20260607T183000Z.json",
        when=when2,
    )

    ledger_path = results_dir / "ledger.csv"
    rows = list(csv.reader(ledger_path.read_text().splitlines()))

    # exact header columns
    assert rows[0] == [
        "timestamp",
        "integration_id",
        "connector_slug",
        "status",
        "n_fail",
        "result_file",
    ]
    # header appears exactly once
    assert sum(1 for r in rows if r[0] == "timestamp") == 1

    # first data row
    assert rows[1] == [
        "20260607T170006Z",
        "Salesforce IAM",
        "salesforce",
        "fail",
        "2",
        "salesforce__salesforce-iam__20260607T170006Z.json",
    ]
    # second data row (connector slugified, status pass, n_fail 0)
    assert rows[2] == [
        "20260607T183000Z",
        "Other Integration",
        "other-connector",
        "pass",
        "0",
        "other-connector__other-integration__20260607T183000Z.json",
    ]


def test_append_ledger_uses_dictreader_columns(results_dir):
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    results_ledger.append_ledger(
        _envelope(status="fail", n_fail=3),
        integration_id="Salesforce IAM",
        connector_id="Salesforce",
        result_file="f.json",
        when=when,
    )
    ledger_path = results_dir / "ledger.csv"
    with ledger_path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["status"] == "fail"
    assert rows[0]["n_fail"] == "3"
    assert rows[0]["connector_slug"] == "salesforce"
    assert rows[0]["result_file"] == "f.json"


def test_append_ledger_quotes_values_with_commas(results_dir):
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    results_ledger.append_ledger(
        _envelope(),
        integration_id="Weird, Integration",
        connector_id="Some Connector",
        result_file="f.json",
        when=when,
    )
    ledger_path = results_dir / "ledger.csv"
    with ledger_path.open() as fh:
        rows = list(csv.DictReader(fh))
    # csv round-trips the embedded comma intact
    assert rows[0]["integration_id"] == "Weird, Integration"
