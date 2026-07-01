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
from zoneinfo import ZoneInfo

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
    """A LEGACY single-diff envelope (no ``variants``) — back-compat path.

    ``append_ledger`` emits a single row with an EMPTY ``variant_id`` for this
    shape; ``write_result`` persists it verbatim.
    """
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


def _aggregate_envelope(variants):
    """An AGGREGATE envelope (multi-capability variant matrix) — the new shape.

    ``variants`` is a list of ``(variant_id, status, n_fail)`` tuples.
    """
    n_fail_total = sum(1 for _, st, _ in variants if st != "pass")
    return {
        "status": "pass" if n_fail_total == 0 else "fail",
        "integration_id": "Akamai WAF SIEM",
        "connector_id": "akamai",
        "summary": {
            "n_variants": len(variants),
            "n_variants_pass": len(variants) - n_fail_total,
            "n_variants_fail": n_fail_total,
        },
        "variants": [
            {
                "variant_id": vid,
                "status": st,
                "summary": {"n_fail": nf},
            }
            for vid, st, nf in variants
        ],
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


# ── _jerusalem_stamp (readable Asia/Jerusalem ledger timestamp) ───────────────


def test_jerusalem_stamp_summer_is_idt():
    # June → Israel Daylight Time (UTC+3): 17:00:06 UTC → 20:00:06 IDT
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    assert results_ledger._jerusalem_stamp(when) == "2026-06-07 20:00:06 IDT"


def test_jerusalem_stamp_winter_is_ist():
    # January → Israel Standard Time (UTC+2): 17:00:06 UTC → 19:00:06 IST
    when = datetime(2026, 1, 7, 17, 0, 6, tzinfo=timezone.utc)
    assert results_ledger._jerusalem_stamp(when) == "2026-01-07 19:00:06 IST"


def test_jerusalem_stamp_naive_when_treated_as_utc():
    # naive datetime is treated as UTC, then converted to Jerusalem
    when = datetime(2026, 6, 7, 17, 0, 6)  # naive
    assert results_ledger._jerusalem_stamp(when) == "2026-06-07 20:00:06 IDT"


def test_jerusalem_stamp_converts_other_aware_zone():
    # an aware datetime in another zone is converted to Jerusalem
    ny = ZoneInfo("America/New_York")
    when = datetime(2026, 6, 7, 13, 0, 6, tzinfo=ny)  # 13:00 EDT = 17:00 UTC
    assert results_ledger._jerusalem_stamp(when) == "2026-06-07 20:00:06 IDT"


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

    # Callers pass the ABSOLUTE path to the per-run JSON (see check_param_parity);
    # the ledger stores it verbatim (resolved).
    path1 = results_dir / "salesforce__salesforce-iam__20260607T170006Z.json"
    path2 = results_dir / "other-connector__other-integration__20260607T183000Z.json"

    results_ledger.append_ledger(
        _envelope(status="fail", n_fail=2),
        integration_id="Salesforce IAM",
        connector_id="Salesforce",
        result_file=str(path1),
        when=when1,
    )
    results_ledger.append_ledger(
        _envelope(status="pass", n_fail=0),
        integration_id="Other Integration",
        connector_id="Other Connector",
        result_file=str(path2),
        when=when2,
    )

    ledger_path = results_dir / "ledger.csv"
    rows = list(csv.reader(ledger_path.read_text().splitlines()))

    # exact header columns (now includes variant_id)
    assert rows[0] == [
        "timestamp",
        "integration_id",
        "connector_slug",
        "variant_id",
        "status",
        "n_fail",
        "result_file",
    ]
    # header appears exactly once
    assert sum(1 for r in rows if r[0] == "timestamp") == 1

    # first data row (legacy envelope → empty variant_id).
    # timestamp is readable Asia/Jerusalem local time (17:00:06 UTC → 20:00:06 IDT
    # in June, DST), result_file is the absolute resolved path.
    assert rows[1] == [
        "2026-06-07 20:00:06 IDT",
        "Salesforce IAM",
        "salesforce",
        "",
        "fail",
        "2",
        str(path1.resolve()),
    ]
    # second data row (connector slugified, status pass, n_fail 0)
    assert rows[2] == [
        "2026-06-07 21:30:00 IDT",
        "Other Integration",
        "other-connector",
        "",
        "pass",
        "0",
        str(path2.resolve()),
    ]


def test_append_ledger_one_row_per_variant(results_dir):
    """An aggregate envelope yields ONE ledger row per variant (with variant_id)."""
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    env = _aggregate_envelope(
        [
            ("automation-and-remediation+fetch-issues", "fail", 1),
            ("automation-and-remediation+log-collection", "pass", 0),
        ]
    )
    result_path = results_dir / "akamai__akamai-waf-siem__20260607T170006Z.json"
    results_ledger.append_ledger(
        env,
        integration_id="Akamai WAF SIEM",
        connector_id="akamai",
        result_file=str(result_path),
        when=when,
    )
    ledger_path = results_dir / "ledger.csv"
    with ledger_path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert rows[0]["variant_id"] == "automation-and-remediation+fetch-issues"
    assert rows[0]["status"] == "fail"
    assert rows[0]["n_fail"] == "1"
    assert rows[1]["variant_id"] == "automation-and-remediation+log-collection"
    assert rows[1]["status"] == "pass"
    assert rows[1]["n_fail"] == "0"
    # both rows share the SAME timestamp (readable Jerusalem) + result_file (one run).
    assert rows[0]["timestamp"] == rows[1]["timestamp"] == "2026-06-07 20:00:06 IDT"
    assert rows[0]["result_file"] == rows[1]["result_file"] == str(result_path.resolve())


def test_append_ledger_uses_dictreader_columns(results_dir):
    when = datetime(2026, 6, 7, 17, 0, 6, tzinfo=timezone.utc)
    result_path = results_dir / "f.json"
    results_ledger.append_ledger(
        _envelope(status="fail", n_fail=3),
        integration_id="Salesforce IAM",
        connector_id="Salesforce",
        result_file=str(result_path),
        when=when,
    )
    ledger_path = results_dir / "ledger.csv"
    with ledger_path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["status"] == "fail"
    assert rows[0]["n_fail"] == "3"
    assert rows[0]["connector_slug"] == "salesforce"
    # result_file is the absolute resolved path to the JSON envelope
    assert rows[0]["result_file"] == str(result_path.resolve())


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
