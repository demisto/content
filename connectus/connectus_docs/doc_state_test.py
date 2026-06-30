"""Unit tests for doc_state (CSV documentation tracking).

Hermetic: writes a synthetic pipeline CSV under tmp_path and points
pipeline_csv_path at it. Run from the package directory::

    cd content/connectus/connectus_docs && python3 -m pytest doc_state_test.py
"""

from __future__ import annotations

import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import doc_state  # noqa: E402
from doc_state import (  # noqa: E402
    DOC_COLUMN,
    DONE_MARK,
    doc_dashboard,
    doc_next,
    doc_status,
    list_connectors,
    set_doc_complete,
)

_HEADER = ["Integration ID", "Connector ID", "Connector Folder Path", "assignee"]


@pytest.fixture
def csv_path(tmp_path, monkeypatch):
    p = tmp_path / "pipeline.csv"
    rows = [
        # akamai: 2 members (Joey), not documented
        ["Akamai WAF", "Akamai", "connectors/akamai", "Joey"],
        ["Akamai SIEM", "Akamai", "connectors/akamai", "Joey"],
        # box: 1 member (Dana), not documented
        ["Box", "Box", "connectors/box", "Dana"],
        # slack: 1 member (Joey), ALREADY documented (set below)
        ["Slack", "Slack", "connectors/slack", "Joey"],
    ]
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_HEADER)
        w.writerows(rows)
    monkeypatch.setattr(doc_state, "pipeline_csv_path", lambda: p)
    return p


def _raw(p):
    with open(p, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Column auto-append
# --------------------------------------------------------------------------- #
def test_column_appended_on_first_write(csv_path):
    # The fixture CSV has no DOC_COLUMN; set_doc_complete must add it.
    set_doc_complete("box")
    rows = _raw(csv_path)
    assert DOC_COLUMN in rows[0]
    # Original columns preserved.
    for col in _HEADER:
        assert col in rows[0]


def test_status_works_before_any_write(csv_path):
    st = doc_status("akamai")
    assert st["complete"] is False
    assert [m["integration_id"] for m in st["members"]] == ["Akamai WAF", "Akamai SIEM"]
    assert all(m["documented"] is False for m in st["members"])


# --------------------------------------------------------------------------- #
# set_doc_complete marks ALL member rows
# --------------------------------------------------------------------------- #
def test_set_complete_marks_all_members(csv_path):
    n = set_doc_complete("akamai")
    assert n == 2
    st = doc_status("akamai")
    assert st["complete"] is True
    assert all(m["documented"] for m in st["members"])


def test_set_complete_does_not_touch_other_connectors(csv_path):
    set_doc_complete("akamai")
    rows = _raw(csv_path)
    box = [r for r in rows if r["Connector Folder Path"] == "connectors/box"][0]
    assert box[DOC_COLUMN] != DONE_MARK


def test_set_complete_unknown_slug_raises(csv_path):
    with pytest.raises(ValueError, match="No member rows"):
        set_doc_complete("nonexistent")


# --------------------------------------------------------------------------- #
# doc_next
# --------------------------------------------------------------------------- #
def test_next_returns_first_undocumented(csv_path):
    nxt = doc_next()
    assert nxt is not None
    assert nxt["slug"] == "akamai"


def test_next_skips_completed(csv_path):
    set_doc_complete("akamai")
    nxt = doc_next()
    assert nxt["slug"] == "box"


def test_next_none_when_all_done(csv_path):
    for slug in ("akamai", "box", "slack"):
        set_doc_complete(slug)
    assert doc_next() is None


def test_next_mine_filters_by_assignee(csv_path, monkeypatch):
    monkeypatch.setattr(doc_state, "_git_user_name", lambda: "Dana")
    nxt = doc_next(mine=True)
    assert nxt is not None
    assert nxt["slug"] == "box"  # the only Dana-assigned connector


def test_next_mine_none_when_my_connectors_done(csv_path, monkeypatch):
    monkeypatch.setattr(doc_state, "_git_user_name", lambda: "Dana")
    set_doc_complete("box")
    assert doc_next(mine=True) is None


# --------------------------------------------------------------------------- #
# doc_dashboard
# --------------------------------------------------------------------------- #
def test_dashboard_counts(csv_path):
    d = doc_dashboard()
    assert d["connectors_total"] == 3  # akamai, box, slack
    assert d["documented"] == 0
    assert d["pending"] == 3
    set_doc_complete("akamai")
    set_doc_complete("slack")
    d2 = doc_dashboard()
    assert d2["documented"] == 2
    assert d2["pending"] == 1


# --------------------------------------------------------------------------- #
# Concurrency: a parallel writer's change is not lost
# --------------------------------------------------------------------------- #
def test_overlay_preserves_other_writers_changes(csv_path):
    # Simulate writer A marking box "out of band" between our re-read and write
    # by marking it, then marking akamai — box must remain marked.
    set_doc_complete("box")
    set_doc_complete("akamai")
    rows = _raw(csv_path)
    box = [r for r in rows if r["Connector Folder Path"] == "connectors/box"][0]
    akamai = [r for r in rows if r["Connector Folder Path"] == "connectors/akamai"]
    assert box[DOC_COLUMN] == DONE_MARK
    assert all(r[DOC_COLUMN] == DONE_MARK for r in akamai)


def test_idempotent_set_complete(csv_path):
    set_doc_complete("akamai")
    first = open(csv_path, encoding="utf-8").read()
    set_doc_complete("akamai")
    second = open(csv_path, encoding="utf-8").read()
    assert first == second


# --------------------------------------------------------------------------- #
# list_connectors (doc-find): candidate lists come ONLY from the CSV
# --------------------------------------------------------------------------- #
def test_list_connectors_returns_all_from_csv(csv_path):
    got = list_connectors()
    slugs = [c["slug"] for c in got]
    # First-seen CSV order, distinct.
    assert slugs == ["akamai", "box", "slack"]
    akamai = next(c for c in got if c["slug"] == "akamai")
    assert akamai["members"] == 2
    assert akamai["connector_id"] == "Akamai"


def test_list_connectors_substring_filter_on_slug(csv_path):
    got = list_connectors("box")
    assert [c["slug"] for c in got] == ["box"]


def test_list_connectors_filter_is_case_insensitive(csv_path):
    assert [c["slug"] for c in list_connectors("AKAMAI")] == ["akamai"]


def test_list_connectors_filter_matches_connector_id(csv_path):
    # 'Slack' Connector ID matches even though the query casing differs.
    assert [c["slug"] for c in list_connectors("slack")] == ["slack"]


def test_list_connectors_unknown_pattern_is_empty(csv_path):
    # A connector folder that is NOT in the pipeline CSV must never appear,
    # which is exactly what an empty result for a non-CSV name guarantees.
    assert list_connectors("microsoft-teams") == []
    assert list_connectors("nonexistent") == []


def test_list_connectors_reports_completion(csv_path):
    set_doc_complete("slack")
    by_slug = {c["slug"]: c for c in list_connectors()}
    assert by_slug["slack"]["complete"] is True
    assert by_slug["akamai"]["complete"] is False
