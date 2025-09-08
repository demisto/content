import pytest
from datetime import datetime
from CommonServerPython import DemistoException
from SearchCases import prepare_start_end_time


def test_prepare_start_end_time_normal(monkeypatch):
    args = {"start_time": "2025-09-01T12:00:00", "end_time": "2025-09-02T13:00:00"}
    prepare_start_end_time(args)
    assert args["gte_creation_time"] == "2025-09-01T12:00:00"
    assert args["lte_creation_time"] == "2025-09-02T13:00:00"


def test_prepare_start_end_time_end_without_start():
    args = {"end_time": "2025-09-02T13:00:00"}
    with pytest.raises(DemistoException):
        prepare_start_end_time(args)


def test_prepare_start_end_time_only_start(monkeypatch):
    args = {"start_time": "2025-09-01T12:00:00"}
    monkeypatch.setattr("SearchCases.datetime", datetime)
    prepare_start_end_time(args)
    assert "gte_creation_time" in args
    assert "lte_creation_time" in args


def test_prepare_start_end_time_both_empty():
    args = {}
    prepare_start_end_time(args)
    assert "gte_creation_time" not in args
    assert "lte_creation_time" not in args


def test_prepare_start_end_time_unparseable():
    args = {"start_time": "not-a-date", "end_time": "also-not-a-date"}
    prepare_start_end_time(args)
    assert "gte_creation_time" not in args
    assert "lte_creation_time" not in args


def test_prepare_start_end_time_only_end():
    args = {"end_time": "2025-09-02T13:00:00"}
    try:
        prepare_start_end_time(args)
    except DemistoException as e:
        assert "start_time must be provided" in str(e)


def test_prepare_start_end_time_relative(monkeypatch):
    # Simulate relative time with dateparser
    args = {"start_time": "1 day ago", "end_time": "now"}
    prepare_start_end_time(args)
    assert "gte_creation_time" in args
    assert "lte_creation_time" in args
