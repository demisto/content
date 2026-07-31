# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Grafana Cloud Data Sources Event Collector."""

import copy

import GrafanaCloudDataSourcesEventCollector as collector


def _ds(uid, **kw):
    d = {
        "id": 1,
        "uid": uid,
        "orgId": 1,
        "name": f"ds-{uid}",
        "type": "prometheus",
        "access": "proxy",
        "url": "https://backend.example.com",
        "user": "",
        "database": "",
        "basicAuth": False,
        "isDefault": False,
        "readOnly": True,
        "jsonData": {},
    }
    d.update(kw)
    return d


class MockClient:
    """Serves a canned data source list without touching the network."""

    _base_url = "https://example.grafana.net"

    def __init__(self, datasources=None):
        self.datasources = datasources or []
        self.calls = 0

    def list_datasources(self):
        self.calls += 1
        return copy.deepcopy(self.datasources)


# --------------------------------------------------------------------------- #
# The endpoint ignores pagination
# --------------------------------------------------------------------------- #


def test_requested_exactly_once():
    """perpage is accepted and ignored, so paging it would re-send the same records."""
    client = MockClient([_ds("a"), _ds("b")])
    events = collector.fetch_datasources(client, 5000)
    assert client.calls == 1
    assert [e["uid"] for e in events] == ["a", "b"]


def test_max_fetch_caps_the_snapshot():
    client = MockClient([_ds(str(i)) for i in range(10)])
    assert len(collector.fetch_datasources(client, 4)) == 4


def test_records_without_a_uid_are_skipped():
    client = MockClient([_ds("a"), {"name": "no uid"}])
    assert [e["uid"] for e in collector.fetch_datasources(client, 5000)] == ["a"]


# --------------------------------------------------------------------------- #
# jsonData is free-form, and credentials must never be collected
# --------------------------------------------------------------------------- #


def test_auth_relevant_json_keys_are_lifted_out():
    got = collector.summarise_json_data({"authType": "keys", "tlsSkipVerify": True, "unrelated": "x"})
    assert got["json_authType"] == "keys"
    assert got["json_tlsSkipVerify"] is True
    assert "json_unrelated" not in got


def test_json_data_is_kept_as_a_string_so_columns_stay_predictable():
    got = collector.summarise_json_data({"anything": {"deeply": "nested"}})
    assert isinstance(got["json_data"], str)
    assert "nested" in got["json_data"]


def test_empty_json_data_yields_none():
    assert collector.summarise_json_data({})["json_data"] is None


def test_nothing_nested_survives_and_metadata_is_added():
    client = MockClient([_ds("a", jsonData={"authType": "keys"})])
    event = collector.fetch_datasources(client, 5000)[0]
    assert event["_time"] == event["snapshot_at"]
    assert event["source_log_type"] == "datasource"
    assert event["grafana_instance"] == "https://example.grafana.net"
    assert not [k for k, v in event.items() if isinstance(v, dict | list)]


def test_has_url_marks_a_source_that_points_somewhere():
    assert collector.fetch_datasources(MockClient([_ds("a", url="")]), 5000)[0]["has_url"] is False
    assert collector.fetch_datasources(MockClient([_ds("b")]), 5000)[0]["has_url"] is True


def test_basic_auth_username_is_kept_but_no_secret_field_exists():
    """Grafana holds credentials in secureJsonData, which this endpoint never returns."""
    event = collector.fetch_datasources(MockClient([_ds("a", basicAuth=True, user="svc-reader")]), 5000)[0]
    assert event["basicAuth"] is True
    assert event["user"] == "svc-reader"
    assert not [k for k in event if "password" in k.lower() or "secret" in k.lower()]


def test_empty_instance_returns_no_events():
    assert collector.fetch_datasources(MockClient([]), 5000) == []
