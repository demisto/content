# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Cloudflare Workers Event Collector."""

import copy
import demistomock as demisto

import CloudflareWorkersEventCollector as collector


class MockClient:
    """Serves canned Workers responses without touching the network."""

    def __init__(self, scripts=None, domains=None, settings=None, settings_error=None):
        self.scripts = scripts or []
        self.domains = domains or []
        self.settings = settings or {}
        self.settings_error = settings_error
        self.script_calls = 0
        self.settings_calls: list[str] = []

    def list_scripts(self, account_id):
        self.script_calls += 1
        return {"result": copy.deepcopy(self.scripts)}

    def list_domains(self, account_id):
        return {"result": copy.deepcopy(self.domains)}

    def get_script_settings(self, account_id, script_name):
        self.settings_calls.append(script_name)
        if self.settings_error:
            raise self.settings_error
        return copy.deepcopy(self.settings.get(script_name, {"result": {}}))


def _script(name, **kw):
    s = {
        "id": name,
        "created_on": "2026-07-01T00:00:00Z",
        "modified_on": "2026-07-02T00:00:00Z",
        "handlers": ["fetch"],
        "observability": {"enabled": False},
        "logpush": False,
    }
    s.update(kw)
    return s


def _settings(bindings=None, **kw):
    r = {"bindings": bindings or [], "tail_consumers": [], "placement": {}}
    r.update(kw)
    return {"result": r}


# --------------------------------------------------------------------------- #
# The scripts endpoint ignores pagination
# --------------------------------------------------------------------------- #


def test_scripts_are_requested_exactly_once():
    """The endpoint returns the whole list whatever page is asked for.

    Paging it would re-request identical records indefinitely, so the collector
    must issue a single request.
    """
    client = MockClient(scripts=[_script("a"), _script("b")])
    events = collector.fetch_events_for_account(client, "acct-1", 5000)
    assert client.script_calls == 1
    assert [e["id"] for e in events] == ["a", "b"]


def test_max_fetch_caps_the_snapshot():
    client = MockClient(scripts=[_script(str(i)) for i in range(5)])
    events = collector.fetch_events_for_account(client, "acct-1", 3)
    assert len(events) == 3
    # Settings are only fetched for the scripts actually kept.
    assert len(client.settings_calls) == 3


# --------------------------------------------------------------------------- #
# Bindings are the security payload
# --------------------------------------------------------------------------- #


def test_sensitive_binding_types_raise_their_flags():
    bindings = [
        {"type": "secret_text", "name": "API_KEY"},
        {"type": "kv_namespace", "name": "CACHE"},
        {"type": "r2_bucket", "name": "UPLOADS"},
    ]
    got = collector.summarise_bindings(bindings)
    assert got["has_secret_binding"] is True
    assert got["has_kv_binding"] is True
    assert got["has_r2_binding"] is True
    assert got["has_d1_binding"] is False
    assert got["binding_count"] == 3
    assert got["binding_types"] == "kv_namespace|r2_bucket|secret_text"
    assert got["binding_names"] == "API_KEY|CACHE|UPLOADS"


def test_binding_values_are_never_collected():
    """A binding's value is configuration detail, and for a secret it is not returned."""
    bindings = [{"type": "plain_text", "name": "REGION", "text": "eu-west-1"}]
    got = collector.summarise_bindings(bindings)
    assert "eu-west-1" not in str(got)
    assert got["binding_names"] == "REGION"


def test_no_bindings_leaves_every_flag_false():
    got = collector.summarise_bindings([])
    assert got["binding_count"] == 0
    assert got["binding_types"] == ""
    assert all(v is False for k, v in got.items() if k.startswith("has_"))


def test_malformed_bindings_are_skipped_not_fatal():
    got = collector.summarise_bindings([{"type": "secret_text"}, "not a dict", None])
    assert got["has_secret_binding"] is True
    assert got["binding_count"] == 1


# --------------------------------------------------------------------------- #
# Hostnames come from a separate endpoint and are joined by script name
# --------------------------------------------------------------------------- #


def test_hostnames_are_joined_onto_the_owning_script():
    scripts = [_script("front"), _script("orphan")]
    domains = [
        {"hostname": "www.example.com", "service": "front", "zone_name": "example.com", "environment": "production"},
        {"hostname": "example.com", "service": "front", "zone_name": "example.com", "environment": "production"},
    ]
    client = MockClient(scripts=scripts, domains=domains)
    events = {e["id"]: e for e in collector.fetch_events_for_account(client, "acct-1", 5000)}
    assert events["front"]["hostname_count"] == 2
    assert events["front"]["hostnames"] == "example.com|www.example.com"
    assert events["front"]["zone_names"] == "example.com"
    # A script serving no hostname is still inventoried.
    assert events["orphan"]["hostname_count"] == 0
    assert events["orphan"]["hostnames"] == ""


def test_domains_without_a_service_are_ignored():
    got = collector.index_domains([{"hostname": "a.example.com"}, {"service": "s", "hostname": "b.example.com"}])
    assert list(got) == ["s"]


# --------------------------------------------------------------------------- #
# Robustness and ingestion metadata
# --------------------------------------------------------------------------- #


def test_a_script_whose_settings_fail_is_still_inventoried():
    """The inventory entry matters more than its bindings."""
    from CommonServerPython import DemistoException

    client = MockClient(scripts=[_script("a")], settings_error=DemistoException("[403] Forbidden"))
    events = collector.fetch_events_for_account(client, "acct-1", 5000)
    assert [e["id"] for e in events] == ["a"]
    assert events[0]["binding_count"] == 0


def test_a_failing_account_does_not_stop_the_others(mocker):
    # The collector logs this failure with demisto.error, which the demisto-sdk
    # harness treats as stdout and fails the run on. Production behaviour is
    # correct and stays as it is; the test simply must not let it leak.
    mocker.patch.object(demisto, "error")
    class Boom(MockClient):
        def list_scripts(self, account_id):
            if account_id == "bad":
                raise Exception("boom")
            return super().list_scripts(account_id)

    client = Boom(scripts=[_script("a")])
    events = collector.fetch_events(client, ["bad", "good"], 5000)
    assert [e["cloudflare_account_id"] for e in events] == ["good"]


def test_nested_objects_are_flattened_for_querying():
    client = MockClient(
        scripts=[_script("a", observability={"enabled": True})],
        settings={"a": _settings(bindings=[{"type": "secret_text", "name": "K"}], tail_consumers=[{"service": "t"}])},
    )
    event = collector.fetch_events_for_account(client, "acct-1", 5000)[0]
    assert event["observability_enabled"] is True
    assert event["handlers"] == "fetch"
    assert event["handler_count"] == 1
    assert event["tail_consumer_count"] == 1
    # Nothing nested survives, so every column is directly queryable.
    assert not [k for k, v in event.items() if isinstance(v, dict | list)]


def test_ingestion_metadata_added():
    client = MockClient(scripts=[_script("a")])
    event = collector.fetch_events_for_account(client, "acct-9", 5000)[0]
    assert event["_time"]
    assert event["snapshot_at"] == event["_time"]
    assert event["source_log_type"] == "worker_script"
    assert event["cloudflare_account_id"] == "acct-9"


def test_empty_account_returns_no_events():
    client = MockClient(scripts=[])
    assert collector.fetch_events_for_account(client, "acct-1", 5000) == []
