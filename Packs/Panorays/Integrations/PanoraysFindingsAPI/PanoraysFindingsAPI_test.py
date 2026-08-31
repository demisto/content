import json
import os
import pytest
import PanoraysFindingsAPI
from CommonServerPython import arg_to_datetime
from PanoraysFindingsAPI import (
    Client,
    _severity_matches,
    fetch_incidents_command,
    fetch_supplier_incidents_command,
    finding_list_command,
    get_cached_suppliers,
    supplier_finding_list_command,
    supplier_list_command,
    verify_module,
)


def load_test_data(filename: str) -> dict:
    """Load mock data from test_data directory."""
    with open(os.path.join(os.path.dirname(__file__), "test_data", filename)) as f:
        return json.load(f)


def get_client():
    # rate_limit=0 disables throttling so the suite does not sleep between mocked calls.
    return Client(base_url="https://test.com", verify=False, proxy=False, headers={}, rate_limit=0)


def test_verify_module_success(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value={})
    assert verify_module(client) == "ok"


def test_verify_module_unauthorized(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", side_effect=Exception("Unauthorized"))
    with pytest.raises(Exception, match="Authorization Error"):
        verify_module(client)


def test_verify_module_rate_limited(mocker):
    """A 429 must surface actionable guidance, since Panorays blocks the caller for a full hour."""
    client = get_client()
    mocker.patch.object(client, "_http_request", side_effect=Exception("Too Many Requests"))
    with pytest.raises(Exception, match="Rate limit reached"):
        verify_module(client)


def test_finding_list_command_success(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value=load_test_data("findings.json"))
    results = finding_list_command(client, {"limit": "1"})
    assert results.outputs[0]["id"] == "123"


def test_paginate_follows_cursor(mocker):
    """The API is cursor paginated; _paginate must echo `next` back as `next_token` until exhausted."""
    client = get_client()
    pages = [
        {"data": [{"id": "a"}], "has_next": True, "next": "tok-1"},
        {"data": [{"id": "b"}], "has_next": False, "next": None},
    ]
    request = mocker.patch.object(client, "_http_request", side_effect=pages)
    results = client.list_company_findings()

    assert [r["id"] for r in results] == ["a", "b"]
    assert request.call_count == 2
    assert request.call_args_list[1].kwargs["params"]["next_token"] == "tok-1"


def test_paginate_respects_limit(mocker):
    client = get_client()
    mocker.patch.object(
        client,
        "_http_request",
        return_value={"data": [{"id": str(i)} for i in range(10)], "has_next": True, "next": "tok"},
    )
    assert len(client.list_company_findings(limit=4)) == 4


def test_fetch_incidents_first_run(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value=load_test_data("findings.json"))
    _, incidents = fetch_incidents_command(client=client, last_run={}, first_fetch_time="3 days", max_fetch=10)
    assert len(incidents) == 1


def test_fetch_incidents_no_new_data(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value=load_test_data("findings.json"))
    last_run = {"last_fetch": "2099-06-01T00:00:00Z"}
    _, incidents = fetch_incidents_command(client=client, last_run=last_run, first_fetch_time="3 days", max_fetch=10)
    assert len(incidents) == 0


def test_supplier_list_command(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value=load_test_data("suppliers.json"))
    results = supplier_list_command(client, {"limit": "10"})
    assert [s["id"] for s in results.outputs] == ["sup-1", "sup-2"]
    assert results.outputs_prefix == "Panorays.Supplier"


def test_supplier_finding_list_command(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value=load_test_data("supplier_findings.json"))
    results = supplier_finding_list_command(client, {"supplier_id": "sup-1", "limit": "10"})
    assert results.outputs_prefix == "Panorays.SupplierFinding"
    # Every finding must carry its supplier so the context is usable downstream.
    assert all(f["supplier_id"] == "sup-1" for f in results.outputs)


def test_supplier_finding_list_requires_supplier_id():
    client = get_client()
    with pytest.raises(Exception, match="supplier_id"):
        supplier_finding_list_command(client, {})


@pytest.mark.parametrize(
    "severity,wanted,expected",
    [
        ("CRITICAL", ["CRITICAL"], True),
        ("Critical", ["CRITICAL"], True),
        ("critical", ["Critical"], True),
        ("HIGH", ["CRITICAL"], False),
        (None, ["CRITICAL"], False),
        ("HIGH", None, True),
    ],
)
def test_severity_matches_is_case_insensitive(severity, wanted, expected):
    """Panorays severity casing is not guaranteed, so matching must not depend on it."""
    assert _severity_matches(severity, wanted) is expected


def _patch_supplier_fetch(mocker, client, findings=None):
    """Point supplier enumeration at the fixture and findings at the supplied payload."""
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=load_test_data("suppliers.json")["data"])
    payload = load_test_data("supplier_findings.json")["data"] if findings is None else findings
    return mocker.patch.object(client, "list_supplier_findings", return_value=payload)


def _fetch_suppliers(client, last_run, max_fetch=50, severities=None):
    return fetch_supplier_incidents_command(
        client=client,
        last_run=last_run,
        first_fetch_time="3 days",
        max_fetch=max_fetch,
        severities=severities or ["CRITICAL"],
        statuses=None,
        date_field="update_ts",
        cache_ttl_hours=12,
        segment_ids=None,
        tags=None,
    )


def test_fetch_supplier_incidents_filters_by_severity(mocker):
    """Only CRITICAL findings become incidents, even when the API returns others."""
    client = get_client()
    _patch_supplier_fetch(mocker, client)
    next_run, incidents = _fetch_suppliers(client, {})

    # find-2 is HIGH so it is dropped; the two CRITICAL findings survive, deduped across suppliers.
    assert [i["CustomFields"]["panoraysfindingid"] for i in incidents] == ["find-1", "find-3"]
    assert all(i["CustomFields"]["panoraysfindingseverity"] == "CRITICAL" for i in incidents)
    assert next_run["supplier_index"] == 0


def test_fetch_supplier_incidents_includes_reopened(mocker):
    """REOPENED is an undocumented third status; a reopened critical finding must still raise an incident."""
    client = get_client()
    _patch_supplier_fetch(mocker, client)
    _, incidents = _fetch_suppliers(client, {})

    reopened = [i for i in incidents if i["CustomFields"]["panoraysfindingstatus"] == "REOPENED"]
    assert len(reopened) == 1
    assert reopened[0]["CustomFields"]["panoraysfindingid"] == "find-3"


def test_fetch_supplier_incidents_enriches_with_supplier_context(mocker):
    client = get_client()
    _patch_supplier_fetch(mocker, client)
    _, incidents = _fetch_suppliers(client, {})

    fields = next(i for i in incidents if i["CustomFields"]["panoraysfindingid"] == "find-1")["CustomFields"]
    assert fields["panorayssuppliername"] == "Acme Logistics"
    assert fields["panorayssupplierid"] == "sup-1"
    assert fields["panorayssupplierbusinessimpact"] == 4
    assert fields["panorayssuppliercombinedscore"] == 42
    assert fields["panorayssuppliertags"] == "critical-vendor, logistics"
    assert all("Acme Logistics" in i["name"] for i in incidents)
    assert json.loads(incidents[0]["rawJSON"])["supplier_name"] == "Acme Logistics"


def test_fetch_supplier_incidents_dedupes_across_runs(mocker):
    """A finding already ingested must not be recreated when the day-granular filter returns it again."""
    client = get_client()
    _patch_supplier_fetch(mocker, client)
    last_run = {"seen_ids": ["find-1", "find-3"], "last_fetch": "2099-01-01T00:00:00Z"}
    _, incidents = _fetch_suppliers(client, last_run)
    assert incidents == []

    # A critical finding that is NOT in the ledger still comes through.
    _, fresh = _fetch_suppliers(client, {"seen_ids": ["find-1"], "last_fetch": "2099-01-01T00:00:00Z"})
    assert [i["CustomFields"]["panoraysfindingid"] for i in fresh] == ["find-3"]


def test_fetch_supplier_incidents_resumes_mid_portfolio(mocker):
    """Hitting max_fetch must hold the cursor and NOT advance last_fetch, or suppliers get skipped."""
    client = get_client()
    # Give each supplier a distinct critical finding so both produce an incident.
    findings_by_supplier = {
        "sup-1": [{"id": "f-1", "severity": "CRITICAL", "asset_name": "a", "insert_ts": "2099-01-01T00:00:00Z"}],
        "sup-2": [{"id": "f-2", "severity": "CRITICAL", "asset_name": "b", "insert_ts": "2099-01-01T00:00:00Z"}],
    }
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=load_test_data("suppliers.json")["data"])
    mocker.patch.object(
        client,
        "list_supplier_findings",
        side_effect=lambda supplier_id, **kwargs: findings_by_supplier[supplier_id],
    )

    next_run, incidents = _fetch_suppliers(client, {"last_fetch": "2098-01-01T00:00:00Z"}, max_fetch=1)
    assert [i["CustomFields"]["panoraysfindingid"] for i in incidents] == ["f-1"]
    assert next_run["last_fetch"] == "2098-01-01T00:00:00Z", "window must not advance mid-pass"

    # The next run re-reads the held supplier, dedupes it, and moves on to the second one.
    next_run_2, incidents_2 = _fetch_suppliers(client, next_run, max_fetch=1)
    assert [i["CustomFields"]["panoraysfindingid"] for i in incidents_2] == ["f-2"]

    # A third run finds nothing new and closes the pass, resetting the cursor and advancing the window.
    next_run_3, incidents_3 = _fetch_suppliers(client, next_run_2, max_fetch=1)
    assert incidents_3 == []
    assert next_run_3["supplier_index"] == 0


def test_interrupted_first_pass_freezes_the_window(mocker):
    """An interrupted first run must persist a concrete window start, not None.

    Otherwise each resumed run re-resolves `first_fetch` from the current clock, the window slides
    forward mid-pass, and findings in the gap are never fetched by any run.
    """
    client = get_client()
    findings_by_supplier = {
        "sup-1": [{"id": "f-1", "severity": "CRITICAL", "asset_name": "a", "insert_ts": "2099-01-01T00:00:00Z"}],
        "sup-2": [{"id": "f-2", "severity": "CRITICAL", "asset_name": "b", "insert_ts": "2099-01-01T00:00:00Z"}],
    }
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=load_test_data("suppliers.json")["data"])
    mocker.patch.object(
        client,
        "list_supplier_findings",
        side_effect=lambda supplier_id, **kwargs: findings_by_supplier[supplier_id],
    )

    # First ever run (no last_fetch) that stops part-way through the portfolio.
    next_run, incidents = _fetch_suppliers(client, {}, max_fetch=1)
    assert len(incidents) == 1
    assert next_run["last_fetch"] is not None, "interrupted first pass must persist a window start"
    # It must be a usable timestamp, not a relative phrase.
    assert arg_to_datetime(next_run["last_fetch"]) is not None


def test_max_fetch_does_not_drop_findings_mid_supplier(mocker):
    """max_fetch must not strand a supplier's remaining findings.

    Regression: the cap used to break out of the finding loop and then advance the supplier cursor,
    so everything after the cut-off in that supplier was skipped for the entire pass.
    """
    client = get_client()
    many = [{"id": f"f-{i}", "severity": "CRITICAL", "asset_name": "a", "insert_ts": "2099-01-01T00:00:00Z"} for i in range(5)]
    findings_by_supplier = {"sup-1": many, "sup-2": []}
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=load_test_data("suppliers.json")["data"])
    mocker.patch.object(
        client,
        "list_supplier_findings",
        side_effect=lambda supplier_id, **kwargs: findings_by_supplier[supplier_id],
    )

    # max_fetch of 2 is smaller than sup-1's 5 findings.
    next_run, incidents = _fetch_suppliers(client, {}, max_fetch=2)

    # The cap is honored, and the cursor stays ON sup-1 so its remaining findings are not stranded.
    assert len(incidents) == 2
    assert next_run["supplier_index"] == 0, "must resume on the same supplier, not skip past it"

    # Draining the rest yields every finding exactly once, with no duplicates.
    collected = [i["CustomFields"]["panoraysfindingid"] for i in incidents]
    state = next_run
    for _ in range(10):
        state, batch = _fetch_suppliers(client, state, max_fetch=2)
        collected.extend(i["CustomFields"]["panoraysfindingid"] for i in batch)
        if state["supplier_index"] == 0 and not batch:
            break
    assert sorted(collected) == sorted(f"f-{i}" for i in range(5))
    assert len(collected) == len(set(collected))


def test_completed_pass_leaves_nothing_behind(mocker):
    """After a full pass, an immediate re-fetch must produce nothing."""
    client = get_client()
    findings_by_supplier = {
        "sup-1": [
            {"id": f"a-{i}", "severity": "CRITICAL", "asset_name": "x", "insert_ts": "2099-01-01T00:00:00Z"} for i in range(4)
        ],
        "sup-2": [
            {"id": f"b-{i}", "severity": "CRITICAL", "asset_name": "y", "insert_ts": "2099-01-01T00:00:00Z"} for i in range(4)
        ],
    }
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=load_test_data("suppliers.json")["data"])
    mocker.patch.object(
        client,
        "list_supplier_findings",
        side_effect=lambda supplier_id, **kwargs: findings_by_supplier[supplier_id],
    )

    seen, state, runs = [], {}, 0
    while runs < 10:
        runs += 1
        state, batch = _fetch_suppliers(client, state, max_fetch=3)
        assert len(batch) <= 3, "max_fetch must be a hard cap"
        seen.extend(i["CustomFields"]["panoraysfindingid"] for i in batch)
        if state["supplier_index"] == 0 and not batch:
            break

    assert sorted(seen) == sorted([f"a-{i}" for i in range(4)] + [f"b-{i}" for i in range(4)])
    assert len(seen) == len(set(seen)), "no duplicates across the pass"

    # Steady state: the pass is complete, so nothing is left over.
    _, leftover = _fetch_suppliers(client, state, max_fetch=3)
    assert leftover == []


def test_fetch_supplier_incidents_survives_one_bad_supplier(mocker):
    """A single failing supplier must not abort the whole fetch cycle."""
    client = get_client()
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=load_test_data("suppliers.json")["data"])
    mocker.patch.object(
        client,
        "list_supplier_findings",
        side_effect=[
            Exception("boom"),
            [{"id": "f-9", "severity": "CRITICAL", "asset_name": "c", "insert_ts": "2099-01-01T00:00:00Z"}],
        ],
    )
    _, incidents = _fetch_suppliers(client, {})
    assert [i["CustomFields"]["panoraysfindingid"] for i in incidents] == ["f-9"]


def test_supplier_cache_is_reused(mocker):
    """A warm cache must not re-enumerate the portfolio, which costs a request per 100 suppliers."""
    client = get_client()
    cached = {"supplier_cache": {"cached_at": "2099-01-01T00:00:00Z", "suppliers": [{"id": "cached"}]}}
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value=cached)
    list_suppliers = mocker.patch.object(client, "list_suppliers")

    # cached_at is in the future relative to now, so the entry is inside its TTL.
    result = get_cached_suppliers(client, cache_ttl_hours=12, segment_ids=None, tags=None)
    assert result == [{"id": "cached"}]
    list_suppliers.assert_not_called()


def test_supplier_cache_refreshes_when_empty(mocker):
    client = get_client()
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    set_context = mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=[{"id": "fresh"}])

    result = get_cached_suppliers(client, cache_ttl_hours=12, segment_ids=None, tags=None)
    assert result == [{"id": "fresh"}]
    assert set_context.called


def test_fetch_supplier_incidents_no_suppliers(mocker):
    client = get_client()
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setIntegrationContext")
    mocker.patch.object(client, "list_suppliers", return_value=[])
    next_run, incidents = _fetch_suppliers(client, {})
    assert incidents == []
    assert next_run["supplier_index"] == 0


def test_main_test_module_branch(mocker):
    """Tests the 'test-module' branch inside main() to boost coverage."""
    mocker.patch.object(
        PanoraysFindingsAPI.demisto,
        "params",
        return_value={"apikey": {"password": "123"}, "url": "https://test.com", "insecure": False, "proxy": False},
    )
    mocker.patch.object(PanoraysFindingsAPI.demisto, "command", return_value="test-module")
    mocker.patch.object(PanoraysFindingsAPI, "verify_module", return_value="ok")
    mock_results = mocker.patch.object(PanoraysFindingsAPI, "return_results")

    PanoraysFindingsAPI.main()
    assert mock_results.called


def test_main_routes_supplier_fetch(mocker):
    """The Findings scope parameter must select the supplier fetch path."""
    mocker.patch.object(
        PanoraysFindingsAPI.demisto,
        "params",
        return_value={
            "apikey": {"password": "123"},
            "url": "https://test.com",
            "findings_scope": "Supplier Findings",
            "supplier_finding_severity": "CRITICAL",
        },
    )
    mocker.patch.object(PanoraysFindingsAPI.demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(PanoraysFindingsAPI.demisto, "getLastRun", return_value={})
    mocker.patch.object(PanoraysFindingsAPI.demisto, "setLastRun")
    mock_incidents = mocker.patch.object(PanoraysFindingsAPI.demisto, "incidents")
    supplier_fetch = mocker.patch.object(PanoraysFindingsAPI, "fetch_supplier_incidents_command", return_value=({}, []))
    company_fetch = mocker.patch.object(PanoraysFindingsAPI, "fetch_incidents_command", return_value=({}, []))

    PanoraysFindingsAPI.main()
    assert supplier_fetch.called
    assert not company_fetch.called
    assert mock_incidents.called


def test_main_failure(mocker):
    """Tests the global error handler in main()."""
    mocker.patch.object(PanoraysFindingsAPI.demisto, "params", side_effect=Exception("Global Error"))
    mock_error = mocker.patch.object(PanoraysFindingsAPI, "return_error")

    PanoraysFindingsAPI.main()
    assert mock_error.called
