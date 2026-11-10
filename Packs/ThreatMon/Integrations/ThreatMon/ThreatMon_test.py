import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
import ThreatMon
from CommonServerPython import DemistoException, IncidentSeverity, IncidentStatus
from ThreatMon import (
    Client,
    action_command,
    alarm_stats_command,
    fetch_incidents,
    get_findings,
    get_mapping_fields_command,
    get_modified_remote_data_command,
    get_remote_data_command,
    legacy_action_command,
    legacy_update_status_command,
    list_alarms_command,
    list_cves_command,
    list_subscribed_cves_command,
    mask_secrets,
    normalize_base_url,
    parse_api_date,
    test_module as module_test,
    update_alarm_status_command,
    update_remote_system_command,
)

BASE = "https://external.threatmonit.io/api/threatmon/external"
NOW = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_alarm(code, updated, status="Open", severity="High", category="Brand Intelligence", **extra):
    alarm = {
        "alarmCode": code,
        "title": f"Alarm {code}",
        "alarmType": "Suspicious Domain Detected",
        "category": category,
        "subCategory": "Phishing",
        "description": f"Description {code}",
        "mitigation": "Take it down.",
        "source": "PASSIVE SCAN",
        "severity": severity,
        "status": status,
        "alarmDate": iso(updated - timedelta(minutes=5)),
        "lastUpdateDate": iso(updated),
        "items": [[{"key": "Phishing Domain", "value": f"examp1e-{code}.com"}]],
        "details": [{"findingId": code * 10, "Phishing Domain": f"examp1e-{code}.com"}],
    }
    alarm.update(extra)
    return alarm


class FakeThreatMon:
    """Mimics the live /v1/vulnerabilities semantics.

    With lastUpdateStartDate and afterAlarmCode, rows strictly after the (lastUpdateDate, alarmCode) pair are
    returned, ordered by that pair. Without a date, rows with a greater code are returned ordered by code.
    Pages hold 10 rows. Alarms can be hidden to mimic the lagging change index.
    """

    def __init__(self):
        self.alarms: dict[int, dict] = {}
        self.hidden: set[int] = set()
        self.requests: list[dict] = []
        self.patches: list[dict] = []

    def put(self, alarm):
        self.alarms[alarm["alarmCode"]] = alarm

    def vulnerabilities(self, request, context):
        query = {k.lower(): v[0] for k, v in parse_qs(urlparse(request.url).query).items()}
        self.requests.append(query)
        page = int(request.path.rstrip("/").split("/")[-1])
        rows = [a for code, a in self.alarms.items() if code not in self.hidden]
        if query.get("severities"):
            wanted = {s.lower() for s in query["severities"].split(",")}
            rows = [a for a in rows if a["severity"].lower() in wanted]
        if query.get("category"):
            rows = [a for a in rows if a["category"] == query["category"]]
        if "lastupdatestartdate" in query:
            start = parse_api_date(query["lastupdatestartdate"])
            after = int(query.get("afteralarmcode", "-1"))
            floor = datetime.min.replace(tzinfo=UTC)
            rows = [
                a
                for a in rows
                if (parse_api_date(a["lastUpdateDate"]) or floor, a["alarmCode"]) > (start, after) or not a["lastUpdateDate"]
            ]
            rows.sort(key=lambda a: (parse_api_date(a["lastUpdateDate"]) or floor, a["alarmCode"]))
        else:
            after = int(query.get("afteralarmcode", "0"))
            rows = sorted((a for a in rows if a["alarmCode"] > after), key=lambda a: a["alarmCode"])
        return {"totalRecords": len(rows), "data": rows[page * 10 : page * 10 + 10]}

    def install(self, requests_mock):
        requests_mock.get(re.compile(re.escape(BASE) + r"/v1/vulnerabilities/\d+"), json=self.vulnerabilities)

        def patch(request, context):
            self.patches.append(request.json())
            return ""

        requests_mock.patch(f"{BASE}/v1/incident/status", text=patch)
        return self


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    mocker.patch.object(ThreatMon.time, "sleep")
    mocker.patch.object(ThreatMon, "now_utc", return_value=NOW)
    mocker.patch.object(ThreatMon.demisto, "integrationInstance", return_value="ThreatMon_instance_1")


@pytest.fixture
def context(mocker):
    store = {"context": {}, "version": 0}

    def get_context(sync=True):
        return json.loads(json.dumps(store["context"])), store["version"]

    def set_context(value, sync=True, version=-1):
        store["context"] = json.loads(json.dumps(value))
        store["version"] += 1

    mocker.patch.object(ThreatMon, "get_integration_context_with_version", side_effect=get_context)
    mocker.patch.object(ThreatMon, "set_integration_context", side_effect=set_context)
    return store


@pytest.fixture
def client():
    return Client(BASE, "key", verify=True, proxy=False)


@pytest.fixture
def server(requests_mock):
    return FakeThreatMon().install(requests_mock)


PARAMS = {"first_fetch": "2026-11-09T00:00:00Z", "max_fetch": "50", "fetch_statuses": "Open,In Progress"}


def codes(incidents):
    return [json.loads(i["rawJSON"])["alarmCode"] for i in incidents]


# ---------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    "url, expected",
    [
        (BASE, BASE),
        (BASE + "/", BASE),
        (BASE + "/v1", BASE),
        (BASE + "/v1/", BASE),
        (None, BASE),
    ],
)
def test_normalize_base_url(url, expected):
    assert normalize_base_url(url) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-11-04T06:31:33.60638Z", datetime(2026, 11, 4, 6, 31, 33, 606380, tzinfo=UTC)),
        ("2026-11-06T12:01:10.12Z", datetime(2026, 11, 6, 12, 1, 10, 120000, tzinfo=UTC)),
        ("2026-11-06T12:01:10", datetime(2026, 11, 6, 12, 1, 10, tzinfo=UTC)),
        ("2026-11-06T12:01:10.1234567+03:00", datetime(2026, 11, 6, 9, 1, 10, 123456, tzinfo=UTC)),
        ("not a date", None),
        (None, None),
    ],
)
def test_parse_api_date(value, expected):
    assert parse_api_date(value) == expected


def test_mask_secrets():
    alarm = {
        "items": [[{"key": "Password", "value": "Winter2026!"}, {"key": "Username", "value": "john"}]],
        "details": [{"findingId": 1, "password": "Winter2026!", "Session Cookie": "abc123", "Email": "a@b.c"}],
    }
    masked = mask_secrets(alarm)
    assert masked["items"][0][0]["value"] == "Wi******"
    assert masked["items"][0][1]["value"] == "john"
    assert masked["details"][0]["password"] == "Wi******"
    assert masked["details"][0]["Session Cookie"] == "ab******"
    assert masked["details"][0]["Email"] == "a@b.c"
    assert masked["details"][0]["findingId"] == 1


def test_get_findings_tolerates_string_and_items_only():
    assert get_findings({"details": json.dumps([{"findingId": 5, "Url": "x"}])}) == [{"findingId": 5, "Url": "x"}]
    assert get_findings({"details": [], "items": [[{"key": "Victim", "value": "a.com"}]]}) == [{"Victim": "a.com"}]
    assert get_findings({"details": None, "items": None}) == []


# ---------------------------------------------------------------- fetch


def test_fetch_first_run_applies_filters(client, server):
    base = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    server.put(make_alarm(100, base))
    server.put(make_alarm(101, base + timedelta(minutes=1), status="Ignore"))
    server.put(make_alarm(102, base + timedelta(minutes=2), severity="Low"))
    server.put(make_alarm(103, base + timedelta(minutes=3), category="VIP Intelligence"))
    server.put(make_alarm(104, base - timedelta(days=2)))  # Changed before the first fetch time.
    params = {**PARAMS, "min_severity": "Medium", "categories": "Brand Intelligence"}

    incidents, state = fetch_incidents(client, params, {})

    assert codes(incidents) == [100]
    assert server.requests[0]["severities"] == "Medium,High,Critical"
    assert state["resume"] is None
    assert state["cursor"]["code"] == 103
    incident = incidents[0]
    assert incident["name"] == "ThreatMon #100: Alarm 100"
    assert incident["severity"] == IncidentSeverity.HIGH
    raw = json.loads(incident["rawJSON"])
    assert raw["mirror_id"] == "100"
    assert raw["findingIds"] == ["1000"]
    assert "examp1e-100.com" in raw["findings"]
    assert raw["mirror_instance"] == "ThreatMon_instance_1"


def test_fetch_information_severity(client, server):
    server.put(make_alarm(1, datetime(2026, 11, 9, 1, 0, tzinfo=UTC), severity="Information"))
    incidents, _ = fetch_incidents(client, PARAMS, {})
    assert incidents[0]["severity"] == IncidentSeverity.INFO


def test_fetch_catches_late_approved_alarm_with_older_code(client, server):
    """An alarm approved late keeps its older code. A cursor by code alone never returns it."""
    base = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    server.put(make_alarm(500, base))
    incidents, state = fetch_incidents(client, PARAMS, {})
    assert codes(incidents) == [500]

    server.put(make_alarm(400, base + timedelta(hours=2)))  # Older code, approved now.
    incidents, state = fetch_incidents(client, PARAMS, state)
    assert codes(incidents) == [400]


def test_fetch_never_duplicates_on_lookback_or_status_change(client, server):
    base = datetime(2026, 11, 10, 11, 50, tzinfo=UTC)
    server.put(make_alarm(1, base))
    server.put(make_alarm(2, base + timedelta(minutes=1)))
    incidents, state = fetch_incidents(client, PARAMS, {})
    assert codes(incidents) == [1, 2]

    incidents, state = fetch_incidents(client, PARAMS, state)  # The look-back window reads both again.
    assert incidents == []

    server.put(make_alarm(1, base + timedelta(minutes=5), status="In Progress"))
    incidents, state = fetch_incidents(client, PARAMS, state)
    assert incidents == []


def test_fetch_creates_alarm_when_it_moves_to_a_fetched_status(client, server):
    base = datetime(2026, 11, 10, 11, 0, tzinfo=UTC)
    server.put(make_alarm(7, base, status="Ignore"))
    incidents, state = fetch_incidents(client, PARAMS, {})
    assert incidents == []
    server.put(make_alarm(7, base + timedelta(minutes=30), status="Open"))
    incidents, state = fetch_incidents(client, PARAMS, state)
    assert codes(incidents) == [7]


def test_fetch_lagging_change_index(client, server):
    """A change that becomes visible a few minutes late, with a time before the cursor, is still fetched."""
    base = datetime(2026, 11, 10, 11, 40, tzinfo=UTC)
    server.put(make_alarm(10, base))
    server.put(make_alarm(11, base + timedelta(minutes=10)))
    server.hidden.add(10)
    incidents, state = fetch_incidents(client, PARAMS, {})
    assert codes(incidents) == [11]

    server.hidden.clear()
    incidents, state = fetch_incidents(client, PARAMS, state)
    assert codes(incidents) == [10]


def test_fetch_lagging_change_index_outside_lookback_is_missed_without_lookback(client, server):
    """Mutation check: without the look-back the late change is lost."""
    base = datetime(2026, 11, 10, 11, 40, tzinfo=UTC)
    server.put(make_alarm(10, base))
    server.put(make_alarm(11, base + timedelta(minutes=10)))
    server.hidden.add(10)
    params = {**PARAMS, "lookback_minutes": "0"}
    _, state = fetch_incidents(client, params, {})
    server.hidden.clear()
    incidents, _ = fetch_incidents(client, params, state)
    assert incidents == []


def test_fetch_resumes_exactly_after_max_fetch(client, server):
    base = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    for code in range(1, 36):
        server.put(make_alarm(code, base + timedelta(seconds=code)))
    params = {**PARAMS, "max_fetch": "12"}
    seen = []
    state: dict = {}
    for _ in range(5):
        incidents, state = fetch_incidents(client, params, state)
        seen.extend(codes(incidents))
    assert seen == list(range(1, 36))
    assert state["resume"] is None


def test_fetch_same_update_time_uses_code_as_tie_breaker(client, server):
    same = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    for code in range(1, 26):
        server.put(make_alarm(code, same))
    seen = []
    state: dict = {}
    for _ in range(4):
        incidents, state = fetch_incidents(client, {**PARAMS, "max_fetch": "7"}, state)
        seen.extend(codes(incidents))
    assert seen == list(range(1, 26))


def test_fetch_page_budget_and_deadline(client, server, mocker):
    base = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    for code in range(1, 41):
        server.put(make_alarm(code, base + timedelta(seconds=code), status="Ignore"))
    mocker.patch.object(ThreatMon, "FETCH_PAGE_BUDGET", 2)
    incidents, state = fetch_incidents(client, PARAMS, {})
    assert incidents == []
    assert state["resume"]["code"] == 20
    _, state = fetch_incidents(client, PARAMS, state)
    assert state["resume"]["code"] == 40

    incidents, state = fetch_incidents(client, PARAMS, {}, deadline=0.1)
    assert incidents == []
    assert state["resume"] is not None


def test_fetch_upgrade_from_version_1(client, server):
    """Alarms up to the highest code that version 1.x saw are never created again."""
    base = datetime(2026, 11, 10, 11, 30, tzinfo=UTC)
    server.put(make_alarm(900, base))  # Already fetched by 1.x; its status just changed.
    server.put(make_alarm(950, base + timedelta(minutes=1)))
    server.put(make_alarm(930, base - timedelta(days=1)))  # A backlog that 1.x had not reached before the upgrade.
    incidents, state = fetch_incidents(client, PARAMS, {"last_incident_id": 900, "page": 0, "max_seen_id": 920})
    assert codes(incidents) == [930, 950]
    assert state["floor"] == 920
    assert state["version"] == 2


def test_fetch_floor_parameter(client, server):
    base = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    server.put(make_alarm(5, base))
    server.put(make_alarm(6, base + timedelta(minutes=1)))
    incidents, _ = fetch_incidents(client, {**PARAMS, "lastIncidentId": "5"}, {})
    assert codes(incidents) == [6]


def test_fetch_prunes_created_codes(client, server):
    state = {
        "version": 2,
        "cursor": {"updated": iso(NOW), "code": 0},
        "resume": None,
        "floor": 0,
        "created": {"1": ThreatMon.day_number(NOW) - 500, "2": ThreatMon.day_number(NOW)},
    }
    _, state = fetch_incidents(client, PARAMS, state)
    assert state["created"] == {str(ThreatMon.day_number(NOW)): [2]}


def test_fetch_masks_secrets(client, server):
    alarm = make_alarm(3, datetime(2026, 11, 9, 1, 0, tzinfo=UTC))
    alarm["details"] = [{"findingId": 9, "Password": "Secret123"}]
    server.put(alarm)
    incidents, _ = fetch_incidents(client, PARAMS, {})
    assert "Secret123" not in incidents[0]["rawJSON"]
    incidents, _ = fetch_incidents(client, {**PARAMS, "mask_secrets": "false"}, {})
    assert "Secret123" in incidents[0]["rawJSON"]


@pytest.mark.parametrize(
    "params, message",
    [
        ({"max_fetch": "500"}, "between 1 and 200"),
        ({"lookback_minutes": "5000"}, "between 0 and 1440"),
        ({"first_fetch": "not a date"}, "First Fetch Time"),
    ],
)
def test_fetch_invalid_params(client, params, message):
    with pytest.raises((DemistoException, ValueError), match=message):
        fetch_incidents(client, {**PARAMS, **params}, {})


def test_fetch_skips_rows_without_position(client, server):
    alarm = make_alarm(8, datetime(2026, 11, 9, 1, 0, tzinfo=UTC))
    alarm["lastUpdateDate"] = None
    server.alarms[8] = alarm
    server.put(make_alarm(9, datetime(2026, 11, 9, 2, 0, tzinfo=UTC)))
    incidents, _ = fetch_incidents(client, PARAMS, {})
    assert codes(incidents) == [9]


# ---------------------------------------------------------------- mirroring

MIRROR_PARAMS = {"close_incident": "true", "close_out": "true", "lookback_minutes": "30"}


def test_mirroring_incoming_status_change_and_close(client, server, context):
    server.put(make_alarm(42, NOW - timedelta(minutes=3), status="In Progress"))
    modified = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW - timedelta(minutes=1))}, MIRROR_PARAMS)
    assert modified.modified_incident_ids == ["42"]

    first = get_remote_data_command({"id": "42", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert first.mirrored_object["status"] == "In Progress"
    assert first.entries == []  # The first delivery has nothing to compare with.

    server.put(make_alarm(42, NOW - timedelta(minutes=1), status="Resolved"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    second = get_remote_data_command({"id": "42", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert "changed from In Progress to Resolved" in second.entries[0]["Contents"]
    assert second.entries[1]["Contents"]["dbotIncidentClose"] is True

    again = get_remote_data_command({"id": "42", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert again.entries == []  # Notes and close entries are delivered once.

    server.put(make_alarm(42, NOW, status="Open"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    reopened = get_remote_data_command({"id": "42", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert reopened.entries[1]["Contents"] == {"dbotIncidentReopen": True}


def test_mirroring_ignore_closes_without_close_incident_param(client, server, context):
    server.put(make_alarm(5, NOW - timedelta(minutes=2), status="Open"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, {})
    get_remote_data_command({"id": "5", "lastUpdate": iso(NOW)}, {})
    server.put(make_alarm(5, NOW - timedelta(minutes=1), status="Ignore"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, {})
    response = get_remote_data_command({"id": "5", "lastUpdate": iso(NOW)}, {})
    assert len(response.entries) == 1  # Only the note, no close entry.


def test_mirroring_unknown_alarm(context):
    response = get_remote_data_command({"id": "77", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert response.mirrored_object == {}
    assert response.extract_for_local() is None


def test_mirroring_ignores_older_version_from_lagging_index(client, server, context):
    server.put(make_alarm(6, NOW - timedelta(minutes=1), status="Resolved"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    state = context["context"]["mirror"]
    assert state["alarms"]["6"]["status"] == "Resolved"
    # The index returns an older version of the same alarm again.
    server.put(make_alarm(6, NOW - timedelta(minutes=4), status="Open"))
    context["context"]["mirror"]["resume"] = None
    context["context"]["mirror"]["cursor"] = {"updated": iso(NOW - timedelta(minutes=10)), "code": 0}
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert context["context"]["mirror"]["alarms"]["6"]["status"] == "Resolved"


def test_mirroring_cursor_does_not_drift_without_changes(client, server, context):
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    first = context["context"]["mirror"]["cursor"]
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert context["context"]["mirror"]["cursor"] == first
    assert server.requests[-1]["lastupdatestartdate"] == iso(NOW - timedelta(minutes=30))


def test_mirroring_resumes_after_page_budget(client, server, context, mocker):
    mocker.patch.object(ThreatMon, "MIRROR_PAGE_BUDGET", 1)
    for code in range(1, 16):
        server.put(make_alarm(code, NOW - timedelta(minutes=20) + timedelta(seconds=code)))
    first = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert len(first.modified_incident_ids) == 10
    assert context["context"]["mirror"]["resume"]["code"] == 10
    second = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert len(second.modified_incident_ids) == 15


def test_mirroring_prunes_cache(client, server, context):
    context["context"] = {
        "mirror": {
            "alarms": {"1": {"status": "Open", "lastUpdateDate": iso(NOW - timedelta(days=3))}},
            "set": {"1": {"status": "Resolved", "at": NOW.timestamp() - 7200}},
            "delivered": {"1": {"status": "Open", "day": ThreatMon.day_number(NOW) - 500}},
        }
    }
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    state = context["context"]["mirror"]
    assert state["alarms"] == {}
    assert state["set"] == {}
    assert state["delivered"] == {}


def update_args(delta=None, status=IncidentStatus.ACTIVE, changed=True, data=None):
    return {"remoteId": "42", "incidentChanged": changed, "delta": delta or {}, "status": status, "data": data or {}}


def test_outgoing_close_sets_resolved_and_ignore(client, server, context):
    assert (
        update_remote_system_command(
            client,
            update_args(status=IncidentStatus.DONE, data={"closeReason": "Resolved", "closeNotes": "Done."}),
            MIRROR_PARAMS,
        )
        == "42"
    )
    assert server.patches[-1]["status"] == "Resolved"
    assert server.patches[-1]["alarmIds"] == [42]
    assert "Done." in server.patches[-1]["remarks"]

    args = {**update_args(status=IncidentStatus.DONE, data={"closeReason": "False Positive"}), "remoteId": "43"}
    update_remote_system_command(client, args, MIRROR_PARAMS)
    assert server.patches[-1]["status"] == "Ignore"


def test_outgoing_close_without_close_out_param(client, server, context):
    update_remote_system_command(client, update_args(status=IncidentStatus.DONE), {})
    assert server.patches == []


def test_outgoing_status_field_and_echo_prevention(client, server, context):
    update_remote_system_command(client, update_args(delta={"status": "In Progress"}), MIRROR_PARAMS)
    assert server.patches[-1]["status"] == "In Progress"
    # The same status again (for example after incoming mirroring) is not sent.
    update_remote_system_command(client, update_args(delta={"status": "In Progress"}), MIRROR_PARAMS)
    assert len(server.patches) == 1

    # The change index shows the change back later: no note and no close entry.
    server.put(make_alarm(42, NOW - timedelta(seconds=10), status="In Progress"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    response = get_remote_data_command({"id": "42", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert response.entries == []

    # A row older than this change is ignored completely.
    server.put(make_alarm(42, NOW - timedelta(minutes=10), status="Open"))
    context["context"]["mirror"]["alarms"]["42"] = {"status": "Open", "lastUpdateDate": iso(NOW - timedelta(minutes=10))}
    response = get_remote_data_command({"id": "42", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert response.mirrored_object == {}


def test_outgoing_not_changed_or_invalid(client, server, context):
    update_remote_system_command(client, update_args(changed=False, delta={"status": "Open"}), MIRROR_PARAMS)
    update_remote_system_command(client, {**update_args(delta={"status": "Open"}), "remoteId": "abc"}, MIRROR_PARAMS)
    update_remote_system_command(client, update_args(delta={"other": "x"}), MIRROR_PARAMS)
    assert server.patches == []


def test_outgoing_error_is_raised(client, requests_mock, context):
    requests_mock.patch(f"{BASE}/v1/incident/status", status_code=400, text='{"error":"bad"}')
    with pytest.raises(DemistoException, match="400"):
        update_remote_system_command(client, update_args(delta={"status": "Open"}), MIRROR_PARAMS)


def test_get_mapping_fields():
    result = get_mapping_fields_command().extract_mapping()
    assert "status" in result["ThreatMon Alert"]


# ---------------------------------------------------------------- client and errors


def test_client_sends_headers_and_customer_name(requests_mock):
    requests_mock.get(f"{BASE}/v1/alarm/status", json={"Open": "1"})
    Client(BASE + "/v1", "secret", True, False, customer_name="Acme Corp").get_stats("status")
    request = requests_mock.last_request
    assert request.headers["X-COMPANY-API-KEY"] == "secret"
    assert request.headers["User-Agent"].startswith("threatmon-xsoar/")
    assert request.qs["customername"] == ["acme corp"]
    assert request.url.startswith(BASE + "/v1/alarm/status")


def test_client_retries_get_on_rate_limit_and_server_errors(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/alarm/status",
        [{"status_code": 429}, {"status_code": 502}, {"json": {"Open": "3"}}],
    )
    assert client.get_stats("status") == {"Open": "3"}
    assert requests_mock.call_count == 3


def test_client_retries_transient_empty_403_once(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/alarm/status", [{"status_code": 403, "text": ""}, {"json": {"Open": "3"}}])
    assert client.get_stats("status") == {"Open": "3"}


@pytest.mark.parametrize(
    "status, text, customer, message",
    [
        (403, "", None, "rejected the API key"),
        (403, "", "Acme", "sub company"),
        (401, "", None, "rejected the API key"),
        (403, "<html><title>403 Forbidden</title></html>", None, "not whitelisted"),
        (403, "error code: 1010", None, "1010"),
        (429, "", None, "rate limit"),
        (500, "boom", None, "ThreatMon API error 500: boom"),
    ],
)
def test_client_error_messages(requests_mock, status, text, customer, message):
    requests_mock.get(f"{BASE}/v1/alarm/status", status_code=status, text=text)
    with pytest.raises(DemistoException, match=message):
        Client(BASE, "key", True, False, customer_name=customer).get_stats("status")


def test_client_invalid_json(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/alarm/status", text="not json")
    with pytest.raises(DemistoException, match="invalid JSON"):
        client.get_stats("status")


def test_client_retries_connection_errors_for_get_only(client, mocker):
    calls = []

    def failing(*args, **kwargs):
        calls.append(args[0])
        raise DemistoException("Verify that the server URL parameter is correct. Error Type: ConnectionError")

    mocker.patch.object(client, "_http_request", side_effect=failing)
    with pytest.raises(DemistoException):
        client.get_stats("status")
    assert len(calls) == ThreatMon.MAX_RETRIES + 1
    calls.clear()
    with pytest.raises(DemistoException):
        client.submit_action("/v1/takedown", 1, "x")
    assert len(calls) == 1


def test_rate_limiter_waits(mocker):
    clock = iter([0.0, 0.0, 0.1, 0.1, 0.2, 0.2, 10.5])
    mocker.patch.object(ThreatMon.time, "monotonic", side_effect=lambda: next(clock))
    limiter = ThreatMon.RateLimiter(calls=2, window=10.0)
    limiter.wait()
    limiter.wait()
    limiter.wait()
    ThreatMon.time.sleep.assert_called_once()
    assert ThreatMon.time.sleep.call_args[0][0] == pytest.approx(9.8)


# ---------------------------------------------------------------- commands


def test_module_command(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/alarm/status", json={"Open": "1"})
    assert module_test(client, {"isFetch": "true", **PARAMS}) == "ok"
    with pytest.raises(DemistoException):
        module_test(client, {"isFetch": "true", "max_fetch": "0" if False else "999"})


def test_list_alarms(client, server):
    base = datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    for code in range(1, 26):
        server.put(make_alarm(code, base, status="Open" if code % 2 else "Resolved"))
    result = list_alarms_command(client, {"limit": "15", "severity": "High", "status": "Open"})
    assert [a["AlarmCode"] for a in result.outputs] == list(range(1, 16, 2))
    assert result.outputs[0]["FindingIDs"] == [10]
    assert server.requests[0]["severities"] == "High"

    result = list_alarms_command(client, {"limit": "5", "page": "1"})
    assert [a["AlarmCode"] for a in result.outputs] == [6, 7, 8, 9, 10]
    result = list_alarms_command(client, {"limit": "15", "page": "1"})
    assert [a["AlarmCode"] for a in result.outputs] == list(range(16, 26))

    with pytest.raises(DemistoException):
        list_alarms_command(client, {"limit": "500"})


def test_list_alarms_date_filters(client, server):
    list_alarms_command(
        client,
        {
            "start_date": "2026-11-01T00:00:00Z",
            "end_date": "2026-11-02T00:00:00Z",
            "updated_after": "2026-11-01T00:00:00Z",
            "category": "VIP Intelligence",
        },
    )
    query = server.requests[0]
    assert query["startdate"] == "2026-11-01T00:00:00.000000Z"
    assert query["enddate"] == "2026-11-02T00:00:00.000000Z"
    assert query["category"] == "VIP Intelligence"


def test_update_alarm_status(client, server):
    result = update_alarm_status_command(client, {"alarm_ids": "1,2", "status": "in progress", "remarks": "Checked."})
    assert server.patches[-1] == {"alarmIds": [1, 2], "status": "In Progress", "remarks": "Checked."}
    assert result.outputs == [{"AlarmCode": 1, "Status": "In Progress"}, {"AlarmCode": 2, "Status": "In Progress"}]
    with pytest.raises(DemistoException):
        update_alarm_status_command(client, {"alarm_ids": "x", "status": "Open"})
    with pytest.raises(DemistoException):
        update_alarm_status_command(client, {"alarm_ids": "1", "status": "False Positive"})


def test_legacy_update_status(client, requests_mock):
    requests_mock.patch(f"{BASE}/v1/incident/status", text="")
    assert (
        "status changed to Resolved"
        in legacy_update_status_command(client, {"alarmId": "5", "status": "Resolved"}).readable_output
    )
    requests_mock.patch(f"{BASE}/v1/incident/status", status_code=400, text="bad")
    with pytest.raises(DemistoException, match="Failed to change status"):
        legacy_update_status_command(client, {"alarmId": "5", "status": "Resolved"})
    with pytest.raises(DemistoException):
        legacy_update_status_command(client, {"alarmId": "x", "status": "Resolved"})


@pytest.mark.parametrize(
    "status, result, submitted",
    [
        (200, "Submitted", True),
        (400, "Not Eligible", False),
        (403, "Not Allowed", False),
        (404, "Not Found", False),
        (409, "Already Requested", True),
    ],
)
@pytest.mark.parametrize(
    "action, path, prefix",
    [
        ("takedown", "/v1/takedown", "ThreatMon.Takedown"),
        ("data_removal", "/v1/blackMarket/dataRemoval", "ThreatMon.DataRemoval"),
    ],
)
def test_action_results(client, requests_mock, status, result, submitted, action, path, prefix):
    requests_mock.post(f"{BASE}{path}", status_code=status, text="")
    response = action_command(client, {"finding_id": "123", "finding": "examp1e.com"}, action)
    assert response.outputs_prefix == prefix
    assert response.outputs["Result"] == result
    assert response.outputs["Submitted"] is submitted
    assert requests_mock.last_request.json() == {"findingId": 123, "finding": "examp1e.com"}


def test_action_never_retried(client, requests_mock):
    requests_mock.post(f"{BASE}/v1/takedown", status_code=503, text="")
    with pytest.raises(DemistoException, match="503"):
        action_command(client, {"finding_id": "1", "finding": "x"}, "takedown")
    assert requests_mock.call_count == 1


def test_action_whitelist_error(client, requests_mock):
    requests_mock.post(f"{BASE}/v1/takedown", status_code=403, text="<html>403 Forbidden</html>")
    with pytest.raises(DemistoException, match="whitelisted"):
        action_command(client, {"finding_id": "1", "finding": "x"}, "takedown")


@pytest.mark.parametrize(
    "args, message",
    [({"finding": "x"}, "required"), ({"finding_id": "1"}, "required"), ({"finding_id": "a", "finding": "x"}, "integer")],
)
def test_action_invalid_args(client, args, message):
    with pytest.raises(ValueError, match=message):
        action_command(client, args, "takedown")


@pytest.mark.parametrize(
    "status, message",
    [
        (200, None),
        (404, "Finding not found"),
        (409, "already exists"),
        (403, "quota"),
        (400, "not eligible"),
        (500, "API Error: 500"),
    ],
)
def test_legacy_action(client, requests_mock, status, message):
    requests_mock.post(f"{BASE}/v1/takedown", status_code=status, text="")
    if message is None:
        assert (
            "submitted successfully"
            in legacy_action_command(client, {"findingId": "1", "finding": "x"}, "takedown").readable_output
        )
    else:
        with pytest.raises(DemistoException, match=message):
            legacy_action_command(client, {"findingId": "1", "finding": "x"}, "takedown")


def test_alarm_stats(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/alarm/status", json={"Open": "64", "Ignore": "12711"})
    requests_mock.get(f"{BASE}/v1/alarm/severity", json={"High": "584"})
    requests_mock.get(f"{BASE}/v1/alarm/total", json={"Brand Intelligence": "125"})
    result = alarm_stats_command(client, {"from_date": "2026-10-01", "to_date": "2026-11-01"})
    assert result.outputs == {
        "Status": {"Open": 64, "Ignore": 12711},
        "Severity": {"High": 584},
        "Category": {"Brand Intelligence": 125},
    }
    assert requests_mock.last_request.qs["fromdate"] == ["2026-10-01t00:00:00.000000z"]


CVE_RESPONSE = {
    "totalRecords": 1,
    "data": [{"cve": "CVE-2026-0001", "summary": "x", "cvssV3": 9.8, "vendors": {"acme": ["router"]}, "exploit": True}],
}


def test_cve_commands(requests_mock):
    requests_mock.get(f"{BASE}/v1/cve/0", json=CVE_RESPONSE)
    requests_mock.get(f"{BASE}/v1/cve/subscribed/2", json=CVE_RESPONSE)
    mssp = Client(BASE, "key", True, False, customer_name="Parent Sub")
    result = list_cves_command(mssp, {"cvss": "CRITICAL"})
    assert result.outputs[0]["cve"] == "CVE-2026-0001"
    assert "acme: router" in result.readable_output
    assert "customername" not in requests_mock.last_request.qs
    list_subscribed_cves_command(mssp, {"page": "2", "customer_name": "Other Sub"})
    assert requests_mock.last_request.qs["customername"] == ["other sub"]
    list_subscribed_cves_command(mssp, {"page": "2"})
    assert requests_mock.last_request.qs["customername"] == ["parent sub"]


def test_mirroring_keeps_changes_older_than_cache_when_cortex_asks_for_them(client, server, context):
    """After a long pause Cortex asks for changes since an old time. They must not be pruned first."""
    server.put(make_alarm(31, NOW - timedelta(hours=40), status="Resolved"))
    modified = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW - timedelta(hours=48))}, MIRROR_PARAMS)
    assert modified.modified_incident_ids == ["31"]
    modified = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert modified.modified_incident_ids == []
    assert context["context"]["mirror"]["alarms"] == {}


# ---------------------------------------------------------------- review regressions


def test_incoming_ignore_close_is_not_overwritten_by_outgoing_close(client, server, context):
    """A ThreatMon analyst sets Ignore; the incident is closed by incoming mirroring; closing must not send Resolved."""
    server.put(make_alarm(60, NOW - timedelta(minutes=5), status="Open"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    get_remote_data_command({"id": "60", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    server.put(make_alarm(60, NOW - timedelta(minutes=1), status="Ignore"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    response = get_remote_data_command({"id": "60", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert response.entries[-1]["Contents"]["dbotIncidentClose"] is True
    args = {**update_args(status=IncidentStatus.DONE, data={"closeReason": "Other"}), "remoteId": "60"}
    update_remote_system_command(client, args, MIRROR_PARAMS)
    assert server.patches == []


def test_closed_incident_edits_do_not_patch_again(client, server, context):
    args = {**update_args(status=IncidentStatus.DONE, data={"closeReason": "Resolved"}), "remoteId": "61"}
    update_remote_system_command(client, args, MIRROR_PARAMS)
    update_remote_system_command(client, args, MIRROR_PARAMS)
    assert len(server.patches) == 1


def test_echo_guard_drops_pre_change_version_and_accepts_later_changes(client, server, context):
    """Cortex closes the incident (Ignore); the lagging index still returns the earlier Open version."""
    server.put(make_alarm(62, NOW - timedelta(seconds=60), status="Open"))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    get_remote_data_command({"id": "62", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    args = {**update_args(status=IncidentStatus.DONE, data={"closeReason": "False Positive"}), "remoteId": "62"}
    update_remote_system_command(client, args, MIRROR_PARAMS)
    assert server.patches[-1]["status"] == "Ignore"

    response = get_remote_data_command({"id": "62", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert response.mirrored_object == {}  # No false reopen.

    # A real change by a ThreatMon analyst after the integration's change is mirrored.
    server.put(make_alarm(62, NOW + timedelta(minutes=5), status="Open"))
    context["context"]["mirror"]["resume"] = None
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    response = get_remote_data_command({"id": "62", "lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert response.entries[-1]["Contents"] == {"dbotIncidentReopen": True}


def test_mirror_state_save_retries_on_version_conflict(client, server, context, mocker):
    """A save that conflicts with another command re-applies only its own changes on the latest state."""
    real_set = ThreatMon.set_integration_context
    calls = {"n": 0}

    def conflict_once(value, sync=True, version=-1):
        calls["n"] += 1
        if calls["n"] == 1:
            # Another command saved a delivered status in between.
            context["context"] = {
                "mirror": {"alarms": {}, "set": {}, "delivered": {"99": {"status": "Resolved", "day": ThreatMon.day_number(NOW)}}}
            }
            raise ValueError("version conflict")
        real_set(value, sync=sync, version=version)

    mocker.patch.object(ThreatMon, "set_integration_context", side_effect=conflict_once)
    server.put(make_alarm(63, NOW - timedelta(minutes=1)))
    get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    state = context["context"]["mirror"]
    assert "63" in state["alarms"]
    assert state["delivered"]["99"]["status"] == "Resolved"


def test_mirror_state_save_gives_up_after_repeated_conflicts(context, mocker):
    mocker.patch.object(ThreatMon, "set_integration_context", side_effect=ValueError("conflict"))
    with pytest.raises(DemistoException, match="mirroring state"):
        ThreatMon.update_mirror_state(lambda state: None)


def test_mirroring_reports_backlog_older_than_lookback(client, server, context, mocker):
    """Alarms read while resuming a backlog are reported even when they changed before the look-back window."""
    mocker.patch.object(ThreatMon, "MIRROR_PAGE_BUDGET", 1)
    for code in range(1, 21):
        server.put(make_alarm(code, NOW - timedelta(hours=5) + timedelta(seconds=code)))
    first = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW - timedelta(hours=6))}, MIRROR_PARAMS)
    assert len(first.modified_incident_ids) == 20 or len(first.modified_incident_ids) == 10
    second = get_modified_remote_data_command(client, {"lastUpdate": iso(NOW)}, MIRROR_PARAMS)
    assert {"11", "20"} <= set(second.modified_incident_ids)


def test_client_retries_stop_at_deadline(client, requests_mock, mocker):
    requests_mock.get(f"{BASE}/v1/alarm/status", status_code=503)
    client.deadline = ThreatMon.time.time() + 1
    with pytest.raises(DemistoException, match="503"):
        client.get_stats("status")
    assert requests_mock.call_count == 1


def test_created_codes_compact_round_trip():
    created = ThreatMon.load_created({"20000": [5, 3], "20001": [7]})
    assert created == {"5": 20000, "3": 20000, "7": 20001}
    assert ThreatMon.dump_created(created, 20001) == {"20000": [3, 5], "20001": [7]}
    assert ThreatMon.dump_created(created, 20500) == {}
    assert ThreatMon.load_created(None) == {}


# ---------------------------------------------------------------- intelligence, assets, sandbox, MSSP

CVE_DETAIL = {
    "cve": "CVE-2024-3400",
    "summary": "A command injection in GlobalProtect.",
    "publishedAt": "2024-04-12T08:15:06Z",
    "updatedAt": "2025-11-04T16:49:20Z",
    "cvssV3_1": 10.0,
    "cvssV4": None,
    "severity": "CRITICAL",
    "tmvs": 25.0,
    "brvs": 22.5,
    "epss": 0.99,
    "exploit": True,
    "hasPoc": True,
    "kev": {"dateAdded": "2024-04-12", "requiredAction": "Apply the vendor mitigations."},
    "affectedAssets": {"totalCount": 0},
    "pocs": [{"url": "https://github.com/example/poc", "source": "GITHUB", "verdict": "UNVERIFIED"}],
    "report": {
        "header": {"title": "PAN-OS GlobalProtect RCE"},
        "analyst_brief": {"priority": "P1", "priority_rationale": "Exploited in the wild."},
        "overview": {"executive_summary": ["Critical pre-auth RCE."]},
        "response": {
            "ir_playbook": [{"step_num": 1, "title": "Isolate", "description": "Disable GlobalProtect.", "eta": "15 min"}]
        },
        "detection": {"detection_opportunities": ["Unexpected files in GlobalProtect folders."]},
    },
    "timeline": [{"date": "2026-11-06T14:21:14Z", "type": "MENTION", "platformLabel": "X", "description": "Mentioned on X"}],
}


def test_cve_reputation(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/cve/detail/CVE-2024-3400", json=CVE_DETAIL)
    requests_mock.get(f"{BASE}/v1/cve/detail/CVE-1999-0001", status_code=404, json={"message": "CVE not found"})
    results = ThreatMon.cve_reputation_command(client, {"cve": "cve-2024-3400,,CVE-1999-0001"}, RELIABILITY)
    assert results[0].indicator.id == "CVE-2024-3400"
    assert results[0].indicator.cvss == 10.0
    assert results[0].outputs["tmvs"] == 25.0
    assert "CISA required action" in results[0].readable_output
    assert "no information" in results[1].readable_output


def test_cve_get_renders_report_and_timeline(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/cve/detail/CVE-2024-3400", json=CVE_DETAIL)
    result = ThreatMon.cve_get_command(client, {"cve_id": "CVE-2024-3400", "include": "report,timeline"})
    assert requests_mock.last_request.qs["include"] == ["report,timeline"]
    assert "**Priority:** P1" in result.readable_output
    assert "Response Steps" in result.readable_output
    assert "Timeline" in result.readable_output
    assert ThreatMon.cve_report_markdown("plain text") == "\n### AI Report\nplain text\n"
    assert ThreatMon.cve_report_markdown(None) == ""
    with pytest.raises(DemistoException):
        ThreatMon.cve_get_command(client, {})


def test_cve_search_reads_cursor_parts(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/cve/vulnerabilities",
        [
            {"json": {"data": [{"cve": f"CVE-2026-{i}"} for i in range(3)], "nextCursor": "abc"}},
            {"json": {"data": [{"cve": f"CVE-2026-{i}"} for i in range(3, 6)], "nextCursor": "def"}},
        ],
    )
    result = ThreatMon.cve_search_command(client, {"start_date": "2026-11-01T00:00:00Z", "exploit": "true", "limit": "5"})
    records = result.outputs["ThreatMon.CVE(val.cve && val.cve == obj.cve)"]
    assert [r["cve"] for r in records] == [f"CVE-2026-{i}" for i in range(6)]  # Whole parts.
    assert result.outputs["ThreatMon.CVESearch"]["NextCursor"] == "def"
    assert requests_mock.request_history[0].qs["exploit"] == ["true"]
    assert requests_mock.request_history[1].qs["cursor"] == ["abc"]
    with pytest.raises(ValueError):
        ThreatMon.cve_search_command(client, {})
    with pytest.raises(DemistoException):
        ThreatMon.cve_search_command(client, {"start_date": "2026-11-01", "limit": "5000"})


def test_cve_subscriptions(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/cve/subscriptions",
        json={
            "data": [{"vendor": "acme", "product": "router", "productId": 7, "recipients": [{"email": "a@example.com"}]}],
            "nextCursor": None,
        },
    )
    requests_mock.get(f"{BASE}/v1/cve/subscriptions/vulnerabilities", json={"data": [{"cve": "CVE-2026-1"}], "nextCursor": 5})
    result = ThreatMon.cve_subscription_list_command(client, {"recipient_email": "a@example.com"})
    assert "a@example.com" in result.readable_output
    result = ThreatMon.subscribed_cve_search_command(client, {"start_date": "2026-10-01", "limit": "1"})
    assert result.outputs["ThreatMon.SubscribedCVESearch"]["NextCursor"] == 5


def test_asset_list(client, requests_mock):
    rows = [{"ip": f"10.0.0.{i}", "countryName": "TR"} for i in range(10)]
    requests_mock.get(f"{BASE}/df/ip/0", json={"totalRecords": 13, "data": rows})
    requests_mock.get(f"{BASE}/df/ip/1", json={"totalRecords": 13, "data": rows[:3]})
    result = ThreatMon.asset_list_command(client, {"asset_type": "IP", "limit": "5", "page": "1"})
    assert [a["ip"] for a in result.outputs] == [f"10.0.0.{i}" for i in range(5, 10)]
    assert result.outputs[0]["AssetType"] == "IP"
    assert "Country Name" in result.readable_output
    requests_mock.get(f"{BASE}/df/v2/dnsRecord/0", json={"totalRecords": 0, "data": []})
    assert ThreatMon.asset_list_command(client, {"asset_type": "DNS Record"}).outputs == []
    with pytest.raises(DemistoException):
        ThreatMon.asset_list_command(client, {"asset_type": "Printer"})
    with pytest.raises(DemistoException):
        ThreatMon.asset_list_command(client, {"asset_type": "IP", "limit": "500"})


def test_ciso_dashboard(client, requests_mock):
    dashboard = {
        "statistics": {"averageScore": 64.0, "openAlert": 64},
        "score": {
            "score": 64.0,
            "grade": "D",
            "asScore": 97,
            "asGrade": "A",
            "attackSurface": True,
            "scScore": None,
            "supplyChain": False,
            "report": "# Report",
        },
        "topAlerts": [{"title": "Phishing", "total": 3}],
    }
    requests_mock.get(f"{BASE}/v1/ciso/dashboard", json=dashboard)
    result = ThreatMon.ciso_dashboard_command(client, {})
    assert "Risk Score 64.0 (D)" in result.readable_output
    assert "Attack Surface" in result.readable_output
    assert "Supply Chain" not in result.readable_output
    assert "# Report" in result.readable_output
    assert "# Report" not in ThreatMon.ciso_dashboard_command(client, {"include_report": "false"}).readable_output


def test_nice_header():
    assert ThreatMon.nice_header("countryName") == "Country Name"
    assert ThreatMon.nice_header("cvssV3_1") == "CVSS 3.1"
    assert ThreatMon.nice_header("ip") == "IP"
    assert ThreatMon.nice_header("step_num") == "Step"


@pytest.fixture
def files(mocker):
    created = []

    def fake_file_result(name, data, file_type=None):
        created.append((name, data))
        return {"File": name, "FileID": f"id-{len(created)}", "Type": file_type}

    mocker.patch.object(ThreatMon, "fileResult", side_effect=fake_file_result)
    return created


def test_screenshot_get(client, requests_mock, files):
    requests_mock.get(f"{BASE}/v1/screenshot", [{"content": b"PNG"}, {"status_code": 404}, {"status_code": 403, "text": ""}])
    result = ThreatMon.screenshot_get_command(client, {"blob_name": "https://capi.example/download?blobName=FILE-SHARE/abc.png"})
    assert result["File"] == "abc.png"
    assert files == [("abc.png", b"PNG")]
    assert "not available" in ThreatMon.screenshot_get_command(client, {"blob_name": "x"}).readable_output
    assert "not available" in ThreatMon.screenshot_get_command(client, {"blob_name": "y"}).readable_output
    assert requests_mock.call_count == 3  # A 403 for a screenshot is not retried.
    with pytest.raises(DemistoException):
        ThreatMon.screenshot_get_command(client, {})
    assert ThreatMon.screenshot_name("FILE-SHARE/abc") == "abc.png"


def test_fetch_attaches_screenshots(client, server, requests_mock, files):
    alarm = make_alarm(70, datetime(2026, 11, 9, 1, 0, tzinfo=UTC))
    alarm["items"] = [[{"key": "Screenshot", "value": "https://capi.example/download?blobName=FILE-SHARE/s1.png"}]]
    alarm["details"] = [{"findingId": 1, "Screenshot": "https://capi.example/download?blobName=FILE-SHARE/s2.png"}]
    server.put(alarm)
    server.put(make_alarm(71, datetime(2026, 11, 9, 2, 0, tzinfo=UTC)))
    requests_mock.get(f"{BASE}/v1/screenshot", [{"content": b"one"}, {"status_code": 403, "text": ""}])
    incidents, _ = fetch_incidents(client, PARAMS, {})
    assert incidents[0]["attachment"] == [{"path": "id-1", "name": "s2.png", "showMediaFile": True}]
    assert "attachment" not in incidents[1]
    incidents, _ = fetch_incidents(client, {**PARAMS, "attach_screenshots": "false"}, {})
    assert all("attachment" not in i for i in incidents)


def test_fetch_screenshot_errors_never_stop_the_fetch(client, server, mocker, files):
    alarm = make_alarm(72, datetime(2026, 11, 9, 1, 0, tzinfo=UTC))
    alarm["details"] = [{"findingId": 1, "Screenshot": "FILE-SHARE/s3.png"}]
    server.put(alarm)
    mocker.patch.object(client, "get_screenshot", side_effect=DemistoException("boom"))
    incidents, _ = fetch_incidents(client, PARAMS, {})
    assert codes(incidents) == [72]


SUBMISSION_ROW = {
    "id": 260,
    "sid": "uuid-temporary",
    "originalFileName": "sample.txt",
    "createdAt": "2026-11-10T12:00:05.0",
    "status": 1,
}
RELIABILITY = "B - Usually reliable"


@pytest.fixture
def sandbox_env(mocker, tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"harmless")
    mocker.patch.object(ThreatMon.demisto, "getFilePath", return_value={"path": str(sample), "name": "sample.txt"})
    mocker.patch.object(ThreatMon.demisto, "demistoVersion", return_value={"version": "8.9.0", "buildNumber": "1"})
    mocker.patch.object(ThreatMon.time, "time", return_value=NOW.timestamp())
    return sample


def sandbox_list(rows):
    return {"code": 200, "status": "OK", "data": {"content": rows, "totalElements": len(rows)}}


def test_sandbox_submit_and_poll_until_verdict(client, requests_mock, sandbox_env):
    requests_mock.post(f"{BASE}/v1/sandbox/submit", json={"code": 200, "data": {"success": True, "sid": "uuid-temporary"}})
    row = dict(SUBMISSION_ROW)
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([row]))
    first = ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert first.scheduled_command is not None
    poll_args = first.scheduled_command._args
    assert poll_args["submission_id"] == "260"
    assert requests_mock.request_history[0].method == "POST"
    assert b'filename="sample.txt"' in requests_mock.request_history[0].body

    finished = {**row, "sid": "8492", "overallRating": "Malicious", "status": 2}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([{"id": 999, "originalFileName": "other"}, finished]))
    requests_mock.get(f"{BASE}/v1/sandbox/submission/8492/status", json={"code": 200, "data": finished})
    requests_mock.get(
        f"{BASE}/v1/sandbox/submission/8492/results",
        json={
            "code": 200,
            "data": {"content": [{"fileName": "sample.txt", "sha256": "a" * 64, "rating": "Malicious", "malwareName": "Agent"}]},
        },
    )
    done = ThreatMon.sandbox_submit_command(poll_args, client, RELIABILITY)
    assert done.scheduled_command is None
    assert done.outputs["OverallRating"] == "Malicious"
    assert done.indicators[0].dbot_score.score == 3
    assert sum(1 for r in requests_mock.request_history if r.method == "POST") == 1  # Submitted once.


def test_sandbox_submit_waits_until_listed(client, requests_mock, sandbox_env):
    requests_mock.post(f"{BASE}/v1/sandbox/submit", json={"code": 200, "data": {"success": True}})
    requests_mock.get(
        f"{BASE}/v1/sandbox/submissions", json=sandbox_list([{**SUBMISSION_ROW, "createdAt": "2026-11-01T00:00:00"}])
    )
    result = ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert "submission_id" not in result.scheduled_command._args
    assert result.scheduled_command._args["file_name"] == "sample.txt"


def test_sandbox_duplicate_submission_follows_earlier_one(client, requests_mock, sandbox_env):
    requests_mock.post(f"{BASE}/v1/sandbox/submit", status_code=500, text="")
    earlier = {**SUBMISSION_ROW, "id": 100, "sid": "77", "overallRating": "Clean", "createdAt": "2026-01-01T00:00:00"}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([earlier]))
    requests_mock.get(f"{BASE}/v1/sandbox/submission/77/status", json={"code": 200, "data": earlier})
    requests_mock.get(f"{BASE}/v1/sandbox/submission/77/results", json={"code": 200, "data": {"content": []}})
    result = ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert result.outputs["SID"] == "77"

    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([]))
    with pytest.raises(DemistoException, match="submitted before"):
        ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)


def test_sandbox_submit_errors(client, requests_mock, sandbox_env):
    with pytest.raises(DemistoException, match="entry_id"):
        ThreatMon.sandbox_submit_command({"polling": "true"}, client, RELIABILITY)
    requests_mock.post(f"{BASE}/v1/sandbox/submit", status_code=400, text='{"message":"too big"}')
    with pytest.raises(DemistoException, match="400"):
        ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert requests_mock.call_count == 1


def test_sandbox_list_and_result(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/sandbox/submissions", json=sandbox_list([{**SUBMISSION_ROW, "sid": "5", "overallRating": "Clean"}])
    )
    result = ThreatMon.sandbox_submission_list_command(client, {"limit": "5"})
    assert result.outputs[0]["SID"] == "5"
    requests_mock.get(
        f"{BASE}/v1/sandbox/submission/5/status", json={"code": 200, "data": {"sid": "5", "overallRating": "Clean"}}
    )
    requests_mock.get(
        f"{BASE}/v1/sandbox/submission/5/results",
        json={"code": 200, "data": {"content": [{"sha256": "b" * 64, "rating": "Clean"}, {"fileName": "no-hash"}]}},
    )
    result = ThreatMon.sandbox_result_get_command(client, {"sid": "5"}, RELIABILITY)
    assert len(result.indicators) == 1
    assert result.indicators[0].dbot_score.score == 1
    for bad in ({"sid": ""}, {"sid": "5", "limit": "500"}):
        with pytest.raises(DemistoException):
            ThreatMon.sandbox_result_get_command(client, bad, RELIABILITY)
    with pytest.raises(DemistoException):
        ThreatMon.sandbox_submission_list_command(client, {"limit": "500"})


def test_get_reliability():
    assert ThreatMon.get_reliability({}) == RELIABILITY
    with pytest.raises(DemistoException):
        ThreatMon.get_reliability({"integrationReliability": "Z"})


def test_customer_commands(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/customer",
        json={
            "totalRecords": 1,
            "data": [
                {"customerName": "Example Corp", "customerLicense": "TRIAL", "domain": "example.com", "keywordList": ["example"]}
            ],
        },
    )
    result = ThreatMon.customer_list_command(client, {"customer_name": "Example Corp"})
    assert result.outputs[0]["Keywords"] == ["example"]
    assert requests_mock.last_request.qs["customername"] == ["example corp"]

    requests_mock.post(f"{BASE}/v1/customer", status_code=200, text="")
    ThreatMon.customer_create_command(
        client,
        {
            "customer_name": "Example Corp",
            "license": "TRIAL",
            "customer_domain": "example.com",
            "keywords": "a,b",
            "contract_end_date": "2027-12-31T00:00:00Z",
        },
    )
    assert requests_mock.last_request.json() == {
        "customerName": "Example Corp",
        "customerLicense": "TRIAL",
        "domain": "example.com",
        "keywordList": ["a", "b"],
        "contractEndDate": "2027-12-31T00:00:00Z",
    }
    requests_mock.patch(f"{BASE}/v1/customer", text="")
    ThreatMon.customer_update_command(client, {"customer_name": "Example Corp", "customer_domain": "example.org"})
    assert requests_mock.last_request.json() == {"customerName": "Example Corp", "domain": "example.org"}
    requests_mock.delete(f"{BASE}/v1/customer", text="")
    ThreatMon.customer_delete_command(client, {"customer_name": "Example Corp"})
    assert requests_mock.last_request.qs["customername"] == ["example corp"]
    requests_mock.post(f"{BASE}/v1/customer/keyword", text="")
    requests_mock.delete(f"{BASE}/v1/customer/keyword", text="")
    added = ThreatMon.customer_keyword_command(client, {"customer_name": "Example Corp", "keyword": "x"}, add=True)
    assert "added to" in added.readable_output
    removed = ThreatMon.customer_keyword_command(client, {"customer_name": "Example Corp", "keyword": "x"}, add=False)
    assert "removed from" in removed.readable_output


@pytest.mark.parametrize(
    "args, message",
    [
        ({}, "customer_name"),
        ({"customer_name": "A", "license": "GOLD", "customer_domain": "a.com"}, "TRIAL or CUSTOMER"),
        ({"customer_name": "A", "license": "TRIAL"}, "required to create"),
    ],
)
def test_customer_create_validation(client, args, message):
    with pytest.raises(DemistoException, match=message):
        ThreatMon.customer_create_command(client, args)


def test_customer_errors(client, requests_mock):
    with pytest.raises(DemistoException, match="at least one"):
        ThreatMon.customer_update_command(client, {"customer_name": "A"})
    with pytest.raises(DemistoException):
        ThreatMon.customer_delete_command(client, {})
    with pytest.raises(DemistoException):
        ThreatMon.customer_keyword_command(client, {"customer_name": "A"}, add=True)
    requests_mock.post(
        f"{BASE}/v1/customer",
        status_code=500,
        json={"error": "Internal Server Error", "message": "401 UNAUTHORIZED Unauthorized: API key is not whitelisted."},
    )
    with pytest.raises(DemistoException, match="MSSP administrator account"):
        ThreatMon.customer_create_command(client, {"customer_name": "A", "license": "TRIAL", "customer_domain": "a.com"})
    requests_mock.get(f"{BASE}/v1/customer", status_code=403, text="")
    with pytest.raises(DemistoException, match="Nobody"):
        ThreatMon.customer_list_command(client, {"customer_name": "Nobody"})


def test_website_url_submit(client, requests_mock):
    requests_mock.post(
        f"{BASE}/v1/website/urls",
        json={
            "received": 1,
            "inserted": 0,
            "updated": 0,
            "failed": 1,
            "results": [{"url": "https://x.example/a", "status": "FAILED", "reason": "not an asset"}],
        },
    )
    result = ThreatMon.website_url_submit_command(client, {"urls": "https://x.example/a"})
    assert result.outputs[0]["Status"] == "FAILED"
    assert requests_mock.last_request.json() == {"urls": [{"url": "https://x.example/a"}]}
    with pytest.raises(DemistoException):
        ThreatMon.website_url_submit_command(client, {})
    with pytest.raises(DemistoException, match="1000"):
        ThreatMon.website_url_submit_command(client, {"urls": ",".join(f"https://x.example/{i}" for i in range(1001))})
    requests_mock.post(f"{BASE}/v1/website/urls", status_code=400, text='{"message":"bad"}')
    with pytest.raises(DemistoException, match="400"):
        ThreatMon.website_url_submit_command(client, {"urls": "https://x.example/a"})


def test_status_update_with_emails(client, server):
    args = {
        "alarm_ids": "5",
        "status": "Resolved",
        "assigned_email": "a@example.com",
        "info_email_list": "b@example.com,c@example.com",
    }
    update_alarm_status_command(client, args)
    assert server.patches[-1] == {
        "alarmIds": [5],
        "status": "Resolved",
        "assignedEmail": "a@example.com",
        "infoEmailList": ["b@example.com", "c@example.com"],
    }


def test_sandbox_submit_is_never_retried(client, requests_mock, sandbox_env):
    """A submission that may have reached ThreatMon is not sent again, even on a temporary error."""
    requests_mock.post(f"{BASE}/v1/sandbox/submit", status_code=503, text="unavailable")
    with pytest.raises(DemistoException, match="503"):
        ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert requests_mock.call_count == 1


# ---------------------------------------------------------------- second review regressions


def test_cursor_parts_never_skip_records_and_stop_on_repeats(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/cve/vulnerabilities",
        [
            {"json": {"data": [{"cve": "CVE-2026-1"}], "nextCursor": "same"}},
            {"json": {"data": [{"cve": "CVE-2026-2"}], "nextCursor": "same"}},
            {"json": {"data": [{"cve": "CVE-2026-3"}], "nextCursor": "same"}},
        ],
    )
    result = ThreatMon.cve_search_command(client, {"start_date": "2026-11-01", "limit": "10"})
    assert len(result.outputs["ThreatMon.CVE(val.cve && val.cve == obj.cve)"]) == 2
    assert result.outputs["ThreatMon.CVESearch"]["NextCursor"] is None
    requests_mock.get(f"{BASE}/v1/cve/vulnerabilities", json={"data": [], "nextCursor": "x"})
    assert ThreatMon.cve_search_command(client, {"start_date": "2026-11-01"}).outputs["ThreatMon.CVESearch"]["NextCursor"] is None


def test_cve_reputation_validation_and_reliability(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/cve/detail/CVE-2024-3400", json=CVE_DETAIL)
    result = ThreatMon.cve_reputation_command(client, {"cve": "CVE-2024-3400"}, "A - Completely reliable")[0]
    assert result.indicator.dbot_score.reliability == "A - Completely reliable"
    with pytest.raises(DemistoException, match="not a valid CVE ID"):
        ThreatMon.cve_reputation_command(client, {"cve": "CVE-2024/../x"}, RELIABILITY)
    requests_mock.get(f"{BASE}/v1/cve/detail/CVE-2024-9999", status_code=404, text="")
    unknown = ThreatMon.cve_reputation_command(client, {"cve": "CVE-2024-9999"}, RELIABILITY)[0]
    assert unknown.indicator.dbot_score.score == 0


def test_permanent_server_errors_are_not_retried(client, requests_mock):
    requests_mock.get(f"{BASE}/v1/customer", status_code=500, json={"message": "Unauthorized: API key is not whitelisted."})
    with pytest.raises(DemistoException, match="enable the feature"):
        ThreatMon.customer_list_command(client, {})
    assert requests_mock.call_count == 1


def test_sandbox_success_false_is_an_error(client, requests_mock, sandbox_env):
    requests_mock.post(f"{BASE}/v1/sandbox/submit", json={"code": 200, "data": {"success": False, "message": "Quota exceeded"}})
    with pytest.raises(DemistoException, match="Quota exceeded"):
        ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)


def test_sandbox_matches_temporary_sid_before_name(client, requests_mock, sandbox_env):
    """Two files with the same name: the row with the temporary ID of this submission is followed."""
    requests_mock.post(f"{BASE}/v1/sandbox/submit", json={"code": 200, "data": {"success": True, "sid": "uuid-mine"}})
    other = {**SUBMISSION_ROW, "id": 301, "sid": "uuid-other"}
    mine = {**SUBMISSION_ROW, "id": 300, "sid": "uuid-mine"}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([other, mine]))
    result = ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert result.scheduled_command._args["submission_id"] == "300"
    assert result.scheduled_command._args["file_size"] == "8"


def test_sandbox_skips_rows_with_another_size(client, requests_mock, sandbox_env):
    requests_mock.post(f"{BASE}/v1/sandbox/submit", json={"code": 200, "data": {"success": True}})
    other = {**SUBMISSION_ROW, "id": 301, "fileSize": 999}
    mine = {**SUBMISSION_ROW, "id": 300, "fileSize": 8}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([other, mine]))
    result = ThreatMon.sandbox_submit_command({"entry_id": "1@1", "polling": "true"}, client, RELIABILITY)
    assert result.scheduled_command._args["submission_id"] == "300"


def test_sandbox_ends_without_verdict(client, requests_mock, sandbox_env):
    args = {"polling": "true", "submitted_at": "1", "file_name": "sample.txt", "submission_id": "260"}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([{**SUBMISSION_ROW, "sid": "55", "status": 2}]))
    result = ThreatMon.sandbox_submit_command(args, client, RELIABILITY)
    assert result.scheduled_command is None
    assert "without a verdict" in result.readable_output


def test_sandbox_follows_submission_outside_newest_rows(client, requests_mock, sandbox_env):
    args = {"polling": "true", "submitted_at": "1", "file_name": "sample.txt", "submission_id": "260", "sid": "55"}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([]))
    done = {**SUBMISSION_ROW, "sid": "55", "status": 2, "overallRating": "Clean"}
    requests_mock.get(f"{BASE}/v1/sandbox/submission/55/status", json={"code": 200, "data": done})
    requests_mock.get(f"{BASE}/v1/sandbox/submission/55/results", json={"code": 200, "data": {"content": []}})
    result = ThreatMon.sandbox_submit_command(args, client, RELIABILITY)
    assert result.outputs["OverallRating"] == "Clean"
    assert result.outputs["ID"] == 260


def test_fetch_stops_at_deadline_instead_of_dropping_screenshots(client, server, mocker, files):
    for code in (80, 81):
        alarm = make_alarm(code, datetime(2026, 11, 9, 1, code - 79, tzinfo=UTC))
        alarm["details"] = [{"findingId": code, "Screenshot": f"FILE-SHARE/{code}.png"}]
        server.put(alarm)
    clock = {"now": 0.0}

    def slow_screenshot(blob_name):
        clock["now"] = 1000.0  # The first download uses up the rest of the run.
        return b"png"

    mocker.patch.object(client, "get_screenshot", side_effect=slow_screenshot)
    mocker.patch.object(ThreatMon.time, "time", side_effect=lambda: clock["now"])
    incidents, state = fetch_incidents(client, PARAMS, {}, deadline=500.0)
    assert codes(incidents) == [80]
    assert incidents[0]["attachment"]
    assert state["resume"]["code"] == 80


def test_recipients_with_odd_values(client, requests_mock):
    requests_mock.get(
        f"{BASE}/v1/cve/subscriptions",
        json={"data": [{"vendor": "a", "recipients": [{"email": None}, "plain@example.com"]}], "nextCursor": None},
    )
    assert "plain@example.com" in ThreatMon.cve_subscription_list_command(client, {}).readable_output


def test_empty_json_bodies(client, requests_mock):
    requests_mock.post(f"{BASE}/v1/website/urls", status_code=201, text="")
    assert ThreatMon.website_url_submit_command(client, {"urls": "https://x.example/a"}).outputs == []
    requests_mock.get(f"{BASE}/v1/customer", text="")
    assert ThreatMon.customer_list_command(client, {}).outputs == []
    requests_mock.get(f"{BASE}/v1/cve/detail/CVE-2024-0001", text="[]")
    assert ThreatMon.cve_get_command(client, {"cve_id": "CVE-2024-0001"}).readable_output.startswith("ThreatMon has no")


@pytest.mark.parametrize("status", [5, 1])
def test_sandbox_keeps_polling_while_queued_or_running(client, requests_mock, sandbox_env, status):
    args = {"polling": "true", "submitted_at": "1", "file_name": "sample.txt", "submission_id": "260"}
    requests_mock.get(f"{BASE}/v1/sandbox/submissions", json=sandbox_list([{**SUBMISSION_ROW, "status": status}]))
    assert ThreatMon.sandbox_submit_command(args, client, RELIABILITY).scheduled_command is not None
