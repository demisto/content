import json
from datetime import datetime

import pytest
from freezegun import freeze_time
from ProofpointTAP_v2 import ALL_EVENTS, ISSUES_EVENTS, Client, fetch_incidents, get_events_command

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MOCK_URL = "http://123-fake-api.com"
MOCK_DELIVERED_MESSAGE = {
    "GUID": "1111",
    "QID": "r2FNwRHF004109",
    "ccAddresses": ["bruce.wayne@university-of-education.zz"],
    "clusterId": "pharmtech_hosted",
    "fromAddress": "badguy@evil.zz",
    "headerCC": '"Bruce Wayne" <bruce.wayne@university-of-education.zz>',
    "headerFrom": '"A. Badguy" <badguy@evil.zz>',
    "headerReplyTo": None,
    "headerTo": '"Clark Kent" <clark.kent@pharmtech.zz>; "Diana Prince" <diana.prince@pharmtech.zz>',
    "impostorScore": 0,
    "malwareScore": 100,
    "messageID": "1111@evil.zz",
    "threatsInfoMap": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "threat_num",
            "threatId": "threat_num",
            "threatStatus": "active",
            "threatTime": "2010-01-30T00:00:40.000Z",
            "threatType": "ATTACHMENT",
            "threatUrl": "https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
        },
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "badsite.zz",
            "threatId": "3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
            "threatTime": "2010-01-30T00:00:30.000Z",
            "threatType": "URL",
            "threatUrl": "https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
        },
    ],
    "messageTime": "2010-01-30T00:00:59.000Z",
    "modulesRun": ["pdr", "sandbox", "spam", "urldefense"],
    "phishScore": 46,
    "policyRoutes": ["default_inbound", "executives"],
    "quarantineFolder": "Attachment Defense",
    "quarantineRule": "module.sandbox.threat",
    "recipient": ["clark.kent@pharmtech.zz", "diana.prince@pharmtech.zz"],
    "replyToAddress": None,
    "sender": "e99d7ed5580193f36a51f597bc2c0210@evil.zz",
    "senderIP": "192.0.2.255",
    "spamScore": 4,
    "subject": "Please find a totally safe invoice attached.",
    "toAddresses": "xx@xxx.com",
    "xmailer": None,
}

MOCK_BLOCKED_MESSAGE = {
    "GUID": "2222",
    "QID": "r2FNwRHF004109",
    "ccAddresses": ["bruce.wayne@university-of-education.zz"],
    "clusterId": "pharmtech_hosted",
    "fromAddress": "badguy@evil.zz",
    "headerCC": '"Bruce Wayne" <bruce.wayne@university-of-education.zz>',
    "headerFrom": '"A. Badguy" <badguy@evil.zz>',
    "headerReplyTo": None,
    "headerTo": '"Clark Kent" <clark.kent@pharmtech.zz>; "Diana Prince" <diana.prince@pharmtech.zz>',
    "impostorScore": 0,
    "malwareScore": 100,
    "messageID": "2222@evil.zz",
    "threatsInfoMap": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "threat_num",
            "threatId": "threat_num",
            "threatStatus": "active",
            "threatTime": "2010-01-25T00:00:40.000Z",
            "threatType": "ATTACHMENT",
            "threatUrl": "https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
        },
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "badsite.zz",
            "threatId": "3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
            "threatTime": "2010-01-25T00:00:30.000Z",
            "threatType": "URL",
            "threatUrl": "https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
        },
    ],
    "messageTime": "2010-01-25T00:00:10.000Z",
    "modulesRun": ["pdr", "sandbox", "spam", "urldefense"],
    "phishScore": 46,
    "policyRoutes": ["default_inbound", "executives"],
    "quarantineFolder": "Attachment Defense",
    "quarantineRule": "module.sandbox.threat",
    "recipient": ["clark.kent@pharmtech.zz", "diana.prince@pharmtech.zz"],
    "replyToAddress": None,
    "sender": "e99d7ed5580193f36a51f597bc2c0210@evil.zz",
    "senderIP": "192.0.2.255",
    "spamScore": 4,
    "subject": "Please find a totally safe invoice attached.",
    "toAddresses": "xx@xxx.com",
    "xmailer": None,
}

MOCK_PERMITTED_CLICK = {
    "id": "click-permitted-1",
    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
    "classification": "MALWARE",
    "clickIP": "192.0.2.1",
    "clickTime": "2010-01-11T00:00:20.000Z",
    "messageID": "3333",
    "recipient": "bruce.wayne@pharmtech.zz",
    "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
    "senderIP": "192.0.2.255",
    "threatID": "threat_num2",
    "threatTime": "2010-01-11T00:00:10.000Z",
    "threatURL": "https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
    "url": "http://badguy.zz/",
    "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0",
}

MOCK_BLOCKED_CLICK = {
    "id": "click-blocked-1",
    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
    "classification": "MALWARE",
    "clickIP": "192.0.2.2",
    "clickTime": "2010-01-22T00:00:10.000Z",
    "messageID": "4444",
    "recipient": "bruce.wayne@pharmtech.zz",
    "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
    "senderIP": "192.0.2.255",
    "threatID": "threat_num2",
    "threatTime": "2010-01-22T00:00:20.000Z",
    "threatURL": "https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
    "url": "http://badguy.zz/",
    "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0",
}

MOCK_ISSUES = {"messagesDelivered": [MOCK_DELIVERED_MESSAGE], "clicksPermitted": [MOCK_PERMITTED_CLICK]}

MOCK_ALL_EVENTS = {
    "messagesDelivered": [MOCK_DELIVERED_MESSAGE],
    "clicksPermitted": [MOCK_PERMITTED_CLICK],
    "clicksBlocked": [MOCK_BLOCKED_CLICK],
    "messagesBlocked": [MOCK_BLOCKED_MESSAGE],
}

# Additional "new event" mocks for the look-back + dedup tests.
# These are derived from the existing mocks above by copying them and overriding
# only the dedup-key field (GUID for messages, id for clicks). They represent
# genuinely new events that should NOT collide with the previously-seen IDs.
MOCK_NEW_DELIVERED_MESSAGE = {**MOCK_DELIVERED_MESSAGE, "GUID": "9999", "messageID": "9999@evil.zz"}
MOCK_NEW_BLOCKED_CLICK = {**MOCK_BLOCKED_CLICK, "id": "click-blocked-NEW"}


def get_mocked_time():
    return datetime.strptime("2010-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ")


def test_command(requests_mock):
    requests_mock.get(
        MOCK_URL + "/v2/siem/issues?format=json&sinceSeconds=100&threatType=url&threatType=attachment", json=MOCK_ISSUES
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    args = {"threatType": "url,attachment", "sinceSeconds": "100", "eventTypes": ISSUES_EVENTS}
    _, outputs, _ = get_events_command(client, args)

    assert len(outputs["Proofpoint.MessagesDelivered(val.GUID == obj.GUID)"]) == 1
    assert len(outputs["Proofpoint.ClicksPermitted(val.GUID == obj.GUID)"]) == 1


def return_self(return_date):
    return return_date


@freeze_time("2010-01-01T00:00:00Z", tz_offset=0)
def test_first_fetch_incidents(requests_mock, mocker):
    requests_mock.get(
        MOCK_URL + "/v2/siem/all?format=json&interval=2009-12-31T23%3A30%3A00Z%2F2010-01-01T00%3A00%3A00Z", json=MOCK_ALL_EVENTS
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    next_run, incidents, _ = fetch_incidents(
        client=client, last_run={}, first_fetch_time="30 minutes", event_type_filter=ALL_EVENTS, threat_status="", threat_type=""
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]["rawJSON"])["messageID"] == "4444"


def test_next_fetch(requests_mock, mocker):
    # Use 31 minutes to ensure interval is >= 30 seconds
    current_date = "2010-01-01T00:31:00Z"
    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_date, "%Y-%m-%dT%H:%M:%SZ"))

    requests_mock.get(
        MOCK_URL + "/v2/siem/all?format=json&interval=2010-01-01T00%3A00%3A00Z%"
        "2F2010-01-01T00%3A31%3A00Z&threatStatus=active&threatStatus=cleared",
        json=MOCK_ALL_EVENTS,
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": "2010-01-01T00:00:00Z"},
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status=["active", "cleared"],
        threat_type="",
        limit=50,
        look_back_minutes=0,
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]["rawJSON"])["messageID"] == "4444"


def test_fetch_limit(requests_mock, mocker):
    # Use 31 minutes to ensure interval is >= 30 seconds
    current_date = "2010-01-01T00:31:00Z"
    this_run = {"last_fetch": "2010-01-01T00:00:00Z"}
    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_date, "%Y-%m-%dT%H:%M:%SZ"))
    requests_mock.get(MOCK_URL + "/v2/siem/all", json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    next_run, incidents, remained = fetch_incidents(
        client=client,
        last_run=this_run,
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status=["active", "cleared"],
        threat_type="",
        limit=3,
        look_back_minutes=0,
    )

    assert next_run["last_fetch"] == "2010-01-01T00:31:00Z"
    assert len(incidents) == 3
    assert len(remained) == 1
    # test another run
    next_run, incidents, remained = fetch_incidents(
        client=client,
        last_run=this_run,
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status=["active", "cleared"],
        threat_type="",
        limit=3,
        integration_context={"incidents": remained},
        look_back_minutes=0,
    )
    assert next_run["last_fetch"] == "2010-01-01T00:00:00Z"
    assert len(incidents) == 1
    assert not remained


@freeze_time("2010-01-01T00:01:00Z", tz_offset=0)
def test_fetch_incidents_with_encoding(requests_mock, mocker):
    """
    Given:
        - Message with latin chars in its subject
        - Raw JSON encoding param set to latin-1

    When:
        - Running fetch incidents

    Then:
        - Ensure subject is returned properly in the raw JSON
    """
    # Mock time to be 1 minute after the parsed time to ensure >= 30 second interval
    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime("2010-01-01T00:01:00Z", "%Y-%m-%dT%H:%M:%SZ"))
    mocker.patch("ProofpointTAP_v2.parse_date_range", return_value=("2010-01-01T00:00:00Z", "never mind"))
    requests_mock.get(
        MOCK_URL + "/v2/siem/all?format=json&interval=2010-01-01T00%3A00%3A00Z%2F2010-01-01T00%3A01%3A00Z",
        json={
            "messagesDelivered": [
                {
                    "subject": "p\u00c3\u00a9rdida",
                    "messageTime": "2010-01-30T00:00:59.000Z",
                },
            ],
        },
    )

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None,
    )

    _, incidents, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="now",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        raw_json_encoding="latin-1",
        look_back_minutes=0,
    )

    assert json.loads(incidents[0]["rawJSON"])["subject"] == "pérdida"


# Test data: (last_fetch, current_time, expected_interval_count)
# Old format returned list of timestamps, new format returns list of (start, end) tuples
FETCH_TIMES_MOCK = [
    ("2010-01-01T00:00:00Z", "2010-01-01T03:00:00Z", 4),  # 3 hours = 3 intervals of 59min + 1 final interval
    ("2010-01-01T00:00:00Z", "2010-01-01T00:03:00Z", 1),  # 3 minutes = 1 interval
]


@pytest.mark.parametrize("mock_past, mock_now, expected", FETCH_TIMES_MOCK)
def test_get_fetch_times(mocker, mock_past, mock_now, expected):
    from ProofpointTAP_v2 import get_fetch_times

    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(mock_now, "%Y-%m-%dT%H:%M:%SZ"))
    intervals = get_fetch_times(mock_past)
    assert len(intervals) == expected
    # Verify all intervals are tuples of (start, end)
    for interval in intervals:
        assert isinstance(interval, tuple)
        assert len(interval) == 2
        start, end = interval
        assert isinstance(start, str)
        assert isinstance(end, str)


def test_fetch_with_look_back_buffer(requests_mock, mocker):
    """
    Scenario: Fetch incidents with look-back buffer to account for Proofpoint API indexing delay.
    Given:
     - User has configured look_back_minutes=2 to prevent missing events
     - Last fetch was at 2010-01-01T00:00:00Z
     - Current time is 2010-01-01T00:05:00Z
    When:
     - fetch_incidents is called with look_back_minutes=2
    Then:
     - Ensure the fetch start is shifted back by 2 minutes to 2009-12-31T23:58:00Z
     - Ensure the fetch end is current time 2010-01-01T00:05:00Z
     - Ensure incidents are fetched correctly
     - Ensure next_run checkpoint is set to the end of the last interval (now)
    """
    from ProofpointTAP_v2 import fetch_incidents

    last_fetch_time = "2010-01-01T00:00:00Z"
    current_time = "2010-01-01T00:05:00Z"
    # With 2-minute look-back, effective start shifts back: 00:00:00 - 2min = 23:58:00 previous day
    expected_start_time = "2009-12-31T23:58:00Z"
    # End time is now
    expected_end_time = current_time

    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%SZ"))

    # Mock API call with the expected look-back interval (single interval since < 59 minutes)
    start_encoded = expected_start_time.replace(":", "%3A")
    end_encoded = expected_end_time.replace(":", "%3A")
    requests_mock.get(
        MOCK_URL + f"/v2/siem/all?format=json&interval={start_encoded}%2F{end_encoded}",
        json=MOCK_ALL_EVENTS,
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": last_fetch_time},
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        limit=50,
        look_back_minutes=2,
    )

    # Verify incidents were fetched
    assert len(incidents) == 4
    # Verify checkpoint is set to the end of the last interval (current time)
    assert next_run["last_fetch"] == expected_end_time


# ---------------------------------------------------------------------------
# Look-back + Deduplication tests
# ---------------------------------------------------------------------------
# The integration tracks already-seen events in `last_run["seen_ids"]` as a
# dict {dedup_key: interval_end_str}. Dedup keys per event type:
#   - messagesDelivered -> "GUID"
#   - messagesBlocked   -> "GUID"
#   - clicksPermitted   -> "id"
#   - clicksBlocked     -> "id"
# ---------------------------------------------------------------------------


def test_dedup_filters_already_seen_incidents_in_lookback_window(requests_mock, mocker):
    """
    Given:
     - last_run.seen_ids contains all four event IDs from a previous fetch,
       and look_back_minutes=2 so the previous window is rescanned.
     - The API returns the exact same events again because of the overlap.
    When:
     - fetch_incidents is called.
    Then:
     - All already-seen events are filtered; zero incidents are produced.
     - The seen_ids dedup state is preserved (not lost) in next_run.
     - last_fetch advances to the end of the last fetched interval.
    """
    last_fetch_time = "2010-01-01T00:00:00Z"
    current_time = "2010-01-01T00:01:00Z"
    interval_end_seen = "2010-01-01T00:00:00Z"

    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%SZ"))

    # API returns the same events that were already fetched previously.
    requests_mock.get(MOCK_URL + "/v2/siem/all", json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    # Previously-seen IDs (mapped to the interval end in which they were first seen,
    # which must be within the lookback window so they are not pruned).
    seen_ids = {
        MOCK_DELIVERED_MESSAGE["GUID"]: interval_end_seen,
        MOCK_BLOCKED_MESSAGE["GUID"]: interval_end_seen,
        MOCK_PERMITTED_CLICK["id"]: interval_end_seen,
        MOCK_BLOCKED_CLICK["id"]: interval_end_seen,
    }

    next_run, incidents, remained = fetch_incidents(
        client=client,
        last_run={"last_fetch": last_fetch_time, "seen_ids": dict(seen_ids)},
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        limit=50,
        look_back_minutes=2,
    )

    # All four events were already seen -> filtered out
    assert incidents == []
    assert remained == []
    # Dedup state is retained in next_run (not lost) — all 4 previously-seen IDs still present
    assert set(next_run["seen_ids"].keys()) == set(seen_ids.keys())
    # last_fetch advances to the end of the last fetched interval (= current time)
    assert next_run["last_fetch"] == current_time


def test_dedup_includes_new_events_within_lookback_window(requests_mock, mocker):
    """
    Given:
     - last_run.seen_ids contains IDs of a delivered message and a blocked click
       from a previous fetch.
     - The API returns a mix of those previously-seen events AND new events
       (MOCK_NEW_DELIVERED_MESSAGE, MOCK_NEW_BLOCKED_CLICK) within the
       overlapped lookback window.
     - look_back_minutes=2.
    When:
     - fetch_incidents is called.
    Then:
     - Only the new (unseen) events become incidents.
     - next_run.seen_ids contains both the previously-seen IDs (still in window)
       AND the new IDs from this fetch.
    """
    last_fetch_time = "2010-01-01T00:00:00Z"
    current_time = "2010-01-01T00:05:00Z"
    interval_end_seen = "2010-01-01T00:00:00Z"

    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%SZ"))

    api_response = {
        "messagesDelivered": [MOCK_DELIVERED_MESSAGE, MOCK_NEW_DELIVERED_MESSAGE],
        "messagesBlocked": [],
        "clicksPermitted": [],
        "clicksBlocked": [MOCK_BLOCKED_CLICK, MOCK_NEW_BLOCKED_CLICK],
    }
    requests_mock.get(MOCK_URL + "/v2/siem/all", json=api_response)

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    previously_seen = {
        MOCK_DELIVERED_MESSAGE["GUID"]: interval_end_seen,
        MOCK_BLOCKED_CLICK["id"]: interval_end_seen,
    }

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": last_fetch_time, "seen_ids": dict(previously_seen)},
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        limit=50,
        look_back_minutes=2,
    )

    # Only the two new events become incidents
    assert len(incidents) == 2
    raw_jsons = [json.loads(inc["rawJSON"]) for inc in incidents]
    fetched_dedup_keys = {raw.get("GUID") or raw.get("id") for raw in raw_jsons}
    assert fetched_dedup_keys == {MOCK_NEW_DELIVERED_MESSAGE["GUID"], MOCK_NEW_BLOCKED_CLICK["id"]}

    # next_run.seen_ids contains BOTH old (still within window) and new IDs
    final_ids = set(next_run["seen_ids"].keys())
    assert MOCK_DELIVERED_MESSAGE["GUID"] in final_ids  # old, retained
    assert MOCK_BLOCKED_CLICK["id"] in final_ids  # old, retained
    assert MOCK_NEW_DELIVERED_MESSAGE["GUID"] in final_ids  # new
    assert MOCK_NEW_BLOCKED_CLICK["id"] in final_ids  # new


def test_lookback_zero_no_dedup_filtering(requests_mock, mocker):
    """
    Given:
     - look_back_minutes=0 (default behavior, no lookback).
     - last_run carries a stale seen_ids entry that does not collide with the
       new events from the API.
     - The API returns brand-new events in a non-overlapping window.
    When:
     - fetch_incidents is called.
    Then:
     - All events from the API window become incidents (no dedup-driven drops).
     - The seen_ids in next_run is NOT pruned (pruning only happens when
       look_back_minutes > 0), so the pre-existing stale ID is preserved
       alongside the new IDs.
    """
    last_fetch_time = "2010-01-01T00:00:00Z"
    current_time = "2010-01-01T00:31:00Z"

    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%SZ"))

    requests_mock.get(MOCK_URL + "/v2/siem/all", json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    # A stale dedup ID that is far older than any look-back window.
    pre_existing_seen = {"ancient-id": "2000-01-01T00:00:00Z"}

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": last_fetch_time, "seen_ids": dict(pre_existing_seen)},
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        limit=50,
        look_back_minutes=0,
    )

    # All 4 events appear: no dedup overlap because the pre-existing seen ID
    # doesn't collide with the new event dedup keys.
    assert len(incidents) == 4

    # With look_back_minutes=0 the integration does NOT call prune_seen_ids,
    # so the ancient ID survives along with the freshly-tracked new IDs.
    final_ids = set(next_run["seen_ids"].keys())
    assert "ancient-id" in final_ids
    assert MOCK_DELIVERED_MESSAGE["GUID"] in final_ids
    assert MOCK_BLOCKED_MESSAGE["GUID"] in final_ids
    assert MOCK_PERMITTED_CLICK["id"] in final_ids
    assert MOCK_BLOCKED_CLICK["id"] in final_ids


def test_lookback_dedup_state_pruning(requests_mock, mocker):
    """
    Given:
     - last_run.seen_ids contains a mix of IDs:
         * one mapped to an interval_end well outside the lookback window
           (must be pruned),
         * one mapped to an interval_end inside the lookback window
           (must be kept).
     - look_back_minutes=5  ->  prune cutoff = now - (5 + 30) min.
    When:
     - fetch_incidents is called.
    Then:
     - The stale ID is removed from next_run.seen_ids.
     - The in-window ID is preserved.
    """
    last_fetch_time = "2010-01-01T00:55:00Z"
    current_time = "2010-01-01T01:00:00Z"

    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%SZ"))

    # Empty API response so we focus purely on pruning behavior.
    requests_mock.get(
        MOCK_URL + "/v2/siem/all",
        json={"messagesDelivered": [], "messagesBlocked": [], "clicksPermitted": [], "clicksBlocked": []},
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    # Cutoff for look_back_minutes=5 is now - 35min = 2010-01-01T00:25:00Z.
    seen_ids = {
        "stale-id": "2009-12-31T00:00:00Z",  # way before cutoff -> pruned
        "fresh-id": "2010-01-01T00:55:00Z",  # after cutoff -> kept
    }

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": last_fetch_time, "seen_ids": dict(seen_ids)},
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        limit=50,
        look_back_minutes=5,
    )

    assert incidents == []
    assert "stale-id" not in next_run["seen_ids"]
    assert "fresh-id" in next_run["seen_ids"]


def test_lookback_first_fetch_initializes_dedup_state(requests_mock, mocker):
    """
    Given:
     - First fetch (last_run = {}) with look_back_minutes=2.
     - The API returns the standard set of all four events.
    When:
     - fetch_incidents is called.
    Then:
     - The seen_ids dedup state is initialized in next_run with the dedup
       keys of every fetched incident (GUIDs for messages, ids for clicks).
     - All events become incidents and last_fetch is populated.
    """
    current_time = "2010-01-01T00:05:00Z"
    mocker.patch("ProofpointTAP_v2.get_now", return_value=datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%SZ"))
    # parse_date_range returns the first_fetch start time for a clean first-fetch flow.
    mocker.patch("ProofpointTAP_v2.parse_date_range", return_value=("2010-01-01T00:00:00Z", "never mind"))

    requests_mock.get(MOCK_URL + "/v2/siem/all", json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={},  # first fetch
        first_fetch_time="30 minutes",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type="",
        limit=50,
        look_back_minutes=2,
    )

    # All 4 events become incidents on first fetch
    assert len(incidents) == 4

    # seen_ids is initialized and contains all 4 dedup keys
    assert "seen_ids" in next_run
    expected_ids = {
        MOCK_DELIVERED_MESSAGE["GUID"],
        MOCK_BLOCKED_MESSAGE["GUID"],
        MOCK_PERMITTED_CLICK["id"],
        MOCK_BLOCKED_CLICK["id"],
    }
    assert set(next_run["seen_ids"].keys()) == expected_ids
    # last_fetch checkpoint is populated (end of last interval = current time)
    assert next_run["last_fetch"] == current_time


class TestGetForensics:
    PLATFORMS_OBJECT = [
        {
            "name": "windows 7 sp1",
            "os": "windows 7",
            "version": "4.5.661",
        }
    ]
    EVIDENCE_OBJECT_URL = {
        "type": "url",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "url": "string",
            "blacklisted": "boolean",
            "ip": "string",
            "httpStatus": "string",
            "md5": "string",
            "offset": "integer",
            "rule": "string",
            "sha256": "string",
            "size": "integer",
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_REGISTRY = {
        "type": "registry",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "key": "string",
            "name": "string",
            "rule": "string",
            "value": "string",
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_PROCESS = {
        "type": "process",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "path": "string",
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_NETWORK = {
        "type": "network",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "ip": "string",
            "port": "string",
            "type": "string",
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_MUTEX = {
        "type": "mutex",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "name": "string",
            "path": "string",
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_IDS = {
        "type": "ids",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "name": "string",
            "signatureId": "integer",
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_FILE = {
        "type": "file",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {"action": "string", "md5": "string", "path": "string", "rule": "string", "sha256": "string", "size": "integer"},
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_DROPPER = {
        "type": "dropper",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {"path": "string", "rule": "string", "url": "string"},
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_DNS = {
        "type": "dns",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "host": "string",
            "cnames": ["string1", "string2"],
            "ips": ["string1", "string2"],
            "nameservers": ["string1", "string2"],
            "nameserversList": ["string1", "string2"],
        },
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_COOKIE = {
        "type": "cookie",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {"action": "string", "domain": "string", "key": "string", "value": "string"},
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_OBJECT_ATTACHMENT = {
        "type": "attachment",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {"sha256": "string", "md5": "string", "offset": "integer", "rule": "string", "size": "integer"},
        "platforms": PLATFORMS_OBJECT,
    }
    EVIDENCE_LIST = [
        EVIDENCE_OBJECT_ATTACHMENT,
        EVIDENCE_OBJECT_COOKIE,
        EVIDENCE_OBJECT_DNS,
        EVIDENCE_OBJECT_DROPPER,
        EVIDENCE_OBJECT_FILE,
        EVIDENCE_OBJECT_IDS,
        EVIDENCE_OBJECT_MUTEX,
        EVIDENCE_OBJECT_NETWORK,
        EVIDENCE_OBJECT_PROCESS,
        EVIDENCE_OBJECT_REGISTRY,
        EVIDENCE_OBJECT_URL,
    ]
    REPORT_OBJECT = [
        {
            "name": "string",
            "scope": "string",
            "type": "string",
            "id": "string",
            "forensics": EVIDENCE_LIST,
        }
    ]

    REPORT = {
        "generated": "string",
        "reports": REPORT_OBJECT * 2,
    }

    FORENSICS_REPORT = {
        "Scope": "string",
        "Type": "string",
        "ID": "string",
        "Attachment": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "SHA256": "string",
                "MD5": "string",
                "Offset": "integer",
                "Size": "integer",
            }
        ],
        "Cookie": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Action": "string",
                "Domain": "string",
                "Key": "string",
                "Value": "string",
            }
        ],
        "DNS": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Host": "string",
                "CNames": ["string1", "string2"],
                "IP": ["string1", "string2"],
                "NameServers": ["string1", "string2"],
                "NameServersList": ["string1", "string2"],
            }
        ],
        "Dropper": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Path": "string",
                "URL": "string",
                "Rule": "string",
            }
        ],
        "File": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Path": "string",
                "Action": "string",
                "SHA256": "string",
                "MD5": "string",
                "Size": "integer",
            }
        ],
        "IDS": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Name": "string",
                "SignatureID": "integer",
            }
        ],
        "Mutex": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Name": "string",
                "Path": "string",
            }
        ],
        "Network": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Action": "string",
                "IP": "string",
                "Port": "string",
                "Protocol": "string",
            }
        ],
        "Process": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Action": "string",
                "Path": "string",
            }
        ],
        "Registry": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "Name": "string",
                "Action": "string",
                "Key": "string",
                "Value": "string",
            }
        ],
        "URL": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [{"Name": "windows 7 sp1", "OS": "windows 7", "Version": "4.5.661"}],
                "URL": "string",
                "Blacklisted": "boolean",
                "SHA256": "string",
                "MD5": "string",
                "Size": "integer",
                "HTTPStatus": "string",
                "IP": "string",
            }
        ],
    }

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )

    def test_get_forensics(self, requests_mock):
        from ProofpointTAP_v2 import get_forensic_command

        requests_mock.get("http://123-fake-api.com/v2/forensics?threatId=1256", json=self.REPORT)
        _, output, _ = get_forensic_command(self.client, {"threatId": "1256"})
        reports = output["Proofpoint.Report(var.ID === obj.ID)"]
        assert len(reports) == 2
        report = reports[0]
        assert all(report)
        assert report == self.FORENSICS_REPORT


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f"test_data/{file_name}", encoding="utf-8") as mock_file:
        return mock_file.read()


def test_get_clicks_command(requests_mock):
    """
    Scenario: Retrieves clicks to malicious URLs blocked and permitted in the specified time period.
    Given:
     - User has provided valid credentials and arguments.
    When:
     - A get-clicks command is called and there is clicks in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_clicks_command

    requests_mock.get(
        f"{MOCK_URL}/v2/siem/clicks/blocked", json={"queryEndTime": "2021-03-23T14:00:00Z", "clicksBlocked": [MOCK_BLOCKED_CLICK]}
    )
    requests_mock.get(
        f"{MOCK_URL}/v2/siem/clicks/permitted",
        json={"queryEndTime": "2021-03-23T14:00:00Z", "clicksPermitted": [MOCK_PERMITTED_CLICK]},
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    blocked_result = get_clicks_command(client, True, "3 days")
    permitted_result = get_clicks_command(client, False, "3 days")
    assert len(blocked_result.outputs) == 1
    assert blocked_result.outputs_prefix == "Proofpoint.ClicksBlocked"
    assert blocked_result.outputs[0].get("messageID") == "4444"
    assert len(permitted_result.outputs) == 1
    assert permitted_result.outputs_prefix == "Proofpoint.ClicksPermitted"
    assert permitted_result.outputs[0].get("messageID") == "3333"


def test_get_messages_command(requests_mock):
    """
    Scenario: Retrieves messages to malicious URLs blocked and delivered in the specified time period.
    Given:
     - User has provided valid credentials and arguments.
    When:
     - A get-messages command is called and there is messages in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_messages_command

    requests_mock.get(
        f"{MOCK_URL}/v2/siem/messages/blocked",
        json={"queryEndTime": "2021-03-23T14:00:00Z", "messagesBlocked": [MOCK_BLOCKED_MESSAGE]},
    )
    requests_mock.get(
        f"{MOCK_URL}/v2/siem/messages/delivered",
        json={"queryEndTime": "2021-03-23T14:00:00Z", "messagesDelivered": [MOCK_DELIVERED_MESSAGE]},
    )

    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    blocked_result = get_messages_command(client, True, "3 days")
    delivered_result = get_messages_command(client, False, "3 days")
    assert len(blocked_result.outputs) == 1
    assert blocked_result.outputs_prefix == "Proofpoint.MessagesBlocked"
    assert blocked_result.outputs[0].get("messageID") == "2222@evil.zz"
    assert len(delivered_result.outputs) == 1
    assert delivered_result.outputs_prefix == "Proofpoint.MessagesDelivered"
    assert delivered_result.outputs[0].get("messageID") == "1111@evil.zz"


def test_list_campaigns_command(requests_mock):
    """
    Scenario: Retrieves a list of IDs of campaigns active in a time window.
    Given:
     - User has provided valid credentials.
    When:
     - A list-campaign-ids command is called and there is campaigns in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, list_campaigns_command

    mock_response = json.loads(load_mock_response("campaigns.json"))
    requests_mock.get(f"{MOCK_URL}/v2/campaign/ids", json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    result = list_campaigns_command(client, "3 days")
    assert len(result.outputs) == 2
    assert result.outputs_prefix == "Proofpoint.Campaign"
    assert result.outputs[0].get("id") == "f3ff0874-85ef-475e-b3fe-d05f97b2ed3f"
    assert result.outputs[0].get("lastUpdatedAt") == "2021-03-25T10:37:46.000Z"


def test_get_campaign(requests_mock):
    """
    Scenario: Retrieves information for a given campaign.
    Given:
     - User has provided valid credentials and argument.
    When:
     - A get-campaign command is called and there is a campaign in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_campaign_command

    mock_response = json.loads(load_mock_response("campaign_information.json"))
    requests_mock.get(f"{MOCK_URL}/v2/campaign/1", json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    result = get_campaign_command(client, "1")
    assert len(result.outputs) == 7
    assert result.outputs_prefix == "Proofpoint.Campaign"
    assert result.outputs.get("info").get("id") == "aa9b3d62-4d72-4ebc-8f39-3da3833e7038"


def test_list_most_attacked_users_command(requests_mock):
    """
    Scenario: Retrieves a list of the most attacked users in the organization for a given period.
    Given:
     - User has provided valid credentials and argument.
    When:
     - A get-vap command is called and there is a attacked people in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, list_most_attacked_users_command

    mock_response = json.loads(load_mock_response("most_attacked_users.json"))
    requests_mock.get(f"{MOCK_URL}/v2/people/vap", json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    result = list_most_attacked_users_command(client, "")
    assert len(result.outputs) == 5
    assert result.outputs_prefix == "Proofpoint.Vap"
    assert result.outputs.get("users")[0].get("identity").get("guid") == "88e36bf359-99e8-7e53-f58a-6df8b430be6d"
    assert result.outputs.get("totalVapUsers") == 2


def test_get_top_clickers_command(requests_mock):
    """
    Scenario: Retrieves a list of the top clickers in the organization for a given period.
    Given:
     - User has provided valid credentials and argument.
    When:
     - A get_top_clickers command is called and there is clickers in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_top_clickers_command

    mock_response = json.loads(load_mock_response("top_clickers.json"))
    requests_mock.get(f"{MOCK_URL}/v2/people/top-clickers", json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    result = get_top_clickers_command(client, "")
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "Proofpoint.Topclickers"
    assert result.outputs.get("users")[1].get("identity").get("guid") == "b4077fsv0e-3a2e-767f-7315-c049f831cc95"
    assert result.outputs.get("totalTopClickers") == 2


def test_url_decode(requests_mock):
    """
    Scenario: Decode URLs that have been rewritten by TAP to their original, target URL.
    Given:
     - User has provided valid credentials and arguments.
    When:
     - A url-decode command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, url_decode_command

    mock_response = json.loads(load_mock_response("url_decode.json"))
    requests_mock.post(f"{MOCK_URL}/v2/url/decode", json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    result = url_decode_command(client, "")
    assert len(result.outputs) == 2
    assert result.outputs_prefix == "Proofpoint.URL"
    assert result.outputs[1].get("decodedUrl") == "http://www.bouncycastle.org/"


def test_list_issues_command(requests_mock):
    """
    Scenario: Retrieves events for clicks to malicious URLs permitted and messages delivered in the specified time period.
    Given:
     - User has provided valid credentials and arguments.
    When:
     - A list_issues command is called and there is clicks and messages in the response.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, list_issues_command

    requests_mock.get(
        f"{MOCK_URL}/v2/siem/issues",
        json={
            "queryEndTime": "2021-04-16T14:00:00Z",
            "messagesDelivered": [MOCK_DELIVERED_MESSAGE],
            "clicksPermitted": [MOCK_PERMITTED_CLICK],
        },
    )
    client = Client(
        proofpoint_url=MOCK_URL, api_version="v2", service_principal="user1", secret="123", verify=False, proxies=None
    )
    result = list_issues_command(client, "3 days")
    messages_result = result[0]
    clicks_result = result[1]

    assert len(clicks_result.outputs) == 1
    assert clicks_result.outputs_prefix == "Proofpoint.ClicksPermitted"
    assert clicks_result.outputs[0].get("messageID") == "3333"

    assert len(messages_result.outputs) == 1
    assert messages_result.outputs_prefix == "Proofpoint.MessagesDelivered"
    assert messages_result.outputs[0].get("messageID") == "1111@evil.zz"


@freeze_time("2024-05-03T11:00:00")
def test_validate_first_fetch_time_valid_str():
    """
    Given:
     - A valid str first_fetch_time
    When:
     - running test_module.
    Then:
     - No exception is thrown.
    """
    from ProofpointTAP_v2 import validate_first_fetch_time

    first_fetch_time = "1 day ago"
    try:
        validate_first_fetch_time(first_fetch_time)
    except Exception as e:
        raise AssertionError(f"validate_first_fetch_time raised an exception {e}")  # noqa: PT015


@freeze_time("2024-05-03T11:00:00")
def test_validate_first_fetch_time_not_valid():
    """
    Given:
     - A first_fetch_time bigger than 7 days ago
    When:
     - running test_module.
    Then:
     - Exception is thrown.
    """
    from ProofpointTAP_v2 import validate_first_fetch_time

    first_fetch_time = "8 days ago"
    try:
        validate_first_fetch_time(first_fetch_time)
    except Exception as e:
        assert (
            "The First fetch time range is more than 7 days ago. Please update this parameter since "
            "Proofpoint supports a maximum 1 week fetch back."
        ) in str(e)
