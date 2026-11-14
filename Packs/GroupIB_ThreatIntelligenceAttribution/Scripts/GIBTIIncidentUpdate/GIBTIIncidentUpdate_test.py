import json

import demistomock as demisto
from GIBTIIncidentUpdate import prevent_duplication

EXISTING_INCIDENT = [{"Contents": {"total": 1, "data": [{"id": "1", "gibid": "12v"}]}}]
INCOMING_INCIDENT = {
    "id": "302",
    "gibid": "12v",
    "name": "n",
    "status": 1,
    "owner": "x",
    "CustomFields": {"gibid": "12v", "gibseverity": "High"},
}


def test_an_incident_with_a_duplicate_is_dropped(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=EXISTING_INCIDENT)
    result = prevent_duplication(INCOMING_INCIDENT)
    assert not result


def test_an_incident_without_a_duplicate_is_kept(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    result = prevent_duplication(INCOMING_INCIDENT)
    assert result


def test_the_duplicate_is_updated_not_the_incoming_incident(mocker):
    calls = []

    def fake(command, args):
        calls.append((command, args))
        return EXISTING_INCIDENT if command == "getIncidents" else [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake)
    assert prevent_duplication(dict(INCOMING_INCIDENT)) is False
    assert calls[0][1]["query"] == 'gibid:"12v" and -status:closed'
    set_calls = [a for c, a in calls if c == "setIncident"]
    assert len(set_calls) == 1
    assert set_calls[0]["id"] == "1"
    assert set_calls[0]["gibseverity"] == "High"
    assert set_calls[0]["name"] == "n"
    assert "status" not in set_calls[0]
    assert "owner" not in set_calls[0]


def test_the_incoming_incident_is_kept_when_the_update_fails(mocker):
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=lambda c, a: EXISTING_INCIDENT if c == "getIncidents" else [{"Type": 4, "Contents": "setIncident failed"}],
    )
    assert prevent_duplication(dict(INCOMING_INCIDENT)) is True


def test_an_incident_without_a_gib_id_is_kept_without_a_search(mocker):
    execute = mocker.patch.object(demisto, "executeCommand")
    assert prevent_duplication({"name": "n"}) is True
    execute.assert_not_called()


def test_a_refused_grid_field_is_left_out_of_the_retry(mocker):
    calls = []

    def fake(command, args):
        calls.append((command, args))
        if command == "getIncidents":
            return EXISTING_INCIDENT
        if "gibreportstable" in args:
            return [{"Type": 4, "Contents": "Invalid grid column in row 0: '2026-08-28' is not a legal date"}]
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake)
    incoming = dict(INCOMING_INCIDENT)
    incoming["CustomFields"] = {**INCOMING_INCIDENT["CustomFields"], "gibreportstable": [{"datepublished": "2026-08-28"}]}
    assert prevent_duplication(incoming) is False
    set_calls = [a for c, a in calls if c == "setIncident"]
    assert len(set_calls) == 2
    assert "gibreportstable" not in set_calls[1]
    assert set_calls[1]["gibseverity"] == "High"


def test_the_update_fields_drop_empty_values():
    from GIBTIIncidentUpdate import build_update_fields

    incident = {"name": "x", "details": "", "CustomFields": {"gibid": "12v", "gibsource": "", "gibemails": []}}
    update_fields = build_update_fields(incident)
    assert "details" not in update_fields
    assert "gibsource" not in update_fields
    assert "gibemails" not in update_fields
    assert update_fields == {"name": "x", "gibid": "12v"}


def _run(mocker, incoming, existing, set_result=None):
    calls = []

    def fake(command, args):
        calls.append((command, args))
        if command == "getIncidents":
            return [{"Type": 1, "Contents": {"data": existing}}]
        return set_result or [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=fake)
    keep = prevent_duplication(incoming)
    return [a["query"] for c, a in calls if c == "getIncidents"], [a["id"] for c, a in calls if c == "setIncident"], keep


def test_only_an_incident_of_the_incoming_type_and_port_is_a_duplicate(mocker):
    """An address is the GIB ID of a record in every suspicious_ip/* collection, and an open proxy
    address can have several listings, each with its port."""
    vpn = {"type": "GIB Suspicious IP VPN", "CustomFields": {"gibid": "198.51.100.10"}}
    assert _run(mocker, vpn, [])[0] == ['gibid:"198.51.100.10" and type:"GIB Suspicious IP VPN" and -status:closed']
    proxy = {"type": "GIB Suspicious IP Open Proxy", "CustomFields": {"gibid": "198.51.100.10", "gibproxyport": 8080.0}}
    assert _run(mocker, proxy, [])[0] == [
        'gibid:"198.51.100.10" and type:"GIB Suspicious IP Open Proxy" and gibproxyport:8080 and -status:closed'
    ]


def test_a_flagged_phishing_group_updates_its_incident_and_is_never_kept_and_an_unflagged_one_without_an_incident_is_kept(mocker):
    flagged = {"type": "GIB Attacks Phishing Group", "CustomFields": {"gibid": "12v"}, "rawJSON": json.dumps({"whitelist": True})}
    assert _run(mocker, flagged, [{"id": "1"}])[1:] == (["1"], False)
    assert _run(mocker, flagged, [])[1:] == ([], False)
    assert _run(mocker, flagged, [{"id": "1"}], set_result=[{"Type": 4, "Contents": "setIncident failed"}])[1:] == (["1"], False)
    assert _run(mocker, {**flagged, "rawJSON": json.dumps({"whitelist": False})}, [])[1:] == ([], True)
    allow_listed = {**flagged, "rawJSON": "{", "CustomFields": {"gibid": "12v", "giballowlisted": True}}
    assert _run(mocker, allow_listed, [])[1:] == ([], False)
    assert _run(mocker, {**flagged, "rawJSON": "{"}, [])[1:] == ([], True)


def test_without_a_search_result_a_flagged_phishing_group_is_never_kept_and_an_unflagged_one_is_kept(mocker):
    flagged = {"type": "GIB Attacks Phishing Group", "CustomFields": {"gibid": "12v", "giballowlisted": True}}
    assert _run(mocker, {**flagged, "CustomFields": {"giballowlisted": True}}, [{"id": "1"}]) == ([], [], False)
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "getIncidents failed"}])
    assert prevent_duplication(flagged) is False
    assert prevent_duplication({**flagged, "CustomFields": {"gibid": "12v"}}) is True


def _breach(upload_time, leak="Leak A", **extra):
    fields = {"gibid": "12v", "gibleakname": leak, "gibuploadtime": upload_time}
    return {"type": "GIB Data Breach", "CustomFields": fields, **extra}


def test_a_breached_credential_matches_only_the_incident_of_the_same_leak(mocker):
    """A breached record's GIB ID names the credential, which appears in several leaks."""
    assert _run(mocker, _breach(None), [])[0] == [
        'gibid:"12v" and type:"GIB Data Breach" and gibleakname:"Leak A" and -status:closed'
    ]


def test_a_breached_record_matches_only_the_incident_of_the_same_upload(mocker):
    """id, leakName and uploadTime name a breached record."""
    existing = [_breach("2026-01-01T00:00:00Z", id="1"), _breach("2026-02-01T00:00:00Z", id="2")]
    assert _run(mocker, _breach("2026-02-01T00:00:00+00:00"), existing)[1:] == (["2"], False)
    assert _run(mocker, _breach("2026-03-01T00:00:00Z"), existing)[1:] == ([], True)
    assert _run(mocker, _breach("2026-02-01T00:00:00"), existing)[1:] == (["2"], False)


def test_a_leak_whose_name_only_contains_the_incoming_one_is_another_leak(mocker):
    """The quoted phrase also finds a longer leak name, such as "Leak A 2013" for "Leak A"."""
    existing = [_breach(None, leak="Leak A 2013", id="1"), _breach(None, id="2")]
    assert _run(mocker, _breach(None), existing)[1:] == (["2"], False)
    assert _run(mocker, _breach(None), existing[:1])[1:] == ([], True)
