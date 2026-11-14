import demistomock as demisto
from GIBIncidentUpdateIncludingClosed import prevent_duplication

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
    assert calls[0][1]["query"] == 'gibid:"12v"'
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
    from GIBIncidentUpdateIncludingClosed import build_update_fields

    incident = {"name": "x", "details": "", "CustomFields": {"gibid": "12v", "gibsource": "", "gibemails": []}}
    update_fields = build_update_fields(incident)
    assert "details" not in update_fields
    assert "gibsource" not in update_fields
    assert "gibemails" not in update_fields
    assert update_fields == {"name": "x", "gibid": "12v"}
