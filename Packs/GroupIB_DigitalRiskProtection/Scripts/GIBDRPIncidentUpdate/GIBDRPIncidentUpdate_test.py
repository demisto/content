import demistomock as demisto
from GIBDRPIncidentUpdate import prevent_duplication


EXISTING_INCIDENT = [{"Contents": {"total": 1, "data": [{"id": "1", "gibdrpid": "12v"}]}}]
INCOMING_INCIDENT = {"gibdrpid": "12v"}


def test_prevent_duplication_existing_duplication(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=EXISTING_INCIDENT)
    result = prevent_duplication(INCOMING_INCIDENT)
    assert not result


def test_prevent_duplication_no_duplication(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    result = prevent_duplication(INCOMING_INCIDENT)
    assert result


def test_prevent_duplication_uses_rawjson_when_no_customfields(mocker):
    calls: list[tuple[str, dict]] = []

    def _exec(cmd, args):
        calls.append((cmd, args))
        if cmd == "getIncidents":
            return [{"Contents": {"total": 0, "data": []}}]
        return {}

    incident = {
        "rawJSON": '{"id":"raw-123","violation":{"id":"nested-ignored"}}',
        # No CustomFields, no top-level gibdrpid
    }
    mocker.patch.object(demisto, "executeCommand", side_effect=_exec)
    result = prevent_duplication(incident)
    assert result is True
    # Ensure query used raw id
    get_calls = [a for a in calls if a[0] == "getIncidents"]
    assert len(get_calls) == 1
    assert get_calls[0][1]["query"] == 'gibdrpid:"raw-123"'


def test_prevent_duplication_updates_existing_and_flattens_payload(mocker):
    set_calls: list[dict] = []

    def _exec(cmd, args):
        if cmd == "getIncidents":
            return [{"Contents": {"total": 1, "data": [{"id": "42", "gibdrpid": "abc"}]}}]
        if cmd == "setIncident":
            set_calls.append(args)
            return {}
        return {}

    incident = {
        "id": "should-be-ignored",
        "labels": [{"k": "v"}],
        "occurred": "2020-01-01T00:00:00Z",
        "sla": 0,
        "other": "other value",
        "CustomFields": {
            "gibdrpid": "abc",
            "x": "1",
        },
    }
    mocker.patch.object(demisto, "executeCommand", side_effect=_exec)
    result = prevent_duplication(incident)
    assert result is False
    # Verify setIncident called with flattened fields and without forbidden keys
    assert any(c["id"] == "42" and c.get("other") == "other value" for c in set_calls)
    assert any(c["id"] == "42" and c.get("gibdrpid") == "abc" for c in set_calls)
    assert any(c["id"] == "42" and c.get("x") == "1" for c in set_calls)
    # None of the calls should try to set forbidden keys
    for c in set_calls:
        assert "CustomFields" not in c
        assert "labels" not in c
        assert "occurred" not in c
        assert "sla" not in c
        assert "id" in c  # target id is allowed as the identifier, not as a field to set


def test_prevent_duplication_uses_mirror_id_as_fallback(mocker):
    captured_queries: list[str] = []

    def _exec(cmd, args):
        if cmd == "getIncidents":
            captured_queries.append(args["query"])
            return [{"Contents": {"total": 0, "data": []}}]
        return {}

    incident = {
        "dbotMirrorId": "mirror-789",
    }
    mocker.patch.object(demisto, "executeCommand", side_effect=_exec)
    result = prevent_duplication(incident)
    assert result is True
    assert captured_queries
    assert captured_queries[0] == 'gibdrpid:"mirror-789"'
