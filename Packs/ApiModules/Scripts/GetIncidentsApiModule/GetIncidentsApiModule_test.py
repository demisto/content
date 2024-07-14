import pytest
from GetIncidentsApiModule import *


def mock_incident(
    inc_id: int,
    inc_type: str,
    created: str,
    modified: str,
    **kwargs,
) -> dict:
    # helper method for creating mock incidents
    return {
        "id": inc_id,
        "name": f"This is incident {inc_id}",
        "type": inc_type,
        "severity": 0,
        "status": 1,
        "created": created,
        "modified": modified,
        "CustomFields": {
            "testField": "testValue"
        },
        "closed": "0001-01-01T00:00:00Z",
        "labels": [{"type": "subject", "value": "This subject1"}, {"type": "unique", "value": "This subject1"}],
        "attachment": [{"name": "Test word1 word2"}],
    } | kwargs


INCIDENTS_LIST = [
    mock_incident(1, "Phishing", "2019-01-02T00:00:00Z", "2020-01-02T00:00:00Z"),
    mock_incident(2, "Phishing", "2019-02-02T00:00:00Z", "2020-02-02T00:00:00Z"),
    mock_incident(3, "Malware", "2020-02-02T00:00:00Z", "2020-02-02T00:00:00Z"),
    mock_incident(4, "Malware", "2021-02-02T00:00:00Z", "2021-02-02T00:00:00Z"),
    mock_incident(5, "Malware", "2021-02-02T00:00:00Z", "2021-02-02T00:00:00Z"),
    mock_incident(6, "Unclassified", "2021-02-02T00:00:00Z", "2021-02-02T00:00:00Z"),
    mock_incident(7, "Unclassified", "2021-02-02T00:00:00Z", "2021-02-02T00:00:00Z"),
]


def does_incident_match_query(
    inc: dict,
    time_field: str,
    from_date_str: str,
    to_date_str: str,
    incident_types: list[str],
) -> bool:
    # a helper method for mock_execute_command() that determines
    # whether an incident should be part of the response
    if not incident_types or inc["type"] in incident_types:
        inc_time_field = dateparser.parse(inc[time_field])
        from_date = dateparser.parse(from_date_str or inc[time_field])
        to_date = dateparser.parse(to_date_str or inc[time_field])
        return from_date <= inc_time_field < to_date
    return False


def mock_execute_command(command: str, args: dict) -> list[dict]:
    # Mock implementations for `getIncidents` and `getContext` builtin commands.
    match command:
        case "getIncidents":
            page = args["page"]
            size = args["size"]
            query = args["query"] or ""
            incident_types = []
            time_field = "modified" if "modified" in query else "created"
            from_date = args["fromdate"]
            to_date = args["todate"]
            # populate_fields = args["populateFields"] or []

            if match := re.search(r"\(modified:>=\"([^\"]*)\"\)", query):
                from_date = match.group(1)
            if match := re.search(r"\(modified:<\"([^\"]*)\"\)", query):
                to_date = match.group(1)
            if match := re.search(r"\(type:\(([^)]*)\)\)", query):
                incident_types = argToList(match.group(1), separator=" ", transform=lambda t: t.strip("\""))
            res = [
                i  # {k: v for k, v in i.items() if not populate_fields or k in populate_fields}
                for i in INCIDENTS_LIST
                if does_incident_match_query(i, time_field, from_date, to_date, incident_types)
            ][page * size:(page + 1) * size]
            return [{"Contents": {"data": res}, "Type": "json"}]
        case "getContext":
            return [{"Contents": "context", "Type": "json"}]
        case _:
            raise Exception(f"Unmocked command: {command}")


def test_prepare_fields_list():
    """
    Given: A list of incident fields
    When: Running prepare_fields_list()
    Then: Ensure a unique list of fields without the `incident.` prefix for each item is returned
    """
    assert prepare_fields_list(["incident.hello", "", "hello"]) == ["hello"]


def test_build_query():
    """
    Given: Different query arguments
    When: Running build_query_parameter()
    Then: Ensure the result is a query string in the expected format
    """
    query = build_query_parameter(
        custom_query="Extra part",
        incident_types=["*phish*", "Malware"],
        time_field="modified",
        from_date="2019-01-10T00:00:00",
        to_date="2019-01-12T00:00:00",
        non_empty_fields=["status", "closeReason"],
    )
    assert query == (
        "(Extra part) and (type:(*phish* \"Malware\")) and (modified:>=\"2019-01-10T00:00:00\") "
        "and (modified:<\"2019-01-12T00:00:00\") and (status:* and closeReason:*)"
    )


def test_build_query_bad():
    """
    Given: No query arguments
    When: Running build_query_parameter()
    Then: Ensuring a DemistoException is raised
    """
    with pytest.raises(DemistoException):
        build_query_parameter(
            custom_query=None,
            incident_types=[],
            time_field=None,
            from_date=None,
            to_date=None,
            non_empty_fields=[],
        )


def test_get_incidents_by_query_sanity_test(mocker):
    """
    Given:
    - A mock incidents database (INCIDENTS_LIST)
    - Search incidents query arguments
    When: Running get_incidents_by_query()
    Then: Ensure the expected 4 incidents are returned
    """
    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    args = {
        "incidentTypes": "Phishing,Malware",
        "timeField": "created",
        "fromDate": "2019-02-01T00:00:00",
        "toDate": "3 days ago",
        "limit": "10",
        "includeContext": "false",
        "pageSize": "10",
    }
    results = get_incidents_by_query(args)
    assert len(results) == 4
    assert all(
        inc["type"] in args["incidentTypes"] for inc in results
    )
    assert all(
        dateparser.parse(args["fromDate"]).astimezone() <= dateparser.parse(inc["created"])
        for inc in results
    )
    assert all(
        dateparser.parse(inc["created"]) < dateparser.parse(args["toDate"]).astimezone()
        for inc in results
    )


def test_get_incidents_by_query_with_pagination(mocker):
    """
    Given:
    - A mock incidents database (INCIDENTS_LIST)
    - Search incidents query arguments that should return 4 incidents (same as the sanity test)
    When:
    - pageSize is 3
    Then:
    - Ensure the expected 4 incidents are returned
    - Ensure executeCommand was called twice
    """
    execute_command = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    args = {
        "incidentTypes": "Phishing,Malware",
        "timeField": "created",
        "fromDate": "2019-02-01T00:00:00",
        "toDate": "3 days ago",
        "limit": "10",
        "includeContext": "false",
        "pageSize": "3",
    }
    results = get_incidents_by_query(args)
    assert len(results) == 4
    assert execute_command.call_count == 2


def test_get_incidents_by_query_with_populate_fields(mocker):
    """
    Given:
    - A mock incidents database (INCIDENTS_LIST)
    - Search incidents query arguments that should return 4 incidents (same as the sanity test)
    When:
    - populateFields is id,name,testField
    Then:
    - Ensure the expected 4 incidents are returned
    - Ensure the returned incidents' keys are "id", "name", and "testField" only.
    """
    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    args = {
        "incidentTypes": "Phishing,Malware",
        "timeField": "created",
        "fromDate": "2019-02-01T00:00:00",
        "toDate": "3 days ago",
        "limit": "10",
        "includeContext": "false",
        "pageSize": "10",
        "populateFields": "id,name,testField"
    }
    results = get_incidents_by_query(args)
    assert len(results) == 4
    assert all(set(inc.keys()) == {"id", "name", "testField"} for inc in results)


def test_get_incidents_by_query_with_populate_fields_with_pipe_separator(mocker):
    """
    Given:
    - A mock incidents database (INCIDENTS_LIST)
    - Search incidents query arguments that should return 4 incidents (same as the sanity test)
    When:
    - populateFields is id|name|testField
    Then:
    - Ensure the expected 4 incidents are returned
    - Ensure the returned incidents' keys are "id", "name", and "testField" only.
    """
    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    args = {
        "incidentTypes": "Phishing,Malware",
        "timeField": "created",
        "fromDate": "2019-02-01T00:00:00",
        "toDate": "3 days ago",
        "limit": "10",
        "includeContext": "false",
        "pageSize": "10",
        "populateFields": "id|name|testField"
    }
    results = get_incidents_by_query(args)
    assert len(results) == 4
    assert all(set(inc.keys()) == {"id", "name", "testField"} for inc in results)


def test_get_incidents_by_query_with_context(mocker):
    """
    - A mock incidents database (INCIDENTS_LIST)
    - Search incidents query arguments that should return 4 incidents (same as the sanity test)
    When:
    - includeContext is true
    Then:
    - Ensure the expected 4 incidents are returned
    - Ensure each incident has a non-empty context key
    """
    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    args = {
        "incidentTypes": "Phishing,Malware",
        "timeField": "created",
        "fromDate": "2019-02-01T00:00:00",
        "toDate": "3 days ago",
        "limit": "10",
        "includeContext": "true",
        "pageSize": "10",
    }
    results = get_incidents_by_query(args)
    assert len(results) == 4
    assert all(inc["context"] for inc in results)


def test_get_incidents_by_query_timefield_is_modified(mocker):
    """
    - A mock incidents database (INCIDENTS_LIST)
    - Search incidents query arguments
    When:
    - timeField is modified
    Then:
    - Ensure the expected 1 incident is returned
    """
    execute_command = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    args = {
        "timeField": "modified",
        "fromDate": "2020-01-02T00:00:00Z",
        "toDate": "2020-01-03T00:00:00Z",
        "limit": "10",
        "includeContext": "false",
        "pageSize": "3",
    }
    results = get_incidents_by_query(args)
    assert len(results) == 1
    assert execute_command.call_count == 1
