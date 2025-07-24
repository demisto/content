import datetime as dt
import pytest
from Packs.CommonScripts.Scripts.SearchIssues.SearchIssues import *

data_test_check_if_found_incident = [
    ([], "failed to get incidents from xsoar.\nGot: []"),
    (None, "failed to get incidents from xsoar.\nGot: None"),
    ("", "failed to get incidents from xsoar.\nGot: "),
    ([{"Contents": {"data": None}}], False),
    ([{"Contents": {"data": "test"}}], True),
    ([{"Contents": {"test": "test"}}], "{'test': 'test'}"),
]


def create_sample_incidents(start, end, incident_type):
    return [
        {
            "id": f"{i}",
            "type": f"{incident_type}",
            "name": f"incident-{i}",
        }
        for i in range(start, end + 1)
    ]


def execute_get_incidents_command_side_effect(amount_of_mocked_incidents):
    mocked_incidents = []

    default_jump = 100
    counter = 1
    for start in range(1, amount_of_mocked_incidents + 1, default_jump):
        end = min(amount_of_mocked_incidents, default_jump * counter)

        incident_type = "A" if counter % 2 == 0 else "B"
        if counter == 1:
            execute_command_mock = [{"Contents": {"data": create_sample_incidents(start, end, incident_type), "total": 0}}]
        else:
            execute_command_mock = {"data": create_sample_incidents(start, end, incident_type)}

        mocked_incidents.append(execute_command_mock)
        counter += 1

    if mocked_incidents:
        mocked_incidents.append({"data": None})

    return mocked_incidents


@pytest.mark.parametrize("_input, expected_output", data_test_check_if_found_incident)
def test_check_if_found_incident(_input, expected_output):
    try:
        output = check_if_found_incident(_input)
    except DemistoException as error:
        output = str(error)
    assert output == expected_output, f"check_if_found_incident({_input}) returns: {output}. expected: {expected_output}"


data_test_is_valid_args = [
    ("\\", True),
    ("\n", True),
    ("\\n", True),
    ("\\t", True),
    ("\\\\", True),
    ('\\"', True),
    ("\\r", True),
    ("\\7", True),
    ("\\'", True),
]


@pytest.mark.parametrize("_input, expected_output", data_test_is_valid_args)
def test_is_valid_args(_input, expected_output):
    try:
        output = is_valid_args({"test": _input})
    except DemistoException:
        output = False

    assert output == expected_output, f"is_valid_args({_input}) returns: {output}. expected: {expected_output}"


data_test_is_id_valid = [
    (123, True),
    ("123", True),
    (123.3, False),
    ("1,2,3", True),
    ([1, 2, 3], True),
    ("[1,2,3]", True),
]


@pytest.mark.parametrize("id_value, expected_output", data_test_is_id_valid)
def test_is_incident_id_valid(id_value, expected_output):
    """
    Given:
        - an incident id

    When:
        - running the script as a playbook task

    Then:
        - validating that the incident is is a valid input from type int or str

    """
    try:
        is_valid_id = is_valid_args({"id": id_value})
    except DemistoException:
        is_valid_id = False
    assert is_valid_id == expected_output


EXAMPLE_INCIDENTS_RAW_RESPONSE = [
    {"id": "1", "type": "TypeA", "name": "Phishing", "created": "2025-01-01T10:00:00Z"},
    {"id": "2", "type": "Type-A", "name": "Phishing Campaign", "created": "2025-01-01T10:01:00Z"},
    {"id": "3", "type": "SomeType-A", "name": "Go Phish", "created": "2025-01-01T10:02:00Z"},
    {"id": "4", "type": "Another Type-A", "name": "Hello", "created": "2025-01-01T10:03:00Z"},
]

FILTER_TO_MATCHED_INCIDENTS = [
    ({"type": "Type-A"}, ["2"]),
    ({"type": "Type-A, SomeTypeA"}, ["2"]),
    ({"type": ["Type-A", "SomeType-A"]}, ["2", "3"]),
    ({"type": "Another"}, []),
    ({"name": "Phishing"}, ["1"]),
    ({"name": "Phishing,Phishing Campaign"}, ["1", "2"]),
]

INCIDENT = [
    {
        "CustomFields": {
            "hostname": "host_name",  # noqa
            "initiatedby": "initiated_by",
            "targetprocessname": "target_process_name",
            "username": "user_name",
        },
        "status": 0,
        "severity": 1,
    },
]


@pytest.mark.parametrize("args, expected_incident_ids", FILTER_TO_MATCHED_INCIDENTS)
def test_apply_filters(args, expected_incident_ids):
    incidents = apply_filters(EXAMPLE_INCIDENTS_RAW_RESPONSE, args)
    assert [incident["id"] for incident in incidents] == expected_incident_ids


def get_incidents_mock(_, args, extract_contents=True, fail_on_error=True):
    ids = args.get("id", "").split(",")
    incidents_list = [incident for incident in EXAMPLE_INCIDENTS_RAW_RESPONSE if incident["id"] in ids]
    if not extract_contents:
        return [{"Contents": {"data": incidents_list, "total": len(incidents_list)}}]
    return {"data": None}


@pytest.mark.parametrize(
    "args,filtered_args,expected_result",
    [
        # ({}, {}, []),
        ({"trimevents": "0"}, {}, []),
        ({"trimevents": "1"}, {"trimevents": "1"}, []),
        ({"id": 1}, {"id": "1", "todate": "2025-01-01T10:00:00Z"}, [EXAMPLE_INCIDENTS_RAW_RESPONSE[0]]),
        (
            {"id": [1, 2]},
            {"id": "1,2", "todate": "2025-01-01T10:00:00Z"},
            [EXAMPLE_INCIDENTS_RAW_RESPONSE[0], EXAMPLE_INCIDENTS_RAW_RESPONSE[1]],
        ),
        (
            {"id": "1,2"},
            {"id": "1,2", "todate": "2025-01-01T10:00:00Z"},
            [EXAMPLE_INCIDENTS_RAW_RESPONSE[0], EXAMPLE_INCIDENTS_RAW_RESPONSE[1]],
        ),
    ],
)
def get_incidents_mock_include_informational(_, args, extract_contents=True, fail_on_error=True):
    incidents = [
        {"id": "1", "informational": False, "created": "2025-01-01T09:59:00Z"},
        {"id": "2", "informational": False, "created": "2025-01-01T10:00:00Z"},
    ]

    includeinformational = args.get("includeinformational", None)

    if includeinformational:
        incidents.extend(
            [
                {"id": "3", "informational": True, "created": "2025-01-01T10:01:00Z"},
                {"id": "4", "informational": True, "created": "2025-01-01T10:02:00Z"},
            ]
        )

    if not extract_contents:
        return [{"Contents": {"data": incidents, "total": len(incidents)}}]

    return {"Contents": {"data": incidents}}


INCLUDE_INFORMATIONAL_FIXED_TIME = dt.datetime(2024, 10, 1, 15, 0, 0)
INCLUDE_INFORMATIONAL_NOW = INCLUDE_INFORMATIONAL_FIXED_TIME.isoformat()
INCLUDE_INFORMATIONAL_5_HOURS_AGO = dt.datetime(2024, 10, 1, 10, 0, 0).isoformat()
INCLUDE_INFORMATIONAL_3_HOURS_AGO = dt.datetime(2024, 10, 1, 12, 0, 0).isoformat()


def test_transform_to_alert_data():
    incident = transform_to_alert_data(INCIDENT)[0]
    assert incident["hostname"] == "host_name"
    assert incident["status"] == "New"
    assert incident["severity"] == "LOW"


def test_summarize_incidents():
    assert summarize_incidents(
        {"add_fields_to_summarize_context": "test"}, [{"id": "test", "CustomFields": {}}], platform="xsoar"
    ) == [
        {
            "closed": "n/a",
            "created": "n/a",
            "id": "test",
            "issueLink": "n/a",
            "name": "n/a",
            "owner": "n/a",
            "severity": "n/a",
            "status": "n/a",
            "test": "n/a",
            "type": "n/a",
        }
    ]


@pytest.mark.parametrize(
    "amount_of_mocked_incidents, args, expected_incidents_length",
    [
        (306, {}, 100),
        (306, {"limit": "200"}, 200),
        (105, {"limit": "200"}, 105),
        (1000, {"limit": "100"}, 100),
        (1000, {"limit": "1100"}, 1000),
        (205, {"limit": "105.5"}, 105),
        (700, {"limit": "500", "type": "A"}, 300),
        (1500, {"limit": "250", "type": "A"}, 250),
        (500, {"limit": "100", "name": "incident-8"}, 1),
    ],
)
def test_main_flow_with_limit(mocker, amount_of_mocked_incidents, args, expected_incidents_length):
    """
    Given:
       - Case A: Total of 306 incidents matching in XSOAR and no args
       - Case B: Total of 306 incidents matching in XSOAR and limit = 200
       - Case C: Total of 105 incidents matching in XSOAR and limit = 200
       - Case D: Total of 1000 incidents matching in XSOAR and limit = 100
       - Case E: Total of 1000 incidents matching in XSOAR and limit = 1100
       - Case F: Total of 205 incidents matching in XSOAR and limit = 105.5
       - Case G: Total of 700 incidents and only 300 incidents which match type = 'A' and limit = 500
       - Case H: Total of 1500 incidents and only 700 incidents which match type = 'A' and limit = 250
       - Case I: Total of 500 incidents and only 1 incident that its name = 'incident-8' and limit = 100

    When:
       - Running the main flow

    Then:
       - Case A: Make sure only 100 incidents have been returned (default of the limit if not stated)
       - Case B: Make sure only 200 incidents have been returned.
       - Case C: Make sure only 105 incidents have been returned (cause there are fewer incidents than requested limit)
       - Case D: Make sure only 100 incidents have been returned.
       - Case E: Make sure only 1000 incidents have been returned.
       - Case F: Make sure only 105 (rounded) incidents have been returned.
       - Case G: Make sure only 300 incidents have been returned.
       - Case H: Make sure only 250 incidents have been returned.
       - Case I: Make sure only one incident has been returned.

    """
    from Packs.CommonScripts.Scripts.SearchIssues import SearchIssues

    mocker.patch.object(
        SearchIssues, "execute_command", side_effect=execute_get_incidents_command_side_effect(amount_of_mocked_incidents)
    )

    mocker.patch.object(demisto, "args", return_value=args)
    return_results_mocker = mocker.patch.object(SearchIssues, "return_results")
    mocker.patch("SearchIssues.get_demisto_version", return_value={})

    SearchIssues.main()

    assert return_results_mocker.called
    assert len(return_results_mocker.call_args[0][0].outputs) == expected_incidents_length


def test_query_argument_with_unicode_escape(mocker):
    """
    Given:
       - A query to search incidents with unicode escape

    When:
       - Executing the SearchIncidentsV2 command and check arg validation.

    Then:
       - Make sure the query format is correct and is_valid_args method is not failed.
    """
    from Packs.CommonScripts.Scripts.SearchIssues import SearchIssues

    special_chars = ["\n", "\t", "\\", '"', "'", "\7", "\r", "\\x", "\\X", "\\N", "\\u", "\\U"]
    args_array = [
        {"query": f"`(username:'user{special_char}sername') and (name:'name_1' or name:'name_2')`"}
        for special_char in special_chars
    ]
    mocker.patch.object(demisto, "args", side_effect=args_array)
    mocker.patch.object(SearchIssues, "return_results")
    mocker.patch("SearchIssues.get_demisto_version", return_value={})
    for _ in special_chars:
        mocker.patch.object(SearchIssues, "execute_command", side_effect=execute_get_incidents_command_side_effect(1))
        SearchIssues.main()


def test_todate_set_and_pagination(mocker):
    """
    Given: Duplicated incidents from executing getIncidents command to the platform in 2 different requests in a row.
    When: Running the command with limit that is larger than the page size.
    Then: Validate that the command return incident list without duplications by changing the todate to
     be the first incident time from the first run.
    """
    from Packs.CommonScripts.Scripts.SearchIssues import SearchIssues

    # Page 1 returns exactly page_size incidents
    page1_incidents = [{"created": f"2025-01-01T10:0{i}:00Z", "id": i} for i in range(5)]
    # Page 2 returns fewer, triggering end-of-pagination
    page2_incidents = [{"created": "2025-01-01T09:59:00Z", "id": 101}]

    # Mock execute_command behavior
    execute_command_mocker = mocker.patch.object(
        SearchIssues,
        "execute_command",
        side_effect=[
            # 1st call: initial getIncidents
            [{"Contents": {"data": page1_incidents}}],
            # 2nd call: getIncidents inside loop (page2)
            {"data": page2_incidents},
        ],
    )

    args = {"limit": 10, "size": 5}
    SearchIssues.search_incidents(args=args)

    # After first page, todate should be set to the very first created timestamp
    expected_todate = page1_incidents[0]["created"]

    # Confirm that execute_command was called a second time with args including todate
    _, second_call_kwargs = execute_command_mocker.call_args_list
    assert second_call_kwargs[0][1]["todate"] == expected_todate


def test_from_issue_statuses_to_numeric_values():
    """Given statuses test the result."""
    assert from_issue_statuses_to_numeric_values("New,In Progress") == "0,1"
    assert from_issue_statuses_to_numeric_values("Resolved") == "2"
    assert from_issue_statuses_to_numeric_values("In Progress, Resolved") == "1,2"


def test_numeric_values_to_issue_statuses():
    """Given numeric arg return the status of the issue."""
    assert numeric_values_to_issue_statuses(0) == "New"
    assert numeric_values_to_issue_statuses(1) == "In Progress"
    assert numeric_values_to_issue_statuses(2) == "Resolved"
