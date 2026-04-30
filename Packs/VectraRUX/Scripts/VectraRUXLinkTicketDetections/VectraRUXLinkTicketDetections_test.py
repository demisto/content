import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from VectraRUXLinkTicketDetections import main


def test_main_with_incidents_found_and_linked(mocker):
    """
    Given:
    - Arguments with incident_external_reference_id and incident_detection_id.
    - SearchIncidentsV2 returns incidents with matching external reference id.

    When:
    - Calling the 'main' function of the VectraRUXLinkTicketDetections script.

    Then:
    - Assert that SearchIncidentsV2 is called with the correct query.
    - Assert that linkIncidents is called with the found incident IDs.
    - Assert that return_results is called with the link result.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_external_reference_id": "123", "incident_detection_id": "456"},
    )

    search_result = [
        {
            "Contents": [
                {
                    "Contents": {
                        "data": [
                            {"id": "incident_1"},
                            {"id": "incident_2"},
                        ]
                    }
                }
            ]
        }
    ]
    link_result = [{"Type": 1, "Contents": "Incidents linked successfully"}]

    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[search_result, link_result],
    )

    return_results_mock = mocker.patch("VectraRUXLinkTicketDetections.return_results")

    main()

    assert execute_command_mock.call_count == 2

    search_call_args = execute_command_mock.call_args_list[0]
    assert search_call_args[0][0] == "SearchIncidentsV2"
    expected_query = "-status:closed -category:job vectraruxexternalreferenceid:123 -vectraruxdetectionid:=456"
    assert search_call_args[0][1]["query"] == expected_query

    link_call_args = execute_command_mock.call_args_list[1]
    assert link_call_args[0][0] == "linkIncidents"
    assert link_call_args[0][1]["linkedIncidentIDs"] == "incident_1,incident_2"

    return_results_mock.assert_called_once_with(link_result)


def test_main_with_no_incidents_found(mocker):
    """
    Given:
    - Arguments with incident_external_reference_id and incident_detection_id.
    - SearchIncidentsV2 returns no matching incidents (empty data).

    When:
    - Calling the 'main' function of the VectraRUXLinkTicketDetections script.

    Then:
    - Assert that SearchIncidentsV2 is called with the correct query.
    - Assert that linkIncidents is NOT called since no incidents were found.
    - Assert that return_results is called with the search result.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_external_reference_id": "123", "incident_detection_id": "456"},
    )

    search_result: list = [{"Contents": [{"Contents": {"data": []}}]}]

    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=search_result,
    )

    return_results_mock = mocker.patch("VectraRUXLinkTicketDetections.return_results")

    main()

    execute_command_mock.assert_called_once_with(
        "SearchIncidentsV2",
        {"query": "-status:closed -category:job vectraruxexternalreferenceid:123 -vectraruxdetectionid:=456"},
    )

    return_results_mock.assert_called_once_with(search_result)


def test_main_with_empty_content(mocker):
    """
    Given:
    - Arguments with incident_external_reference_id and incident_detection_id.
    - SearchIncidentsV2 returns empty content (None or falsy).

    When:
    - Calling the 'main' function of the VectraRUXLinkTicketDetections script.

    Then:
    - Assert that linkIncidents is NOT called.
    - Assert that return_results is called with the search result.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_external_reference_id": "999", "incident_detection_id": "888"},
    )

    search_result = [{"Contents": None}]

    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=search_result,
    )

    return_results_mock = mocker.patch("VectraRUXLinkTicketDetections.return_results")

    main()

    execute_command_mock.assert_called_once()

    return_results_mock.assert_called_once_with(search_result)


def test_main_with_single_incident(mocker):
    """
    Given:
    - Arguments with incident_external_reference_id and incident_detection_id.
    - SearchIncidentsV2 returns a single matching incident.

    When:
    - Calling the 'main' function of the VectraRUXLinkTicketDetections script.

    Then:
    - Assert that linkIncidents is called with the single incident ID.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_external_reference_id": "100", "incident_detection_id": "200"},
    )

    search_result = [{"Contents": [{"Contents": {"data": [{"id": "single_incident"}]}}]}]
    link_result = [{"Type": 1, "Contents": "Incident linked"}]

    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[search_result, link_result],
    )

    mocker.patch("VectraRUXLinkTicketDetections.return_results")

    main()

    link_call_args = execute_command_mock.call_args_list[1]
    assert link_call_args[0][0] == "linkIncidents"
    assert link_call_args[0][1]["linkedIncidentIDs"] == "single_incident"


def test_main_with_numeric_incident_ids(mocker):
    """
    Given:
    - Arguments with incident_external_reference_id and incident_detection_id.
    - SearchIncidentsV2 returns incidents with numeric IDs.

    When:
    - Calling the 'main' function of the VectraRUXLinkTicketDetections script.

    Then:
    - Assert that linkIncidents is called with incident IDs converted to strings.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_external_reference_id": "50", "incident_detection_id": "60"},
    )

    search_result = [
        {
            "Contents": [
                {
                    "Contents": {
                        "data": [
                            {"id": 12345},
                            {"id": 67890},
                        ]
                    }
                }
            ]
        }
    ]
    link_result = [{"Type": 1, "Contents": "Incidents linked"}]

    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[search_result, link_result],
    )

    mocker.patch("VectraRUXLinkTicketDetections.return_results")

    main()

    link_call_args = execute_command_mock.call_args_list[1]
    assert link_call_args[0][1]["linkedIncidentIDs"] == "12345,67890"


def test_main_query_format(mocker):
    """
    Given:
    - Arguments with specific incident_external_reference_id and incident_detection_id values.

    When:
    - Calling the 'main' function of the VectraRUXLinkTicketDetections script.

    Then:
    - Assert that the query built for SearchIncidentsV2 has the correct format.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"incident_external_reference_id": "ticket_abc", "incident_detection_id": "detection_xyz"},
    )

    search_result: list = [{"Contents": [{"Contents": {"data": []}}]}]

    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=search_result,
    )

    mocker.patch("VectraRUXLinkTicketDetections.return_results")

    main()

    search_call_args = execute_command_mock.call_args_list[0]
    query = search_call_args[0][1]["query"]

    assert "-status:closed" in query
    assert "-category:job" in query
    assert "vectraruxexternalreferenceid:ticket_abc" in query
    assert "-vectraruxdetectionid:=detection_xyz" in query
