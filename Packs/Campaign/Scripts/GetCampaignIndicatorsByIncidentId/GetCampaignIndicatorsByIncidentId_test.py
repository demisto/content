import demistomock as demisto
import pytest
from GetCampaignIndicatorsByIncidentId import (
    associate_to_current_incident,
    format_results,
    get_indicator_link_creator,
    get_indicators_from_incidents,
    main,
)
from pytest_mock import MockerFixture

INCIDENT_IDS = ["1", "2", "3"]
INDICATORS = {
    "iocs": [
        {
            "id": "23",
            "indicator_type": "URL",
            "investigationIDs": ["1"],
            "relatedIncCount": 5,
            "score": 1,
            "value": "http://www.example.com",
            "Type": 0,
        },
        {
            "id": "24",
            "indicator_type": "URL",
            "investigationIDs": ["1", "2"],
            "relatedIncCount": 5,
            "score": 1,
            "value": "http://www.example.com",
            "Type": 0,
        },
    ],
    "total": 2,
}


NO_INDICATORS_FOUND = "No mutual indicators were found."
MD_INDICATORS_RESULT = (
    "|Id|Value|Type|Reputation|Involved Incidents Count|\n"
    "|---|---|---|---|---|\n"
    "| [24](#/indicator/24) | http://www.example.com | 0 | Good | 2 |\n"
)


@pytest.mark.parametrize(
    "incident_ids, indicators, expected_result",
    [
        (INCIDENT_IDS, INDICATORS, MD_INDICATORS_RESULT),
        (INCIDENT_IDS, {"iocs": [], "total": 0}, NO_INDICATORS_FOUND),
        (INCIDENT_IDS, {"iocs": [], "total": 0}, NO_INDICATORS_FOUND),
    ],
)
def test_get_indicators_by_incident_id(mocker: MockerFixture, incident_ids: list, indicators: dict, expected_result: str) -> None:
    """
    Given:
        - Campaign indicators by incident ids.

    When:
        - Running the format_result.

    Then:
        - Ensure the returned MD value as expected.
    """
    mocker.patch.object(demisto, "searchIndicators", return_value=indicators)

    indicators_res = get_indicators_from_incidents(incident_ids)
    result = format_results(indicators_res, incident_ids)

    assert result == expected_result


def test_set_path(mocker: MockerFixture) -> None:
    execute_command_mocker = mocker.patch.object(demisto, "executeCommand")
    mocker.patch("GetCampaignIndicatorsByIncidentId.get_incidents_ids_from_context", return_value={})
    mocker.patch("GetCampaignIndicatorsByIncidentId.get_indicators_from_incidents", return_value={})
    main()
    execute_command_mocker.assert_called_once_with(
        "setIncident", {"campaignmutualindicators": "No mutual indicators were found."}
    )


def test_associate_to_current_incident(mocker: MockerFixture) -> None:
    execute_command_mocker = mocker.patch.object(demisto, "executeCommand")
    mocker.patch.object(demisto, "incident", return_value={"id": "id"})
    associate_to_current_incident([{"value": "indicators"}])
    execute_command_mocker.assert_called_once_with(
        "associateIndicatorsToIncident", {"incidentId": "id", "indicatorsValues": ["indicators"]}
    )


@pytest.mark.parametrize(
    "is_platform_res, is_saas_res, indicator_id, expected_link",
    [
        (True, False, "24", "[24](/indicator/24)"),
        (False, True, "24", "[24](/indicator/24)"),
        (False, False, "24", "[24](#/indicator/24)"),
    ],
)
def test_get_indicator_link_creator(mocker: MockerFixture, is_platform_res, is_saas_res, indicator_id, expected_link):
    """
    Given:
        - An indicator ID.
        - Case 1: Unified Cortex platform (XSIAM v3 / XSOAR on platform) -> path-based URL.
        - Case 2: Cortex XSOAR 8.x SaaS -> path-based URL.
        - Case 3: Cortex XSOAR 6.x (on-prem) -> legacy hash-based URL.
    When:
        - Calling the indicator link creator.
    Then:
        - Ensure the correct link format is produced for each platform (XSUP-78154).
    """
    mocker.patch("GetCampaignIndicatorsByIncidentId.is_platform", return_value=is_platform_res)
    mocker.patch("GetCampaignIndicatorsByIncidentId.is_xsoar_saas", return_value=is_saas_res)

    assert get_indicator_link_creator()(indicator_id) == expected_link
