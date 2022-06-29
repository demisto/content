import pytest
from GetCampaignIndicatorsByIncidentId import *
import demistomock as demisto

INCIDENT_IDS = ['1', '2', '3']
INDICATORS = [
    {
        "Contents": [
            {
                "id": "23",
                "indicator_type": "URL",
                "investigationIDs": [
                    "1"
                ],
                "relatedIncCount": 5,
                "score": 1,
                "value": "http://www.example.com"
            },
            {
                "id": "24",
                "indicator_type": "URL",
                "investigationIDs": [
                    "1",
                    "2"
                ],
                "relatedIncCount": 5,
                "score": 1,
                "value": "http://www.example.com"
            },
            {
                "id": "25",
                "indicator_type": "URL",
                "investigationIDs": [
                    "1",
                    "2",
                    "3",
                    "4"
                ],
                "relatedIncCount": 5,
                "score": 1,
                "value": "http://www.example.com"
            }
        ],
        'Type': 0
    }
]

NO_INDICATORS_FOUND = 'No mutual indicators were found.'
MD_INDICATORS_RESULT = '|Id|Value|Type|Reputation|Involved Incidents Count|\n' \
                       '|---|---|---|---|---|\n' \
                       '| [25](#/indicator/25) | http://www.example.com | URL | Good | 3 |\n' \
                       '| [24](#/indicator/24) | http://www.example.com | URL | Good | 2 |\n'


@pytest.mark.parametrize('incident_ids, indicators, expected_result', [
    (INCIDENT_IDS, INDICATORS, MD_INDICATORS_RESULT),
    ([], INDICATORS, NO_INDICATORS_FOUND),
    (INCIDENT_IDS, [{"Contents": [], 'Type': 0}], NO_INDICATORS_FOUND),
    ([], [{"Contents": [], 'Type': 0}], NO_INDICATORS_FOUND)
])
def test_get_indicators_by_incident_id(mocker, incident_ids, indicators, expected_result):
    """
    Given:
        - Campaign indicators by incident ids.

    When:
        - Running the format_result.

    Then:
        - Ensure the returned MD value as expected.
    """

    mocker.patch.object(demisto, 'executeCommand', return_value=indicators)

    indicators_res = get_indicatos_from_incidents(incident_ids)
    result = format_results(indicators_res, incident_ids)

    assert result == expected_result


def test_set_path(mocker):
    execute_command_mocker = mocker.patch.object(demisto, 'executeCommand')
    mocker.patch('GetCampaignIndicatorsByIncidentId.get_incidents_ids_from_context', return_value={})
    mocker.patch('GetCampaignIndicatorsByIncidentId.get_indicatos_from_incidents', return_value={})
    mocker.patch('GetCampaignIndicatorsByIncidentId.format_results', return_value='test')
    main()
    execute_command_mocker.assert_called_once_with('setIncident', {'campaignmutualindicators': 'test'})


def test_associate_to_current_incident(mocker):
    execute_command_mocker = mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'incident', return_value={'id': 'id'})
    associate_to_current_incident([{'value': 'indicators'}])
    execute_command_mocker.assert_called_once_with(
        'associateIndicatorsToIncident',
        {'incidentId': 'id', 'indicatorsValues': ['indicators']}
    )
