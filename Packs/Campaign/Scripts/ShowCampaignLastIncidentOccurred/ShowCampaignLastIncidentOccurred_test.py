import demistomock as demisto
import pytest

import ShowCampaignLastIncidentOccurred


INCIDENT_IDS = [{"id": '1'}, {"id": '2'}, {"id": '3'}]
MULTIPLE_INCIDENT_CREATED = [
    {
        'Contents': '[{"created": "2021-07-27T15:09:35.269187268Z"}, {"created": "2021-07-28T15:06:33.100736309Z"}, \
                      {"created": "2021-07-29T14:42:38.945010982Z"}, {"created": "2021-07-29T14:09:22.708160443Z"}]',
        'Type': 3
    }
]
ONE_INCIDENT_CREATED = [
    {
        'Contents': '[{"created": "2021-07-28T15:06:33.100736309Z"}]',
        'Type': 3
    }
]


@pytest.mark.parametrize('incident_created, expected_result, pixels', [
    (MULTIPLE_INCIDENT_CREATED, 'July 29, 2021', '24'),
    (ONE_INCIDENT_CREATED, 'July 28, 2021', '24'),
    ([{'Contents': '[]', 'Type': 3}], 'No last incident occurred found.', '20')
])
def test_show_last_incident_occurred(mocker, incident_created, expected_result, pixels):
    """
    Given:
        - Campaign incidents.
    When:
        - Running the show last incident occurred script main function.
    Then:
        - Ensure the correct last incident occurred is appear in the html format.
    """
    mocker.patch.object(demisto, 'get', return_value=INCIDENT_IDS)
    mocker.patch.object(demisto, 'executeCommand', return_value=incident_created)
    mocker.patch.object(demisto, 'results')

    ShowCampaignLastIncidentOccurred.main()

    res = demisto.results.call_args[0][0]['Contents']
    expected_result = f"<div style='text-align:center; font-size:17px; padding: 15px;'>Last Incident Occurred</br> " \
                      f"<div style='font-size:{pixels}px;'> {expected_result} </div></div>"

    assert expected_result == res
