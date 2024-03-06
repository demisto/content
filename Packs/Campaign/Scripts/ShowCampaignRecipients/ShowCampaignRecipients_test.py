import demistomock as demisto
import pytest
from pytest_mock import MockerFixture
from ShowCampaignRecipients import main


INCIDENT_IDS = [{"id": '1'}, {"id": '2'}, {"id": '3'}]
DEMISTO_RESULT = [
    {
        'Contents': '[{"emailto": "example1@support.com"}, {"emailto": "example2@support.com"}, '
                    '{"emailto": "example1@support.com", "emailbcc": "example2@support.com"}, '
                    '{"emailto": "example1@support.com"}, {"emailto": "example1@support.com"}, '
                    '{"emailto": "example3@support.com"}, {"emailto": "example2@support.com", '
                    '"emailcc": "example1@support.com", "emailbcc": "example3@support.com"}]',
        'Type': 3
    }
]
EXPECTED_MD_TABLE = '|Email|Number Of Appearances|\n|---|---|\n| example1@support.com | 5 |\n| ' \
                    'example2@support.com | 3 |\n| example3@support.com | 2 |\n'


@pytest.mark.parametrize('incidents_id, execute_command_result, expected_md_result', [
    (INCIDENT_IDS, DEMISTO_RESULT, EXPECTED_MD_TABLE),
    (INCIDENT_IDS, [{'Contents': '[]', 'Type': 3}], 'No incidents found.'),
    (INCIDENT_IDS, [{'Contents': '[{}]', 'Type': 3}], 'No incident recipients found.'),
    ([], [], (
        "<div style='text-align:center; font-size:17px; padding: 15px;'>"
        "Recipients</br> <div style='font-size:20px;'>"
        " No incident recipients found.</div></div>"
    ))
])
def test_show_campaign_recipients(mocker: MockerFixture, incidents_id: list, execute_command_result: list, expected_md_result):
    """
    Given:
        - Campaign incidents.
    When:
        - Running the show campaign recipients script main function.
    Then:
        - Ensure the returned markdown result as expected.
    """
    mocker.patch.object(demisto, 'get', return_value=incidents_id)
    mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_result)
    mocker.patch.object(demisto, 'results')

    main()

    assert expected_md_result == demisto.results.call_args[0][0]['Contents']
