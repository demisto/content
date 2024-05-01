import demistomock as demisto
import pytest
from pytest_mock import MockerFixture
from ShowCampaignSenders import main


INCIDENT_IDS = [{"id": '1'}, {"id": '2'}, {"id": '3'}]
DEMISTO_RESULT = [
    {
        'Contents': '[{"emailfrom": "example1@support.com"}, {"emailfrom": "example2@support.co"}, '
                    '{"emailfrom": "example1@support.com"}, {"emailfrom": "example1@support.com"},'
                    '{"emailfrom": "example1@support.com"}, {"emailfrom": "example3@support.co"},'
                    '{"emailfrom": "example2@support.co"}]',
        'Type': 3
    }
]
EXPECTED_TABLE = '|Email|Number Of Appearances|\n|---|---|\n| example1@support.com | 4 |\n| ' \
                 'example2@support.co | 2 |\n| example3@support.co | 1 |\n'


@pytest.mark.parametrize('incidents_id, execute_command_result, expected_md_result', [
    (INCIDENT_IDS, DEMISTO_RESULT, EXPECTED_TABLE),
    (INCIDENT_IDS, [{'Contents': '[]', 'Type': 3}], 'No incidents found.'),
    (INCIDENT_IDS, [{'Contents': '[{}]', 'Type': 3}], 'No incident senders found.'),
    ([], [], (
        "<div style='text-align:center; font-size:17px; padding: 15px;'>Senders"
        "</br> <div style='font-size:20px;'> No incident senders found.</div></div>"
    ))
])
def test_show_campaign_senders(mocker: MockerFixture, incidents_id: list, execute_command_result: list, expected_md_result):
    """
    Given:
        - Campaign incidents.
    When:
        - Running the show campaign senders script main function.
    Then:
        - Ensure the returned markdown result as expected.
    """
    mocker.patch.object(demisto, 'get', return_value=incidents_id)
    mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_result)
    mocker.patch.object(demisto, 'results')

    main()

    assert expected_md_result == demisto.results.call_args[0][0]['Contents']
