import demistomock as demisto
import pytest

import ShowCampaignRecipients


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


@pytest.mark.parametrize('execute_command_result, expected_md_result', [
    (DEMISTO_RESULT, EXPECTED_MD_TABLE),
    ([{'Contents': '[]', 'Type': 3}], 'No incidents found.'),
    ([{'Contents': '[{}]', 'Type': 3}], 'No incident recipients found.')
])
def test_show_campaign_recipients(mocker, execute_command_result, expected_md_result):
    """
    Given:
        - Campaign incidents.
    When:
        - Running the show campaign recipients script main function.
    Then:
        - Ensure the returned markdown result as expected.
    """
    mocker.patch.object(demisto, 'get', return_value=INCIDENT_IDS)
    mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_result)
    mocker.patch.object(ShowCampaignRecipients, 'return_results')

    ShowCampaignRecipients.main()
    res = ShowCampaignRecipients.return_results.call_args[0][0].readable_output

    assert expected_md_result == res
