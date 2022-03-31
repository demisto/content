import demistomock as demisto
import pytest

import ShowCampaignSenders


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


@pytest.mark.parametrize('execute_command_result, expected_md_result', [
    (DEMISTO_RESULT, EXPECTED_TABLE),
    ([{'Contents': '[]', 'Type': 3}], 'No incidents found.'),
    ([{'Contents': '[{}]', 'Type': 3}], 'No incident senders found.')
])
def test_show_campaign_senders(mocker, execute_command_result, expected_md_result):
    """
    Given:
        - Campaign incidents.
    When:
        - Running the show campaign senders script main function.
    Then:
        - Ensure the returned markdown result as expected.
    """
    mocker.patch.object(demisto, 'get', return_value=INCIDENT_IDS)
    mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_result)
    mocker.patch.object(ShowCampaignSenders, 'return_results')

    ShowCampaignSenders.main()
    res = ShowCampaignSenders.return_results.call_args[0][0].readable_output

    assert expected_md_result == res
