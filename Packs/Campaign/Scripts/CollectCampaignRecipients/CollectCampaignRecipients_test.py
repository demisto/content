
import pytest
from CollectCampaignRecipients import *
from CommonServerPython import *

KEYS = ['id', 'name', 'recipients', 'severity', 'status', 'created']
NUM_OF_INCIDENTS = 5
MOCKED_INCIDENTS = [
    {
        key:
        f'test_{key}_{i}' if key != 'recipients' else [f'recip_{i}@test_1.com', f'recip_{i}@test_2.com']
        for key in KEYS
    } for i in range(NUM_OF_INCIDENTS)
]

SOME_ERROR = 'Raised by mock of demisto.context'


def prepare(mocker):
    mocker.patch.object(demisto, 'executeCommand')


SELECTED_IDS = (([], 0),
                (['test_id_0', 'test_id_1', 'test_id_2'], 3),
                ('All', NUM_OF_INCIDENTS))


@pytest.mark.parametrize('selected_ids, num_of_selected_ids', SELECTED_IDS)
def test_collect_campaign_recipients(mocker, selected_ids, num_of_selected_ids):
    """

    Given:
        - Mocked incidents

    When:
        - Collect campaign recipients

    Then:
        - Validate the recipients was returned

    """

    # prepare
    prepare(mocker)
    mocker.patch.object(demisto, 'args', return_value={'new': selected_ids})
    mocker.patch.object(demisto, 'incidents', return_value=[MOCKED_INCIDENTS[0]])
    mocker.patch('CollectCampaignRecipients.get_campaign_incidents', return_value=MOCKED_INCIDENTS)

    # run
    main()

    # validate
    command_args = demisto.executeCommand.call_args[0][1]
    recipients = demisto.get(command_args, 'customFields.campaignemailto')
    len(recipients.split(',')) == 2 * num_of_selected_ids  # 2 recipients for each incident
    assert all(f'recip_{i}@test_1.com' in recipients for i in range(num_of_selected_ids))
    assert all(f'recip_{i}@test_2.com' in recipients for i in range(num_of_selected_ids))


def test_collect_campaign_recipients_no_demisto_args(mocker):
    """

    Given:
        - Mocked incidents

    When:
        - Collect campaign recipients

    Then:
        - Validate the recipients was returned

    """

    # prepare
    prepare(mocker)
    mocker.patch.object(demisto, 'args', return_value={})  # without the required arg 'new'

    # run
    try:
        main()
        assert False, 'SystemExit should occurred as return_error was called'
    except SystemExit:
        pass  # expected
