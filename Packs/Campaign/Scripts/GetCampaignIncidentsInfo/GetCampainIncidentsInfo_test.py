from CommonServerPython import *
from GetCampaignIncidentsInfo import *
import pytest

REQUIRED_KEYS = ['id', 'name', 'emailfrom', 'recipients', 'severity', 'status', 'created']
STR_VAL_KEYS = ['name', 'emailfrom', 'recipients', 'created']

NUM_OF_INCIDENTS = 5
MOCKED_INCIDENTS = [
    {key.replace('_', ''): f'test_{key}_{i}' if key in STR_VAL_KEYS else i for key in REQUIRED_KEYS}
    for i in range(NUM_OF_INCIDENTS)
]

UPDATED_MOCKED_INCIDENTS = [
    {key.replace('_', ''): 3 if key in KEYS_FETCHED_BY_QUERY else i for key in REQUIRED_KEYS}
    for i in range(NUM_OF_INCIDENTS)
]

SOME_ERROR = 'Raised by mock of demisto.context'


def raise_exception():
    raise Exception(SOME_ERROR)


def test_incidents_info_md_happy_path(mocker):
    """

    Given:
        - Mocked incidents

    When:
        - Get the campaign incidents info

    Then:
        - Validate all required key and val are in the MD result

    """
    # prepare
    mocker.patch('GetCampaignIncidentsInfo.update_incident_with_required_keys', return_value=MOCKED_INCIDENTS)
    mocker.patch('GetCampaignIncidentsInfo.get_campaign_incidents_from_context', return_value=MOCKED_INCIDENTS)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'incidents', return_value=MOCKED_INCIDENTS)
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'context', return_value={'EmailCampaign': {'fieldsToDisplay': REQUIRED_KEYS}})
    # run
    main()
    hr = demisto.results.call_args[0][0]['HumanReadable']

    # validate required keys are header in the MD and the expected values are the table
    assert all(string_to_table_header(key) in hr for key in REQUIRED_KEYS)
    assert all(f'test_{key}_' in hr for key in STR_VAL_KEYS)
    assert all(status in hr for status in STATUS_DICT.values())
    assert all(f'[{i}](#/Details/{i})' in hr for i in range(NUM_OF_INCIDENTS))  # linkable incident id

    # validate the call to update empty fields
    args = demisto.executeCommand.call_args[0][1]
    assert args['customFields'] == DEFAULT_CUSTOM_FIELDS


def test_incidents_info_md_for_empty_context(mocker):
    """

    Given:
        - There is no campaign incidents in context

    When:
        - Get the campaign incidents info

    Then:
        - Validate return message

    """
    # prepare
    mocker.patch.object(demisto, 'results')
    mocker.patch('GetCampaignIncidentsInfo.get_campaign_incidents_from_context', return_value=[])

    # run
    main()

    # validate
    assert demisto.results.call_args[0][0]['HumanReadable'] == NO_CAMPAIGN_INCIDENTS_MSG


def test_incidents_info_md_with_invalid_keys(mocker):
    """

    Given:
        - Incidents in campaign context contains some invalid keys (e.g. status),

    When:
        -  Get value from incident (GetCampaignIncidentsInfo.get_incident_val)

    Then:
        - Validate invalid key not in the human readable

    """
    # prepare
    incident_with_invalid_status = MOCKED_INCIDENTS[4]
    incident_without_status = MOCKED_INCIDENTS[0].copy()
    incident_without_status.pop('status')
    incidents = [incident_with_invalid_status, incident_without_status]
    mocker.patch.object(demisto, 'results')
    mocker.patch('GetCampaignIncidentsInfo.get_campaign_incidents_from_context', return_value=incidents)
    mocker.patch('GetCampaignIncidentsInfo.update_incident_with_required_keys', return_value=incidents)

    # run
    main()
    hr = demisto.results.call_args[0][0]['HumanReadable']

    # validate
    assert 'Status' not in hr
    assert all(status not in hr for status in STATUS_DICT.values())


def test_some_error(mocker):
    """

    Given:
        - Dynamic section try to populate the MD from script

    When:
        - Get incident info

    Then:
        - Raise exception and validate the return_error is called

    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'context', side_effect=raise_exception)
    mocker.patch('GetCampaignIncidentsInfo.update_incident_with_required_keys')

    # run
    try:
        main()
        pytest.fail(msg='SystemExit should occurred')

    except SystemExit:
        assert demisto.results.call_args[0][0]['Contents'] == SOME_ERROR


def test_updated_status_and_severity(mocker):
    """
        Given -
            Status or severity of incidents in campaign was changed

        When -
            Get the incidents info

        Then -
            Validate the updated values is returned
    """

    # prepare
    mocker.patch.object(demisto, 'results')
    mocker.patch('GetCampaignIncidentsInfo.get_campaign_incidents_from_context', return_value=MOCKED_INCIDENTS)
    mocker.patch.object(demisto,
                        'executeCommand',
                        return_value=[{'Contents': json.dumps(UPDATED_MOCKED_INCIDENTS), 'Type': 'str'}])

    # run
    main()

    # validate
    hr = demisto.results.call_args[0][0]['HumanReadable']
    hr.count('| Archive |') == NUM_OF_INCIDENTS  # all incidents should have the 'Archive' status
    hr.count('| 3 |') == NUM_OF_INCIDENTS  # all incidents should have severity 3


def test_update_incident_with_required_keys(mocker):
    """
        Given
         - Two Phishing Campaign incidents (the first one exists, the second one is deleted)
         - The required keys

        When
         - Execute update_incident_with_required_keys function

        Then
         - Ensure the function returns just the exists incident and does not fail

    """
    incident_1 = {"emailfrom": "", "emailfromdomain": "", "id": "1", "name": "Campaign Test",
                  "occurred": "2023-06-21T13:18:38.056972974Z", "recipients": [], "recipientsdomain": [],
                  "severity": 0, "similarity": 1, "status": 1}
    incident_2 = {"emailfrom": "", "emailfromdomain": "", "id": "2", "name": "Campaign Test",
                  "occurred": "2023-06-21T13:18:38.056972974Z", "recipients": [], "recipientsdomain": [],
                  "severity": 0, "similarity": 1, "status": 1}

    incident_1_correct_format = '[{"emailfrom": "","emailfromdomain": "","id": "1", "name": "Campaign Test",' \
                                ' "occurred": "2023-06-21T13:18:38.056972974Z","recipients": [], "recipientsdomain": [],' \
                                ' "severity": 0, "similarity": 1, "status": 1}]'

    incidents = [incident_1, incident_2]

    mocker.patch("demistomock.executeCommand", side_effect=([{"Contents": "[Test]"}], [{"Contents": "[]"}],
                                                            [{"Type": "Test", "Contents": incident_1_correct_format}]))
    incidents = update_incident_with_required_keys(incidents, KEYS_FETCHED_BY_QUERY)

    assert len(incidents) == 1
    assert incidents[0].get('id') == '1'
