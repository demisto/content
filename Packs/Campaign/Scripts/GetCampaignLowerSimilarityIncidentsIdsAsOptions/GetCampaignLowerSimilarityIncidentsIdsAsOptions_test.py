from GetCampaignLowerSimilarityIncidentsIdsAsOptions import *
import GetCampaignLowerSimilarityIncidentsIdsAsOptions

REQUIRED_KEYS = ['id', 'name', 'email_from', 'recipients', 'severity', 'status', 'created']
STR_VAL_KEYS = ['name', 'email_from', 'recipients', 'created']

NUM_OF_INCIDENTS = 5
MOCKED_INCIDENTS = [
    {key.replace('_', ''): f'test_{key}_{i}' if key in STR_VAL_KEYS else i for key in REQUIRED_KEYS}
    for i in range(NUM_OF_INCIDENTS, 0, -1)
]


def test_get_incident_ids_as_options_happy_path(mocker):
    """

    Given:
        - The "Select Incidents" multi select field try to populate the available ids

    When:
        - Get the incident ids as option for info

    Then:
        - Validate the ids returned as options format for multi select field and are sorted numerically

    """
    # prepare
    mocker.patch.object(demisto, 'results')
    mocker.patch('GetCampaignLowerSimilarityIncidentsIdsAsOptions.get_campaign_incidents', return_value=MOCKED_INCIDENTS)

    # run
    GetCampaignLowerSimilarityIncidentsIdsAsOptions.main()

    # validate
    options_dict = demisto.results.call_args[0][0]
    ids = options_dict['options']
    hidden = options_dict['hidden']

    MOCKED_INCIDENTS.sort(key=lambda incident: incident['id'])  # the original order was descending

    assert hidden is False
    assert ids.pop(0) == ALL_OPTION
    for i in range(NUM_OF_INCIDENTS):
        incident_id = str(MOCKED_INCIDENTS[i]['id'])
        assert incident_id == ids[i]


def test_get_ids_where_no_campaign_incidents_exist(mocker):
    """

    Given -
        There is no campaign in the context

    When -
        Try to get the incident ids

    Then -
        Validate the options in the result is empty

    """

    # prepare
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('GetCampaignLowerSimilarityIncidentsIdsAsOptions.get_campaign_incidents', return_value={})

    # run
    GetCampaignLowerSimilarityIncidentsIdsAsOptions.main()

    # validate
    assert demisto.results.call_args[0][0] == NO_CAMPAIGN_INCIDENTS_MSG


def test_there_is_no_id_in_incident(mocker):
    """
    Given -
        Incident in campaign in context doesn't have id

    When -
        Try to get the ids for the multi select field

    Then -
        Validate the error result as expected

    """

    # prepare
    mocker.patch.object(demisto, 'results')
    no_ids_incidents = [{'name': f'test_{i}' for i in range(NUM_OF_INCIDENTS)}]
    mocker.patch('GetCampaignLowerSimilarityIncidentsIdsAsOptions.get_campaign_incidents', return_value=no_ids_incidents)

    # run
    try:
        GetCampaignLowerSimilarityIncidentsIdsAsOptions.main()
        assert False
    except SystemExit:
        assert demisto.results.call_args[0][0]['Contents'] == NO_ID_IN_CONTEXT
