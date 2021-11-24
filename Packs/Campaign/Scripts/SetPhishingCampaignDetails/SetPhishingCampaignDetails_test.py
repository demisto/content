import pytest
import demistomock as demisto
import CommonServerPython
import copy

INCIDENT_EXAMPLE = [
    {
        "id": "1",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T14:01:02.119800133Z",
        "severity": 0,
        "similarity": 1,
        "status": 1
    },
    {
        "id": "2",
        "name": "Verify your account 2",
        "occurred": "2021-11-21T14:01:01.690685509Z",
        "severity": 0,
        "similarity": 0.9999999999999999,
        "status": 1
    },
    {
        "id": "3",
        "name": "Verify your account 3",
        "occurred": "2021-11-21T14:00:07.425185504Z",
        "severity": 3,
        "similarity": 0.8,
        "status": 1
    }
]
CONTEXT_WITH_CAMPAIGN = {
    "EmailCampaign": {
        "field_example": "field_example",
        "field_example_2": "field_example",
        "involvedIncidentsCount": 3,
        "incidents": INCIDENT_EXAMPLE
    },
    'NotCampaign': 'field_example'
}
EMPTY_CONTEXT = {}
CONTEXT_WITHOUT_CAMPAIGN = {'NotCampaign': 'field_example'}
CONTEXT_MOCK_CASES = [
    (CONTEXT_WITH_CAMPAIGN, CONTEXT_WITH_CAMPAIGN.get("EmailCampaign")),
    (EMPTY_CONTEXT, None),
    (CONTEXT_WITHOUT_CAMPAIGN, None),
]


@pytest.mark.parametrize('context_mock, expected_results', CONTEXT_MOCK_CASES)
def test_get_campaign_context(mocker, context_mock, expected_results):
    """
    Given:  context with campaign data (has EmailCampaign key) and other data
            empty context
            context without campaign data
    When:   Getting context from the original incident in order to put it in other incident
    Then:   Validate we take only the campaign data part.
    """
    from SetPhishingCampaignDetails import get_campaign_context
    mocker.patch.object(demisto, 'context', return_value=context_mock)
    res = get_campaign_context()
    assert res == expected_results


CONTEXT_COPY_CASES = [
    (CONTEXT_WITH_CAMPAIGN.get("EmailCampaign"),
     {'incidents': 1, 'command': 'Set', 'arguments':
         {'key': 'EmailCampaign', 'value': {'field_example': 'field_example', 'field_example_2': 'field_example'},
          'append': False}}),
]


@pytest.mark.parametrize('context_mock, expected_results', CONTEXT_COPY_CASES)
def test_copy_campaign_data_to_incident(mocker, context_mock, expected_results):
    """
    Given:  context with only campaign data
    When:   adding context from the original incident to other incident
    Then:   Validate we call the set command with the correct arguments.
    """
    from SetPhishingCampaignDetails import copy_campaign_data_to_incident
    execute_mock = mocker.patch.object(demisto, 'executeCommand')
    copy_campaign_data_to_incident(1, context_mock, False)
    execute_mock.assert_called_once_with('executeCommandAt', expected_results)


CONTEXT_COPY_CASES_FAILS = [
    (EMPTY_CONTEXT),
    (None)
]


@pytest.mark.parametrize('context_mock', CONTEXT_COPY_CASES_FAILS)
def test_copy_campaign_data_to_incident_fails(mocker, context_mock):
    """
        Given:  empty context
                context without campaign data
        When:   adding context from the original incident to other incident
        Then:   Validate we ignore the incident if no campaign data is found with correct error logged.
    """
    from SetPhishingCampaignDetails import copy_campaign_data_to_incident, EMAIL_CAMPAIGN_KEY
    debugging_mock = mocker.patch.object(demisto, 'debug')
    execute_mock = mocker.patch.object(demisto, 'executeCommand')
    copy_campaign_data_to_incident(1, context_mock, False)
    debugging_mock.assert_called_once_with(f'Error - {EMAIL_CAMPAIGN_KEY} was not found. Ignoring incident id: 1')
    execute_mock.assert_not_called()


def test_args(mocker):
    """
        Given:  possible arguments from client
        When:   running the automation
        Then:   Validate we get result.
    """
    import SetPhishingCampaignDetails
    mocker.patch.object(SetPhishingCampaignDetails, 'get_campaign_context')
    mocker.patch.object(SetPhishingCampaignDetails, 'copy_campaign_data_to_incident',
                        return_value={'example': 'example'})
    mocker.patch.object(demisto, 'args', return_value={'id': '1', 'append': 'false'})
    res_mocker = mocker.patch.object(demisto, 'results')

    SetPhishingCampaignDetails.main()
    res_mocker.assert_called()


###################################

from SetPhishingCampaignDetails import EMAIL_CAMPAIGN_KEY, SetPhishingCampaignDetails

CONTEXT_MOCK_CASES = [
    (CONTEXT_WITH_CAMPAIGN, CONTEXT_WITH_CAMPAIGN.get("EmailCampaign")),
    (EMPTY_CONTEXT, {}),
    (CONTEXT_WITHOUT_CAMPAIGN, {}),
]


@pytest.mark.parametrize('context_mock, expected', CONTEXT_MOCK_CASES)
def test_get_current_incident_campaign_data(context_mock, expected):
    test_obj = SetPhishingCampaignDetails()
    test_obj.incident_context = context_mock
    res = test_obj.get_current_incident_campaign_data()
    assert res == expected


def _mock_execute(cmd, _args):
    if cmd == 'getContext':
        CONTEXT_WITH_CAMPAIGN[EMAIL_CAMPAIGN_KEY] = {'incidents': INCIDENT_EXAMPLE}
        return CONTEXT_WITH_CAMPAIGN


def _mock_dt(data, search_values):
    keys = search_values.split(".")
    val = data
    for key in keys:
        val = val.get(key, {})


def test_get_similarities_from_incident():
    test_obj = SetPhishingCampaignDetails()
    context_with_incidents = CONTEXT_WITH_CAMPAIGN[EMAIL_CAMPAIGN_KEY]
    context_with_incidents['incidents'] = INCIDENT_EXAMPLE

    test_obj.get_campaign_context = lambda x: context_with_incidents

    incident_similarities = test_obj.get_similarities_from_incident(1)
    assert incident_similarities == {'1': 1, '2': 0.9999999999999999, '3': 0.8}


@pytest.mark.parametrize('incident_id, expected', [('2', False), ('4', True)])
def test_is_incident_new_in_campaign(incident_id, expected):
    test_obj = SetPhishingCampaignDetails()
    campign_with_incidents = copy.deepcopy(CONTEXT_WITH_CAMPAIGN)
    campign_with_incidents = campign_with_incidents[EMAIL_CAMPAIGN_KEY]

    res = test_obj.is_incident_new_in_campaign(incident_id, campign_with_incidents)
    assert res == expected


NEW_INCIDENT = {
    "id": "4",
    "name": "Verify your account 4",
    "occurred": "2021-11-21T16:00:07.425185504Z",
    "severity": 3,
    "similarity": 1,
    "status": 1
}

APPEND_CASES = [
    (NEW_INCIDENT, 4)
]


@pytest.mark.parametrize('new_incident_data, new_num_of_incidents', APPEND_CASES)
def test_add_current_incident_to_campaign(new_incident_data, new_num_of_incidents):
    test_obj = SetPhishingCampaignDetails()
    campaign_with_incidents = copy.deepcopy(CONTEXT_WITH_CAMPAIGN)[EMAIL_CAMPAIGN_KEY]
    current_incident = copy.deepcopy(CONTEXT_WITH_CAMPAIGN)
    current_incident = current_incident[EMAIL_CAMPAIGN_KEY]
    current_incident['incidents'].insert(0, new_incident_data)

    test_obj.add_current_incident_to_campaign(current_incident, campaign_with_incidents)
    assert len(campaign_with_incidents['incidents']) == 4
    assert campaign_with_incidents['involvedIncidentsCount'] == new_num_of_incidents

NEW_INCIDENT_CONTEXT = {EMAIL_CAMPAIGN_KEY: [
    {
        "id": "4",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T14:01:02.119800133Z",
        "severity": 0,
        "similarity": 1,
        "status": 1
    },
    {
        "id": "1",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T14:01:02.119800133Z",
        "severity": 0,
        "similarity": 0.97,
        "status": 1
    },
    {
        "id": "2",
        "name": "Verify your account 2",
        "occurred": "2021-11-21T14:01:01.690685509Z",
        "severity": 0,
        "similarity": 0.96,
        "status": 1
    },
    {
        "id": "3",
        "name": "Verify your account 3",
        "occurred": "2021-11-21T14:00:07.425185504Z",
        "severity": 3,
        "similarity": 0.8,
        "status": 1
    }
]}
CASE_NEW_INCIDENT_IS_LATEST = [
    {
        "id": "1",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T14:01:02.119800133Z",
        "similarity": 1
    },
    {
        "id": "2",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T15:01:02.119800133Z",
        "similarity": 1
    },
    {
        "id": "3",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T16:01:02.119800133Z",
        "similarity": 1
    }]

CASE_NEW_INCIDENT_IS_NOT_LATEST = [
    {
        "id": "1",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T14:01:02.119800133Z",
        "similarity": 1
    },
    {
        "id": "2",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T15:01:02.119800133Z",
        "similarity": 1
    },
    {
        "id": "3",
        "name": "Verify your account 1",
        "occurred": "2021-11-21T14:20:02.119800133Z",
        "similarity": 1
    }]

INCIDENTS_CASES = [
    (INCIDENT_EXAMPLE, "1"),
    (CASE_NEW_INCIDENT_IS_LATEST, "3"),
    (CASE_NEW_INCIDENT_IS_NOT_LATEST, "2")
]


@pytest.mark.parametrize('incidents, expected', INCIDENTS_CASES)
def test_get_most_updated_incident_id(incidents, expected):
    test_obj = SetPhishingCampaignDetails()
    res = test_obj._get_most_updated_incident_id(incidents)
    assert res == expected

@pytest.mark.parametrize('incidents, expected', INCIDENTS_CASES)
def test_update_similarity_to_last_incident(incidents, expected):
    test_obj = SetPhishingCampaignDetails()
    test_obj.update_similarity_to_last_incident(incidents)
    similarities_according_to_last_updated = self.get_similarities_from_incident(most_current_incident_id)
    for incident in campaign_incidents:
        if incident['id'] in similarities_according_to_last_updated:
            incident['similarity'] = similarities_according_to_last_updated[incident['id']]


def merge_contexts(self, current_incident_data: dict, campaign_data: dict) -> dict:
    """
    This will update the existing incident's campaign data with the rest of the campaign data,
    according to the following logic:
    If we have a new campaign, copy the all current incident's campaign context to campaign.
    If we have an existing campaign - if the current incident is new, add the new incident to the campaign.
        Also, update other campaign incident's similarity to match the new one.
    """
    if not campaign_data:
        return current_incident_data

    if self.is_incident_new_in_campaign(demisto.incident()["id"], campaign_data):
        self.add_current_incident_to_campaign(current_incident_data, campaign_data)
        self.update_similarity_to_last_incident(current_incident_data.get('incidents', []))
        return campaign_data

    else:
        return campaign_data


def copy_campaign_data_to_incident(self, incident_id: int, merged_campaign: dict, append: bool):
    args = {'key': EMAIL_CAMPAIGN_KEY, 'value': merged_campaign, 'append': append}

    res = self.execute_command(
        'executeCommandAt',
        {
            'incidents': incident_id,
            'command': 'Set',
            'arguments': args,
        }
    )
    if is_error(res):
        return_error(f"error in setting merged campaign data to incident id {incident_id}. Error: {res}")

    return res


def run(self, campaign_incident_id, append):
    if not campaign_incident_id:
        raise ValueError("Please provide Campaign incident id.")

    current_incident_campaign_data = self.get_current_incident_campaign_data()
    campaign_data = self.get_campaign_context(campaign_incident_id)
    merged_campaign = self.merge_contexts(current_incident_campaign_data, campaign_data)
    res = self.copy_campaign_data_to_incident(campaign_incident_id, merged_campaign, append)
    if res:
        demisto.results(res)
