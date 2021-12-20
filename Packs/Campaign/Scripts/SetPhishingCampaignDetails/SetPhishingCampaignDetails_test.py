import pytest
import demistomock as demisto

import copy
from test_data.campaign_data import CAMPAIGN_INCIDENT_CONTEXT, NEW_INCIDENT_CONTEXT, \
    INCIDENTS_BY_ID
from SetPhishingCampaignDetails import EMAIL_CAMPAIGN_KEY, SetPhishingCampaignDetails

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
    EMAIL_CAMPAIGN_KEY: {
        "field_example": "field_example",
        "field_example_2": "field_example",
    },
    'NotCampaign': 'field_example'
}
EMPTY_CONTEXT = {}
CONTEXT_WITHOUT_CAMPAIGN = {'NotCampaign': 'field_example'}
CONTEXT_MOCK_CASES = [
    (CONTEXT_WITH_CAMPAIGN, CONTEXT_WITH_CAMPAIGN.get(EMAIL_CAMPAIGN_KEY)),
    (EMPTY_CONTEXT, None),
    (CONTEXT_WITHOUT_CAMPAIGN, None),
]


@pytest.mark.parametrize('context_mock, expected_results', CONTEXT_MOCK_CASES)
def get_campaign_context_from_incident(context_mock, expected_results):
    """
    Given:  context with campaign data (has EmailCampaign key) and other data
            empty context
            context without campaign data
    When:   Getting context from the original incident in order to put it in other incident
    Then:   Validate we take only the campaign data part.
    """
    test_obj = SetPhishingCampaignDetails()
    test_obj.execute_command = lambda x: context_mock
    res = test_obj.get_campaign_context_from_incident()
    assert res == expected_results


CONTEXT_COPY_CASES = [
    (CONTEXT_WITH_CAMPAIGN.get(EMAIL_CAMPAIGN_KEY),
     {'key': EMAIL_CAMPAIGN_KEY, 'value': {'field_example': 'field_example', 'field_example_2': 'field_example'}})
]


@pytest.mark.parametrize('context_mock, expected_results', CONTEXT_COPY_CASES)
def test_copy_campaign_data_to_incident(context_mock, expected_results):
    """
    Given:  context with only campaign data
    When:   adding context from the original incident to other incident
    Then:   Validate we call the set command with the correct arguments.
    """

    def _validate_execute_command_set(cmd, args):
        assert cmd == 'executeCommandAt'
        assert args['arguments'].get('key') == expected_results.get('key')
        assert args['arguments'].get('value') == expected_results.get('value')

    test_obj = SetPhishingCampaignDetails()
    test_obj.execute_command = _validate_execute_command_set
    test_obj.copy_campaign_data_to_incident(1, context_mock, False)


CONTEXT_MOCK_CASES = [
    (CONTEXT_WITH_CAMPAIGN, CONTEXT_WITH_CAMPAIGN.get(EMAIL_CAMPAIGN_KEY)),
    (EMPTY_CONTEXT, {}),
    (CONTEXT_WITHOUT_CAMPAIGN, {}),
]


@pytest.mark.parametrize('context_mock, expected', CONTEXT_MOCK_CASES)
def test_get_current_incident_campaign_data(context_mock, expected):
    """
    Given:  A context with campaign key
            An empty context
            A context without campaign key
    When:   Trying to get the incident's campaign's data to process
    Then:   Validate the extraction of the campaign's data key.
    """
    test_obj = SetPhishingCampaignDetails()
    test_obj.incident_context = context_mock
    res = test_obj.get_current_incident_campaign_data()
    assert res == expected


def test_get_similarities_from_incident():
    """
    Given:  A context with campaign key
    When:   Trying to get the incident's similarities from the campaign's data according to specific incident id
    Then:   Validate the extraction of the similarities by incidents.
    """
    test_obj = SetPhishingCampaignDetails()
    context_with_incidents = CONTEXT_WITH_CAMPAIGN[EMAIL_CAMPAIGN_KEY]
    context_with_incidents['incidents'] = INCIDENT_EXAMPLE

    test_obj.get_campaign_context_from_incident = lambda x: context_with_incidents

    incident_similarities = test_obj.get_similarities_from_incident(1)
    assert incident_similarities == {'1': 1, '2': 0.9999999999999999, '3': 0.8}


@pytest.mark.parametrize('incident_id, expected', [('2', False), ('4', True)])
def test_is_incident_new_in_campaign(incident_id, expected):
    """
    Given:  An incident id
    When:   Trying to determine if an incident is new to campaign's data
    Then:   Validate that incident is new only if it's not already in campaign's data.
    """
    test_obj = SetPhishingCampaignDetails()
    campign_with_incidents = copy.deepcopy(CONTEXT_WITH_CAMPAIGN)
    campign_with_incidents = campign_with_incidents[EMAIL_CAMPAIGN_KEY]

    res = test_obj.is_incident_new_in_campaign(incident_id, campign_with_incidents)
    assert res == expected


def test_add_current_incident_to_campaign():
    """
    Given:  An incident's campaign data
    When:   Adding new incident to campaign.
    Then:   Validate that incident is added correctly.
    """
    test_obj = SetPhishingCampaignDetails()

    campaign_with_incidents = copy.deepcopy(CAMPAIGN_INCIDENT_CONTEXT)[EMAIL_CAMPAIGN_KEY]
    current_incident = copy.deepcopy(NEW_INCIDENT_CONTEXT)[EMAIL_CAMPAIGN_KEY]

    test_obj.add_current_incident_to_campaign(current_incident, campaign_with_incidents)
    assert len(campaign_with_incidents['incidents']) == 4
    assert campaign_with_incidents['involvedIncidentsCount'] == 4


INCIDENTS_CASES = [
    (CAMPAIGN_INCIDENT_CONTEXT[EMAIL_CAMPAIGN_KEY].get('incidents'), "3")
]


@pytest.mark.parametrize('incidents, expected', INCIDENTS_CASES)
def test_get_most_updated_incident_id(incidents, expected):
    """
    Given:  An incidents' campaign's data list
    When:   Getting the most updated one
    Then:   Validate that the most updated incident is truly the latest.
    """
    test_obj = SetPhishingCampaignDetails()
    res = test_obj._get_most_updated_incident_id(incidents)
    assert res == expected


def _create_incident_list(new_incident):
    """
    Helping function to mock running after adding new incidents to campaign.
    """
    test_obj = SetPhishingCampaignDetails()
    existing_incidents = copy.deepcopy(CAMPAIGN_INCIDENT_CONTEXT[EMAIL_CAMPAIGN_KEY])
    current_incident = copy.deepcopy(new_incident[EMAIL_CAMPAIGN_KEY])
    test_obj.add_current_incident_to_campaign(current_incident, existing_incidents)
    return existing_incidents.get('incidents')


SIMILARITY_CASES = [
    (NEW_INCIDENT_CONTEXT, {'5': 1, '1': 0.99, '2': 0.98, '3': 0.85}),
]


@pytest.mark.parametrize('incident_to_add, expected', SIMILARITY_CASES)
def test_update_similarity_to_last_incident(mocker, incident_to_add, expected):
    """
    Given:  An new/older incident that was added to a new campaign
    When:   Merging the new incident data with existing campaign data and updating the similarity values
    Then:   Validate that all existing incidents have the similarity according to the most recent incident.
            If we have older incident as new (so the recent one will not have similarity for it) ,
            will take the similarity from it and update campaign with it.
    """
    test_obj = SetPhishingCampaignDetails()
    incidents = _create_incident_list(incident_to_add)

    mocker.patch.object(SetPhishingCampaignDetails, 'get_campaign_context_from_incident',
                        side_effect=lambda x: INCIDENTS_BY_ID[x][EMAIL_CAMPAIGN_KEY])
    test_obj.update_similarity_to_last_incident(incidents)
    for incident in incidents:
        assert incident.get('similarity') == expected.get(incident.get('id'))


COMPLETE_FLOW_CASES = [
    (
        '0', '3',  # case incident already in campaign (discovered through another incident already)
        [{'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '1',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T14:00:07.119800133Z',
          'recipients': ['victim-test6@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 1, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example2.com', 'id': '2',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T14:59:01.690685509Z',
          'recipients': ['victim-test1@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 0.9999999999999999, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '3',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T15:00:07.425185504Z',
          'recipients': ['victim-test7@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 3, 'similarity': 1, 'status': 1}]  # expected same campaign data as before
    ),
    (
        '0', '4',  # case new incident
        [{'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '1',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T14:00:07.119800133Z',
          'recipients': ['victim-test6@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 1, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example2.com', 'id': '2',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T14:59:01.690685509Z',
          'recipients': ['victim-test1@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 0.9999999999999999, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '3',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T15:00:07.425185504Z',
          'recipients': ['victim-test7@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 3, 'similarity': 1, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '4',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T16:00:00.119800133Z',
          'recipients': ['victim-test6@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 1, 'status': 1}]
        # expected same campaign with new similarities and one more incident.
    ),
    (
        '1', '5',  # case new (empty campaign) with a new incident.
        [{'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '5',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T15:01:07.119800133Z',
          'recipients': ['victim-test6@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 1, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '1',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T14:00:07.119800133Z',
          'recipients': ['victim-test6@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 0.99, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example2.com', 'id': '2',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T14:59:01.690685509Z',
          'recipients': ['victim-test1@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 0, 'similarity': 0.98, 'status': 1},
         {'emailfrom': 'examplesupport@example2.com', 'emailfromdomain': 'example.com', 'id': '3',
          'name': 'Verify your example account 798', 'occurred': '2021-11-21T15:00:07.425185504Z',
          'recipients': ['victim-test7@demistodev.onmicrosoft.com'], 'recipientsdomain': ['onmicrosoft.com'],
          'severity': 3, 'similarity': 0.85, 'status': 1}]
        # expected, all incidents and similarity found in incident '5'
    )

]


@pytest.mark.parametrize('campaign_id, incident_to_add_id, expected', COMPLETE_FLOW_CASES)
def test_run_flow(mocker, campaign_id, incident_to_add_id, expected):
    """
    Given:  An existing/new campaign's data and a new incident date (the current incident we are running on)
    When:   Adding the new incident to an existing/new campaign as part of the Phishing playbook
    Then:   Validate the flow itself of the context merge of incident and campaign,
            and makes sure the execute command is called with correct arguments
    """

    def _validate_execute_command_set(cmd, args):
        assert cmd == 'executeCommandAt'
        assert args['arguments'].get('key') == EMAIL_CAMPAIGN_KEY
        assert args['incidents'] == campaign_id
        assert args['command'] == 'Set'
        assert args['arguments']['value']['incidents'] == expected

    test_obj = SetPhishingCampaignDetails(execute_command=_validate_execute_command_set)
    mocker.patch.object(SetPhishingCampaignDetails, 'get_campaign_context_from_incident',
                        side_effect=lambda x: INCIDENTS_BY_ID[x].get(EMAIL_CAMPAIGN_KEY))
    mocker.patch.object(SetPhishingCampaignDetails, 'get_current_incident_campaign_data',
                        return_value=INCIDENTS_BY_ID[incident_to_add_id].get(EMAIL_CAMPAIGN_KEY))
    mocker.patch.object(demisto, 'incident', return_value={'id': incident_to_add_id})
    test_obj.run(campaign_id, False)
