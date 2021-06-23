import pytest

from AzureSentinel import Client, list_incidents_command, list_incident_relations_command, incident_add_comment_command, \
    get_update_incident_request_data


def mock_client(self_deployed):
    client = Client(
        self_deployed=self_deployed,
        refresh_token='refresh_token',
        auth_and_token_url='auth_id',
        redirect_uri='redirect_uri',
        enc_key='enc_key',
        auth_code='auth_code',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        workspace_name='workspaceName',
        verify=False,
        proxy=False
    )
    return client


API_VERSION = '2019-01-01-preview'

MOCKED_INCIDENTS_OUTPUT = {
    'value': [{
        'name': 'inc_name',
        'properties': {
            'incidentNumber': 1,
            'title': 'title',
            'description': 'desc',
            'severity': 'High',
            'status': 'New',
            'owner': {
                'assignedTo': 'bla',
                'email': 'bla',
            },
            'labels': [{
                'name': 'label_name',
                'type': 'label_type'
            }],
            'firstActivityTimeUtc': '2020-02-02T14:05:01.5348545Z',
            'lastActivityTimeUtc': '2020-02-02T14:05:01.5348545Z',
            'lastModifiedTimeUtc': '2020-02-02T14:05:01.5348545Z',
            'createdTimeUtc': '2020-02-02T14:05:01.5348545Z',
            'additionalData': {
                'alertsCount': 1,
                'bookmarksCount': 2,
                'commentsCount': 3,
                'alertProductNames': ['name1', 'name2'],
                'tactics': ['tactic']
            },
            'firstActivityTimeGenerated': '2020-02-02T14:05:01.5348545Z',
            'lastActivityTimeGenerated': '2020-02-02T14:05:01.5348545Z'
        }
    }],
    'nextLink': 'https://test.com'
}

MOCKED_RELATIONS_OUTPUT = {
    'value': [{
        'name': 'inc_id_resource_name',
        'properties': {
            'relatedResourceName': 'resource_name',
            'relatedResourceKind': 'SecurityAlert'
        }
    }],
    'nextLink': 'https://test.com'
}

LIST_RELATIONS_NEXT_LINK = None

MOCKED_ADD_COMMENT_OUTPUT = {
    'name': '1234',
    'properties': {
        'author': {
            'email': 'test@demisto.com',
            'name': 'test_name',
        },
        'message': 'test_message'
    }
}


@pytest.mark.parametrize('args,client', [  # disable-secrets-detection
    ({'limit': '1'}, mock_client(self_deployed=False)),
    ({'limit': '1', 'next_link': 'https://test.com'}, mock_client(self_deployed=True))
])
def test_list_incidents(args, client, mocker):
    mocker.patch.object(client, 'http_request', return_value=MOCKED_INCIDENTS_OUTPUT)

    readable_output, outputs, result = list_incidents_command(client, args=args)
    next_link = outputs['AzureSentinel.NextLink(val.Description == "NextLink for listing commands")']['URL']
    context = outputs['AzureSentinel.Incident(val.ID === obj.ID)'][0]

    assert 'Incidents List (1 results)' in readable_output
    assert context['ID'] == 'inc_name', 'Incident name in Azure Sentinel API is Incident ID in Demisto'
    assert context['FirstActivityTimeUTC'] == '2020-02-02T14:05:01Z', 'Dates are formatted to %Y-%m-%dT%H:%M:%SZ'
    assert context['AlertsCount'] == 1
    assert next_link == 'https://test.com'
    assert len(result['value']) == 1


@pytest.mark.parametrize('args,client', [  # disable-secrets-detection
    ({'incident_id': 'inc_id', 'limit': '1'}, mock_client(self_deployed=False)),
    ({'incident_id': 'inc_id', 'next_link': 'https://test.com', 'limit': '1'}, mock_client(self_deployed=True)),
])
def test_list_incident_relations_command(args, client, mocker):
    mocker.patch.object(client, 'http_request', return_value=MOCKED_RELATIONS_OUTPUT)

    readable_output, outputs, result = list_incident_relations_command(client, args=args)
    next_link = outputs['AzureSentinel.NextLink(val.Description == "NextLink for listing commands")']['URL']
    context = outputs['AzureSentinel.IncidentRelatedResource(val.ID === obj.ID && val.IncidentID == inc_id)'][0]

    assert 'Incident inc_id Relations (1 results)' in readable_output
    assert context['ID'] == 'resource_name', 'Recource name in Azure Sentinel API is Recource ID in Demisto'
    assert context['Kind'] == 'SecurityAlert'
    assert context['IncidentID'] == 'inc_id'
    assert next_link == 'https://test.com'
    assert len(result['value']) == 1


@pytest.mark.parametrize('args,client', [  # disable-secrets-detection
    ({'incident_id': 'inc_id', 'message': 'test_message'}, mock_client(self_deployed=False))])
def test_incident_add_comment_command(args, client, mocker):
    import random

    mocker.patch.object(random, 'getrandbits', return_value=1234)
    mocker.patch.object(client, 'http_request', return_value=MOCKED_ADD_COMMENT_OUTPUT)

    args = {'incident_id': 'inc_id', 'message': 'test_message'}
    readable_output, outputs, _ = incident_add_comment_command(client, args=args)
    context = outputs['AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === inc_id)']

    assert 'Incident inc_id new comment details' in readable_output
    assert context['ID'] == '1234', 'Comment IDs are generated by random.getrandbits()'
    assert context['Message'] == 'test_message'
    assert context['AuthorEmail'] == 'test@demisto.com'
    assert context['IncidentID'] == 'inc_id'


MOCKED_UPDATE_INCIDENT = {
    'id': '1',
    'name': '8a44b7bb-c8ae-0000-0000-000000000', 'etag': '"0000000-0000-0000-0000-00000000"',
    'type': 'Microsoft.SecurityInsights/Incidents',
    'properties': {'title': 'dummy title',
                   'description': 'i am a sample description',
                   'severity': 'Informational', 'status': 'New',
                   'owner': {'objectId': None, 'email': 'alice@example.com',
                             'assignedTo': None,
                             'userPrincipalName': None},
                   'labels': [{'labelName': 'label_start', 'labelType': 'User'}],
                   'lastModifiedTimeUtc': '2021-05-24T14:57:40.4174809Z',
                   'createdTimeUtc': '2020-01-15T09:29:00.0000000Z', 'incidentNumber': 2,
                   'additionalData': {'alertsCount': 1, 'bookmarksCount': 0, 'commentsCount': 1,
                                      'alertProductNames': ['Azure Sentinel'], 'tactics': []},
                   'relatedAnalyticRuleIds': [],
                   'incidentUrl': 'https://example.com',
                   'providerName': 'Azure Sentinel', 'providerIncidentId': '2'}}


@pytest.mark.parametrize('args,client', [  # disable-secrets-detection
    ({'labels': ['label_after_1', 'label_after_2'],
      'assignee_email': 'bob@example.com'},
     mock_client(self_deployed=False))])
def test_update_incident(args, client, mocker):
    mocker.patch.object(client, 'http_request', return_value=MOCKED_UPDATE_INCIDENT)

    incident_data = get_update_incident_request_data(client, args)
    properties = incident_data['properties']

    assert properties['labels'] == [{'labelName': 'label_after_1', 'labelType': 'User'},
                                    {'labelName': 'label_after_2', 'labelType': 'User'}]
    assert properties['owner']['email'] == 'bob@example.com'
