from MicrosoftApiModule import MicrosoftClient
from AzureSentinel import Client
import requests_mock
import pytest


@requests_mock.Mocker()
def mock_client(requests_mock):
    requests_mock.post(f'https://login.microsoftonline.com/common/oauth2/token',  # disable-secrets-detection
                       json={'access_token': 'mocked_access_token'})
    client = Client(
        self_deployed=False,
        refresh_token='refresh_token',
        auth_and_token_url='auth_id',
        enc_key='enc_key',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        workspace_name='workspaceName',
        verify=False,
        proxy=False
    )
    return client


API_VERSION = '2019-01-01-preview'

CLIENT = mock_client()

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


@pytest.mark.parametrize('args,url_to_mock', [  # disable-secrets-detection
    ({'limit': '1'},
     CLIENT.base_url + f'/incidents?$top=1&$orderby=properties/'  # disable-secrets-detection
     f'createdTimeUtc asc&api-version={API_VERSION}'),  # disable-secrets-detection
    ({'limit': '1', 'next_link': 'https://test.com'}, 'https://test.com')
])
def test_list_incidents(args, url_to_mock, requests_mock, mocker):
    from AzureSentinel import list_incidents_command

    mocker.patch.object(MicrosoftClient, 'get_access_token', return_value='fake_token')
    requests_mock.get(url_to_mock, json=MOCKED_INCIDENTS_OUTPUT)

    readable_output, outputs, result = list_incidents_command(CLIENT, args=args)
    next_link = outputs['AzureSentinel.NextLink(val.Description == "NextLink for listing commands")']['URL']
    context = outputs['AzureSentinel.Incident(val.ID === obj.ID)'][0]

    assert 'Incidents List (1 results)' in readable_output
    assert context['ID'] == 'inc_name', 'Incident name in Azure Sentinel API is Incident ID in Demisto'
    assert context['FirstActivityTimeUTC'] == '2020-02-02T14:05:01Z', 'Dates are formatted to %Y-%m-%dT%H:%M:%SZ'
    assert context['AlertsCount'] == 1
    assert next_link == 'https://test.com'
    assert len(result['value']) == 1


@pytest.mark.parametrize('args,url_to_mock', [  # disable-secrets-detection
    ({'incident_id': 'inc_id', 'limit': '1'},
     CLIENT.base_url + f'/incidents/inc_id/relations?$top=1&api-version={API_VERSION}'),  # disable-secrets-detection
    ({'incident_id': 'inc_id', 'next_link': 'https://test.com', 'limit': '1'}, 'https://test.com')
])
def test_list_incident_relations_command(args, url_to_mock, requests_mock, mocker):
    from AzureSentinel import list_incident_relations_command

    mocker.patch.object(MicrosoftClient, 'get_access_token', return_value='fake_token')
    requests_mock.get(url_to_mock, json=MOCKED_RELATIONS_OUTPUT)

    readable_output, outputs, result = list_incident_relations_command(CLIENT, args=args)
    next_link = outputs['AzureSentinel.NextLink(val.Description == "NextLink for listing commands")']['URL']
    context = outputs['AzureSentinel.IncidentRelatedResource(val.ID === obj.ID && val.IncidentID == inc_id)'][0]

    assert 'Incident inc_id Relations (1 results)' in readable_output
    assert context['ID'] == 'resource_name', 'Recource name in Azure Sentinel API is Recource ID in Demisto'
    assert context['Kind'] == 'SecurityAlert'
    assert context['IncidentID'] == 'inc_id'
    assert next_link == 'https://test.com'
    assert len(result['value']) == 1


def test_incident_add_comment_command(mocker, requests_mock):
    from AzureSentinel import incident_add_comment_command
    import random

    mocker.patch.object(MicrosoftClient, 'get_access_token', return_value='fake_token')
    mocker.patch.object(random, 'getrandbits', return_value=1234)
    requests_mock.put(CLIENT.base_url + f'/incidents/inc_id/comments/1234?api-version={API_VERSION}',
                      json=MOCKED_ADD_COMMENT_OUTPUT)

    args = {'incident_id': 'inc_id', 'message': 'test_message'}
    readable_output, outputs, _ = incident_add_comment_command(CLIENT, args=args)
    context = outputs['AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === inc_id)']

    assert 'Incident inc_id new comment details' in readable_output
    assert context['ID'] == '1234', 'Comment IDs are generated by random.getrandbits()'
    assert context['Message'] == 'test_message'
    assert context['AuthorEmail'] == 'test@demisto.com'
    assert context['IncidentID'] == 'inc_id'
