from demisto_sdk.commands.init.templates.AzureSentinel.AzureSentinel import Client, list_incidents_command, \
    list_incident_relations_command, incident_add_comment_command
import requests_mock
import random
import pytest


@requests_mock.Mocker()
def mock_client(requests_mock):
    requests_mock.post(f'https://login.microsoftonline.com/{CLIENT.tenant_id}/oauth2/token',
                       json={'access_token': 'mocked_access_token'})
    client = Client(
        url='https://management.azure.com',
        tenant_id='mocked_tenant_id',
        client_id='mocked_client_id',
        client_secret='mocked_client_secret',
        auth_code='mocked_auth_code',
        subscription_id='mocked_subscription_id',
        resource_group_name='mocked_resource_group',
        workspace_name='mocked_workspace',
        verify=True,
        proxy=False
    )
    return client


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

LIST_INCIDENTS_NEXT_LINK = None

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
        'autor': {
            'email': 'test@demisto.com',
            'name': 'test_name',
        },
        'message': 'test_message'
    }
}


@pytest.mark.parametrize('args,url_to_mock', [
    ({'top': '1'}, CLIENT.base_url + '/incidents'),
    ({'next_link': LIST_INCIDENTS_NEXT_LINK}, LIST_INCIDENTS_NEXT_LINK)
])
def test_list_incidents(args, url_to_mock, requests_mock):
    requests_mock.get(url_to_mock, json=MOCKED_INCIDENTS_OUTPUT)

    readable_output, outputs, result = list_incidents_command(CLIENT, args=args)

    assert 'Incidents List (1 results)' in readable_output

    next_link = outputs['AzureSentinel.NextLink']
    context = outputs['AzureSentinel.Incident(val.ID === obj.ID)']
    assert context['ID'] == MOCKED_INCIDENTS_OUTPUT['value'][0]['name']
    assert context['FirstActivityTimeUtc'] == MOCKED_INCIDENTS_OUTPUT['value'][0]['properties']['firstActivityTimeUtc']
    assert context['AlertsCount'] == MOCKED_INCIDENTS_OUTPUT['value'][0]['name']
    assert next_link == 'https://test.com'

    assert len(result['value']) == 1

    global LIST_INCIDENTS_NEXT_LINK
    LIST_INCIDENTS_NEXT_LINK = next_link  # for second iteration


@pytest.mark.parametrize('args,url_to_mock', [
    ({'incident_id': 'inc_id', 'top': '1'}, CLIENT.base_url + 'incidents/inc_id/relations'),
    ({'next_link': LIST_RELATIONS_NEXT_LINK}, LIST_RELATIONS_NEXT_LINK)
])
def test_list_incident_relations_command(args, url_to_mock, requests_mock):
    requests_mock.get(url_to_mock, json=MOCKED_RELATIONS_OUTPUT)

    readable_output, outputs, result = list_incident_relations_command(CLIENT, args=args)

    assert 'Incident inc_id Relations (1 results)' in readable_output

    next_link = outputs['AzureSentinel.NextLink']
    context = outputs['AzureSentinel.IncidentRelatedResource(val.ID === obj.ID && val.IncidentID == inc_id)']
    assert context['ID'] == MOCKED_INCIDENTS_OUTPUT['value'][0]['properties']['relatedResourceName']
    assert context['Kind'] == MOCKED_INCIDENTS_OUTPUT['value'][0]['properties']['relatedResourceKind']
    assert context['IncidentID'] == 'inc_id'

    assert len(result['value']) == 1

    global LIST_RELATIONS_NEXT_LINK
    LIST_RELATIONS_NEXT_LINK = next_link  # for second iteration


def test_incident_add_comment_command(mocker, requests_mock):
    mocker.patch.object(random, 'getrandbits', return_value=1234)
    requests_mock.put('incidents/inc_id/comments/comment_id', json=MOCKED_RELATIONS_OUTPUT)

    args = {'incident_id': 'inc_id', 'message': 'test_message'}
    readable_output, outputs, _ = incident_add_comment_command(CLIENT, args=args)

    assert 'Incident inc_id Relations (1 results)' in readable_output

    context = outputs['AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === inc_id)']
    assert context['ID'] == MOCKED_ADD_COMMENT_OUTPUT['name']
    assert context['Message'] == MOCKED_ADD_COMMENT_OUTPUT['properties']['message']
    assert context['AuthorEmail'] == MOCKED_ADD_COMMENT_OUTPUT['properties']['author']['email']
    assert context['IncidentID'] == 'inc_id'
