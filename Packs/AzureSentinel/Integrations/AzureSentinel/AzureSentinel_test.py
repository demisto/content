import json

import pytest
import requests
import demistomock as demisto

from AzureSentinel import AzureSentinelClient, list_incidents_command, list_incident_relations_command, \
    incident_add_comment_command, \
    get_update_incident_request_data, list_incident_entities_command, list_incident_comments_command, \
    list_incident_alerts_command, list_watchlists_command, \
    delete_watchlist_command, list_watchlist_items_command, \
    create_update_watchlist_command, create_update_watchlist_item_command, delete_watchlist_item_command, \
    delete_incident_command, XSOAR_USER_AGENT, incident_delete_comment_command

TEST_ITEM_ID = 'test_watchlist_item_id_1'

NEXT_LINK_CONTEXT_KEY = 'AzureSentinel.NextLink(val.Description == "NextLink for listing commands")'


def mock_client():
    client = AzureSentinelClient(
        server_url='server_url',
        tenant_id='tenant_id',
        client_id='client_id',
        client_secret='client_secret',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        workspace_name='workspaceName',
        verify=False,
        proxy=False
    )

    return client


def mock_404_response(resource_id: str):
    res = requests.Response()
    res.status_code = 404
    res._content = json.dumps({'error': {'code': 'NotFound', 'message': f"Resource '{resource_id}' does not exist"}}).encode()
    return res


TEST_INCIDENT_ID = 'test_incident_id'
TEST_WATCHLIST_ALIAS = 'test_watchlist_id_1'
INCIDENT_ELEMENTS_CONTEXT_KEY = '{context_prefix}(val.ID === obj.ID && val.IncidentId == obj.IncidentId)'
ALERTS_CONTEXT_KEY = INCIDENT_ELEMENTS_CONTEXT_KEY.format(context_prefix='AzureSentinel.IncidentAlert')
ENTITIES_CONTEXT_KEY = INCIDENT_ELEMENTS_CONTEXT_KEY.format(context_prefix='AzureSentinel.IncidentEntity')

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
    }]
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

MOCKED_INCIDENT_ENTITIES = {
    "entities": [
        {
            'id': 'test_id_1',
            'name': 'test_entity_name_1',
            "kind": "Account",
            "properties": {
                "accountName": "test_1",
                "displayName": "Test User 1",
                "friendlyName": "Test User 1"
            }
        },
        {
            'id': 'test_id_2',
            'name': 'test_entity_name_2',
            "kind": "Account",
            "properties": {
                "accountName": "test_2",
                "displayName": "Test User 2",
                "friendlyName": "Test User 2"
            }
        }
    ]
}

MOCKED_INCIDENT_ALERTS = {
    "value": [
        {
            "id": "test_alert_id_1",
            "name": "test_alert_id_1",
            "kind": "SecurityAlert",
            "properties": {
                "systemAlertId": "test_alert_id_1",
                "tactics": [
                    "InitialAccess",
                    "Persistence",
                    "PrivilegeEscalation",
                    "DefenseEvasion",
                    "CredentialAccess",
                    "Discovery",
                    "LateralMovement",
                    "Execution",
                    "Collection",
                    "Exfiltration",
                    "CommandAndControl",
                    "Impact"
                ],
                "alertDisplayName": "Test alert 1",
                "description": "Test description",
                "severity": "Medium",
                "confidenceLevel": "Unknown",
                "vendorName": "Microsoft",
                "productName": "Azure Sentinel",
                "productComponentName": "Scheduled Alerts",
                "status": "New",
                "endTimeUtc": "2021-08-12T01:48:03.4349774Z",
                "startTimeUtc": "2021-08-11T01:48:03.4349774Z",
                "timeGenerated": "2021-08-12T01:53:07.3071703Z",
                "friendlyName": "Test alert 1"
            }
        },
        {
            "id": "test_alert_id_2",
            "name": "test_alert_id_2",
            "kind": "SecurityAlert",
            "properties": {
                "systemAlertId": "test_alert_id_2",
                "tactics": [
                    "InitialAccess",
                    "Persistence",
                    "PrivilegeEscalation",
                    "DefenseEvasion",
                    "CredentialAccess",
                    "Discovery",
                    "LateralMovement",
                    "Execution",
                    "Collection",
                    "Exfiltration",
                    "CommandAndControl",
                    "Impact"
                ],
                "alertDisplayName": "Test alert 2",
                "description": "Test description",
                "confidenceLevel": "Unknown",
                "severity": "Medium",
                "vendorName": "Microsoft",
                "productName": "Azure Sentinel",
                "productComponentName": "Scheduled Alerts",
                "status": "New",
                "endTimeUtc": "2021-08-12T01:48:03.4349774Z",
                "startTimeUtc": "2021-08-11T01:48:03.4349774Z",
                "timeGenerated": "2021-08-12T01:53:07.3071703Z",
                "friendlyName": "Test alert 2"
            }
        }
    ]
}

MOCKED_WATCHLISTS = {
    "value": [
        {
            "id": "test_watchlist_id_1",
            "name": "test_watchlist_name_1",
            "properties": {
                "watchlistId": "test_watchlist_id_1",
                "displayName": "test_watchlist_name_1",
                "provider": "test_provider",
                "source": "Local file",
                "itemsSearchKey": "IP",
                "created": "2021-07-11T08:20:35.8964775+00:00",
                "updated": "2021-07-11T08:20:35.8964775+00:00",
                "createdBy": {
                    "email": "test@demisto.com",
                    "name": "test_user"
                },
                "updatedBy": {
                    "email": "test@demisto.com",
                    "name": "test_user"
                },
                "description": "test_description",
                "watchlistType": "watchlist",
                "watchlistAlias": "test_watchlist_id_1",
                "labels": [
                    "IP"
                ],
                "numberOfLinesToSkip": 0,
                "uploadStatus": "Complete"
            }
        },
        {
            "id": "test_watchlist_id_2",
            "name": "test_watchlist_name_2",
            "properties": {
                "watchlistId": "test_watchlist_id_2",
                "displayName": "test_watchlist_name_2",
                "provider": "test_provider",
                "source": "Local file",
                "itemsSearchKey": "IP",
                "created": "2021-07-11T08:20:35.8964775+00:00",
                "updated": "2021-07-11T08:20:35.8964775+00:00",
                "createdBy": {
                    "email": "test@demisto.com",
                    "name": "test_user"
                },
                "updatedBy": {
                    "email": "test@demisto.com",
                    "name": "test_user"
                },
                "description": "test_description",
                "watchlistType": "watchlist",
                "watchlistAlias": "test_watchlist_id_2",
                "labels": [
                    "IP"
                ],
                "numberOfLinesToSkip": 0,
                "uploadStatus": "Complete"
            }
        }
    ]
}

MOCKED_WATCHLIST_ITEMS = {
    "value": [
        {
            "id": "test_watchlist_item_id_1",
            "name": "test_watchlist_item_name_1",
            "properties": {
                "watchlistItemId": "test_watchlist_item_id_1",
                "created": "2021-08-15T14:14:28.7803449+00:00",
                "updated": "2021-08-15T14:14:28.7803449+00:00",
                "createdBy": {
                    "name": "User 1"
                },
                "updatedBy": {
                    "name": "User 2"
                },
                "itemsKeyValue": {
                    "name": "test1",
                    "IP": "1.1.1.1"
                }
            }
        },
        {
            "id": "test_watchlist_item_id_2",
            "name": "test_watchlist_item_name_2",
            "properties": {
                "watchlistItemId": "test_watchlist_item_id_2",
                "created": "2021-08-15T14:14:28.7803449+00:00",
                "updated": "2021-08-15T14:14:28.7803449+00:00",
                "createdBy": {
                    "name": "User 3"
                },
                "updatedBy": {
                    "name": "User 4"
                },
                "itemsKeyValue": {
                    "name": "test2",
                    "IP": "2.2.2.2"
                }
            }
        }
    ]
}

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


class TestHappyPath:
    """
    Group the Happy path tests
    """

    @pytest.mark.parametrize('args, expected_next_link, client', [  # disable-secrets-detection
        ({'limit': '1'}, 'https://test.com', mock_client()),
        ({'limit': '50'}, None, mock_client())
    ])
    def test_get_limited_list_incidents(self, args, expected_next_link, client, mocker):
        """
        Given:
            - Args with and various limit parameter for the tested command
            - Expected value for next link if exist
            - An app client object
        When:
            - Calling function list_incidents_command
        Then:
            - Ensure the results holds the expected incidents list data
            - Ensure next link returned as expected
        """

        # prepare
        mocked_incidents = MOCKED_INCIDENTS_OUTPUT.copy()
        mocker.patch.object(client, 'http_request', return_value=mocked_incidents)
        if expected_next_link:
            mocked_incidents['nextLink'] = expected_next_link

        # execute
        command_res = list_incidents_command(client, args=args)
        readable_output, outputs, raw_response = command_res.readable_output, command_res.outputs, command_res.raw_response
        context = outputs['AzureSentinel.Incident(val.ID === obj.ID)'][0]

        # validate
        assert 'Incidents List (1 results)' in readable_output

        assert context['ID'] == 'inc_name', 'Incident name in Azure Sentinel API is Incident ID in Cortex XSOAR'
        assert context['FirstActivityTimeUTC'] == '2020-02-02T14:05:01Z', 'Dates are formatted to %Y-%m-%dT%H:%M:%SZ'
        assert context['AlertsCount'] == 1

        assert len(raw_response['value']) == 1
        next_link = outputs.get(NEXT_LINK_CONTEXT_KEY, {}).get('URL')
        assert next_link == expected_next_link

    def test_get_next_page_list_incidents(self, mocker):
        """
        Given:
            - Next link parameter to get the next page of incidents
            - An app client object
        When:
            - Calling function list_incidents_command
        Then:
            - Ensure the the request sent to the next link url
        """

        # prepare
        next_link_uri = 'https://test.com'
        args = {'limit': '1', 'next_link': next_link_uri}
        client = mock_client()
        mocker.patch.object(client, 'http_request')

        # execute
        list_incidents_command(client, args=args)

        # validate
        assert client.http_request.call_args[1]['full_url'] == next_link_uri

    def test_incident_add_comment(self, mocker):
        """
        Given:
            - Incident Id and comment as argument for the command

        When:
            - Calling function incident_add_comment_command

        Then:
            - Validate the comment was sent as expected
        """

        # prepare
        import random
        client = mock_client()
        mocker.patch.object(random, 'getrandbits', return_value=1234)
        mocker.patch.object(client, 'http_request', return_value=MOCKED_ADD_COMMENT_OUTPUT)

        # run
        args = {'incident_id': 'inc_id', 'message': 'test_message'}
        command_result = incident_add_comment_command(client, args=args)
        readable_output, outputs = command_result.readable_output, command_result.outputs

        # validate
        assert 'Incident inc_id new comment details' in readable_output
        assert outputs['ID'] == '1234', 'Comment IDs are generated by random.getrandbits()'
        assert outputs['Message'] == 'test_message'
        assert outputs['AuthorEmail'] == 'test@demisto.com'
        assert outputs['IncidentID'] == 'inc_id'

    @pytest.mark.parametrize(argnames='mocked_status_code, expected_result',
                             argvalues=[
                                 (200, 'Comment comment_id was deleted successfully.'),
                                 (204, 'Comment comment_id does not exist.'),
                             ])
    def test_incident_delete_comment(self, mocker, mocked_status_code, expected_result):
        """
        Given:
            - Incident Id and comment Id as argument for the command

        When:
            - Calling function incident_delete_comment_command

        Then:
            - Validate the comment was sent as expected
        """

        # prepare
        client = mock_client()
        res = requests.Response()
        res.status_code = mocked_status_code
        mocker.patch.object(client, 'http_request', return_value=res)

        # run
        args = {'incident_id': 'inc_id', 'comment_id': 'comment_id'}
        readable_output = incident_delete_comment_command(client, args=args).readable_output

        # validate
        assert readable_output == expected_result

    def test_update_incident(self, mocker):
        """
        Given:
            - Labels for update an incident

        When:
            - Calling function get_update_incident_request_data

        Then:
            - Validate the labels was sent as expected with the label name and label type
        """

        # prepare
        client = mock_client()
        args = {'labels': ['label_after_1', 'label_after_2'], 'assignee_email': 'bob@example.com'}
        mocker.patch.object(client, 'http_request', return_value=MOCKED_UPDATE_INCIDENT)

        # run
        incident_data = get_update_incident_request_data(client, args)

        # validate
        properties = incident_data['properties']
        assert properties['labels'] == [{'labelName': 'label_after_1', 'labelType': 'User'},
                                        {'labelName': 'label_after_2', 'labelType': 'User'}]
        assert properties['owner']['email'] == 'bob@example.com'

    def test_list_incident_entities(self, mocker):
        """
        Given:
            - Args with incident id to get entities for

        When:
            - Calling function list_incident_entities_command

        Then:
            - Validate the expected entities was returned as expected
        """

        # prepare
        client = mock_client()
        args = {'incident_id': TEST_INCIDENT_ID}
        mocker.patch.object(client, 'http_request', return_value=MOCKED_INCIDENT_ENTITIES)
        with open('TestData/expected_entities.json', 'r') as file:
            expected_entities = json.load(file)

        # run
        command_result = list_incident_entities_command(client=client, args=args)

        # validate
        assert client.http_request.call_args[0][1] == f'incidents/{TEST_INCIDENT_ID}/entities'
        assert command_result.raw_response == MOCKED_INCIDENT_ENTITIES
        assert f'Incident {TEST_INCIDENT_ID} Entities (2 results)' in command_result.readable_output
        assert expected_entities == command_result.outputs

    def test_list_incident_alerts(self, mocker):
        """
        Given:
            - Existing incident Id

        When:
            - Calling function list_incident_alerts_command

        Then:
            - Validate the result was returned as expected
        """

        # prepare
        client = mock_client()
        mocker.patch.object(client, 'http_request', return_value=MOCKED_INCIDENT_ALERTS)
        with open('TestData/expected_alerts.json', 'r') as file:
            expected_alerts = json.load(file)

        # run
        command_result = list_incident_alerts_command(client, {'incident_id': TEST_INCIDENT_ID})

        # validate
        assert client.http_request.call_args[0][1] == f'incidents/{TEST_INCIDENT_ID}/alerts'
        assert command_result.raw_response == MOCKED_INCIDENT_ALERTS
        assert command_result.outputs == expected_alerts

    def test_list_watchlist(self, mocker):
        """
        Given:
            -

        When:
            - Calling function list_watchlists_command

        Then:
            - Validate watchlist was returned as expected
        """

        # prepare
        client = mock_client()
        mocker.patch.object(client, 'http_request', return_value=MOCKED_WATCHLISTS)
        with open('TestData/expected_watchlists.json', 'r') as file:
            expected_watchlists = json.load(file)

        # run
        command_result = list_watchlists_command(client=client, args={})

        # validate
        assert '### Watchlists results\n|Name|ID|Description|' in command_result.readable_output
        assert '| test_watchlist_name_1 | test_watchlist_id_1 | test_description |' in command_result.readable_output
        assert command_result.raw_response == MOCKED_WATCHLISTS
        assert expected_watchlists == command_result.outputs

    def test_get_specific_watchlist(self, mocker):
        """
        Given:
            -

        When:
            - Calling function list_watchlists_command with alias for specific watchlist

        Then:
            - Validate watchlist was returned as expected
        """

        # prepare
        client = mock_client()
        args = {'watchlist_alias': TEST_WATCHLIST_ALIAS}
        mocker.patch.object(client, 'http_request', return_value=MOCKED_WATCHLISTS['value'][0])
        with open('TestData/expected_watchlists.json', 'r') as file:
            expected_watchlist = json.load(file)[0]

        # run
        command_result = list_watchlists_command(client=client, args=args)

        # validate
        assert '### Watchlists results\n|Name|ID|Description|' in command_result.readable_output
        assert '| test_watchlist_name_1 | test_watchlist_id_1 | test_description |' in command_result.readable_output

        assert command_result.raw_response == MOCKED_WATCHLISTS['value'][0]
        assert expected_watchlist == command_result.outputs[0]

    @pytest.mark.parametrize(argnames='deletion_command, args', argvalues=[
        (delete_incident_command, {'incident_id': TEST_INCIDENT_ID}),
        (delete_watchlist_command, {'watchlist_alias': TEST_WATCHLIST_ALIAS}),
        (delete_watchlist_item_command, {'watchlist_item_id': TEST_ITEM_ID, 'watchlist_alias': TEST_WATCHLIST_ALIAS})
    ])
    def test_generic_delete_items(self, deletion_command, args, mocker):
        """
        Given:
            - Item for deletion is exist

        When:
            - Calling varius commands for deletion items with the required args

        Then:
            - Validate result was as expected
        """

        # prepare
        client = mock_client()
        mocker.patch.object(client, 'http_request')

        # run
        command_result = deletion_command(client=client, args=args)
        readable_output = command_result.readable_output

        # validate
        item_id = args.popitem()[1]
        f'{item_id} was deleted successfully.' in readable_output

    def test_list_watchlist_items(self, mocker):
        """
        Given:
            - Watchlist with items

        When:
            - Calling to function list_watchlist_items_command

        Then:
            - Validate the expected result was returned
        """

        # prepare
        client = mock_client()
        args = {'watchlist_alias': TEST_WATCHLIST_ALIAS}
        mocker.patch.object(client, 'http_request', return_value=MOCKED_WATCHLIST_ITEMS)
        with open('TestData/expected_watchlist_items.json', 'r') as file:
            expected_items = json.load(file)

        # run
        command_result = list_watchlist_items_command(client=client, args=args)

        # validate
        assert f'| {TEST_ITEM_ID} | name: test1<br>IP: 1.1.1.1 |' in command_result.readable_output
        assert command_result.raw_response == MOCKED_WATCHLIST_ITEMS
        assert command_result.outputs == expected_items

    def test_single_watchlist_item(self, mocker):
        """
        Given:
            - Watchlist with at least one item

        When:
            - Calling to function list_watchlist_items_command with argument for specific item

        Then:
            - Validate the expected result was returned
        """

        # prepare
        client = mock_client()
        args = {'watchlist_alias': TEST_WATCHLIST_ALIAS, 'watchlist_item_id': TEST_ITEM_ID}
        mocked_item = MOCKED_WATCHLIST_ITEMS['value'][0]
        mocker.patch.object(client, 'http_request', return_value=mocked_item)
        with open('TestData/expected_watchlist_items.json', 'r') as file:
            expected_item = json.load(file)[0]

        # run
        command_result = list_watchlist_items_command(client=client, args=args)

        # validate
        client.http_request.call_args[0][1] == f'watchlists/{TEST_WATCHLIST_ALIAS}/watchlistItems/test_watchlist_id_1'
        assert f'| {TEST_ITEM_ID} | name: test1<br>IP: 1.1.1.1 |' in command_result.readable_output
        assert command_result.raw_response == mocked_item
        assert command_result.outputs[0] == expected_item

    def test_create_update_watchlist(self, mocker):
        """
        Given:
            - Not existing watchlist alias or existing and we want to update

        When:
            - Calling function create_update_watchlist_command

        Then:
            - Validate result returned as expected
        """

        # prepare
        client = mock_client()
        mocked_watchlist = MOCKED_WATCHLISTS['value'][0]
        args = {
            'watchlist_alias': demisto.get(mocked_watchlist, 'properties.watchlistAlias'),
            'raw_content': None,
            'watchlist_display_name': demisto.get(mocked_watchlist, 'properties.displayName'),
            'description': demisto.get(mocked_watchlist, 'properties.description'),
            'provider': demisto.get(mocked_watchlist, 'properties.provider'),
            'source': demisto.get(mocked_watchlist, 'properties.source'),
            'labels': 'IP',
            'lines_to_skip': demisto.get(mocked_watchlist, 'properties.numberOfLinesToSkip'),
            'items_search_key': demisto.get(mocked_watchlist, 'properties.itemsSearchKey'),
            'content_type': demisto.get(mocked_watchlist, 'properties.contentType')
        }
        mocker.patch.object(client, 'http_request', return_value=mocked_watchlist)
        with open('TestData/expected_watchlists.json', 'r') as file:
            expected_watchlist = json.load(file)[0]

        # run
        command_result = create_update_watchlist_command(client, args)

        # validate
        assert expected_watchlist == command_result.outputs
        assert '|Name|ID|Description|' in command_result.readable_output
        assert '| test_watchlist_name_1 | test_watchlist_id_1 | test_description |' in command_result.readable_output

    def test_create_update_watchlist_item(self, mocker):
        """
        Given:
            - Not existing watchlist item or existing and we want to update

        When:
            - Calling function create_update_watchlist_item_command

        Then:
            - Validate result returned as expected
        """

        # prepare
        client = mock_client()
        mocked_item = MOCKED_WATCHLIST_ITEMS['value'][0]
        args = {
            'watchlist_alias': TEST_WATCHLIST_ALIAS,
            'item_key_value': json.dumps(demisto.get(mocked_item, 'properties.itemsKeyValue'))
        }

        mocker.patch.object(client, 'http_request', return_value=mocked_item)
        with open('TestData/expected_watchlist_items.json', 'r') as file:
            expected_item = json.load(file)[0]

        # run
        command_result = create_update_watchlist_item_command(client, args)

        # validate
        assert expected_item == command_result.outputs
        assert mocked_item['id'] in command_result.readable_output

    def test_user_agent_in_request(self, mocker):
        """
        Given:
            - Request go to send to Azure

        When:
            - Run any command

        Then:
            - Validate the required header exist in request
        """

        # prepare
        client = mock_client()
        mocker.patch.object(client._client, 'get_access_token')
        mocker.patch.object(requests.Session, 'request')

        # run
        list_watchlists_command(client, args={})

        # validate
        user_agent = requests.Session.request.call_args[1]['headers']['User-Agent']
        assert user_agent == XSOAR_USER_AGENT


class TestEdgeCases:
    """
    Group for the Edge cases tests
    """

    @pytest.mark.parametrize(argnames='command, resource_id', argvalues=[
        (list_incident_entities_command, TEST_INCIDENT_ID),
        (list_incident_comments_command, TEST_INCIDENT_ID),
        (list_incident_relations_command, TEST_INCIDENT_ID),
        (list_incident_alerts_command, TEST_INCIDENT_ID),
        (list_watchlists_command, TEST_WATCHLIST_ALIAS),
        (list_watchlist_items_command, TEST_WATCHLIST_ALIAS)
    ])
    def test_not_exist_elements(self, command, resource_id, mocker):
        """
        Given:
            - Not existing resource id (incident, watchlist alias)

        When:
            - Calling various list incident elements commands

        Then:
            - Validate the expected error message was returned
        """

        # prepare
        client = mock_client()
        args = {'incident_id': TEST_INCIDENT_ID, 'limit': '50'}
        not_exist_response = mock_404_response(resource_id=resource_id)
        mocker.patch.object(requests.Session, 'request', return_value=not_exist_response)
        mocker.patch.object(client._client, 'get_access_token')

        # run
        with pytest.raises(ValueError) as error:
            command(client=client, args=args)

        # validate
        assert error.value.args[0] == f"[NotFound 404] Resource '{resource_id}' does not exist"
