import json

import dateparser
import pytest
import requests
import demistomock as demisto
from CommonServerPython import IncidentStatus, tableToMarkdown, pascalToSpace, CommandResults
from AzureSentinel import AzureSentinelClient, list_incidents_command, list_incident_relations_command, \
    incident_add_comment_command, \
    get_update_incident_request_data, list_incident_entities_command, list_incident_comments_command, \
    list_incident_alerts_command, list_watchlists_command, \
    delete_watchlist_command, list_watchlist_items_command, \
    create_update_watchlist_command, create_update_watchlist_item_command, delete_watchlist_item_command, \
    delete_incident_command, XSOAR_USER_AGENT, incident_delete_comment_command, \
    query_threat_indicators_command, create_threat_indicator_command, delete_threat_indicator_command, \
    append_tags_threat_indicator_command, replace_tags_threat_indicator_command, update_threat_indicator_command, \
    list_threat_indicator_command, NEXT_LINK_DESCRIPTION, process_incidents, fetch_incidents, \
    fetch_incidents_additional_info, \
    get_modified_remote_data_command, get_remote_data_command, get_remote_incident_data, get_mapping_fields_command, \
    update_remote_system_command, update_remote_incident, close_incident_in_remote, update_incident_request, \
    set_xsoar_incident_entries, build_threat_indicator_data, DEFAULT_SOURCE, list_alert_rule_command, \
    list_alert_rule_template_command, delete_alert_rule_command, validate_required_arguments_for_alert_rule, \
    create_data_for_alert_rule, create_and_update_alert_rule_command, COMMENT_HEADERS, update_incident_command, \
    extract_classification_reason, create_incident_command

TEST_ITEM_ID = 'test_watchlist_item_id_1'

NEXT_LINK_CONTEXT_KEY = 'AzureSentinel.NextLink(val.Description == "NextLink for listing commands")'

API_VERSION = '2022-11-01'


def test_valid_error_is_raised_when_empty_api_response_is_returned(mocker):
    """
    Given
    - Empty api response and invalid status code returned from the api response.

    When
    - running 'test-module'.

    Then
    - ValueError is raised.
    """
    from AzureSentinel import test_module
    client = mock_client()
    api_response = requests.Response()
    api_response.status_code = 403
    api_response._content = None

    mocker.patch.object(client._client, 'get_access_token')
    mocker.patch.object(client._client._session, 'request', return_value=api_response)

    with pytest.raises(ValueError, match='[Forbidden 403]'):
        test_module(client, {})


def mock_client():
    client = AzureSentinelClient(
        tenant_id='tenant_id',
        client_id='client_id',
        client_secret='client_secret',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        workspace_name='workspaceName',
        verify=False,
        proxy=False,
        certificate_thumbprint=None,
        private_key=None,
    )

    return client


def mock_404_response(resource_id: str):
    res = requests.Response()
    res.status_code = 404
    res._content = json.dumps(
        {'error': {'code': 'NotFound', 'message': f"Resource '{resource_id}' does not exist"}}).encode()
    return res


def mock_204_response():
    res = requests.Response()
    res.status_code = 204
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
                "additionalData": {
                    "MitreTechniques": "Unknown",
                },
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
                "additionalData": {
                    "MitreTechniques": "Unknown",
                },
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

MOCKED_THREAT_INDICATOR_OUTPUT = {
    "value": [
        {
            "id": "ind_id",
            "name": "ind_name",
            "etag": "\"1200b4fe-0000-0800-0000-6194cfae0000\"",
            "type": "Microsoft.SecurityInsights/threatIntelligence",
            "kind": "indicator",
            "properties": {
                "confidence": 100,
                "created": "2021-11-17T09:43:15.9576155Z",
                "externalId": "indicator--0a1a583a-d801-4b64-9c5b-f595f77aa53d",
                "lastUpdatedTimeUtc": "2021-11-17T09:43:15.9579245Z",
                "source": "Azure Sentinel",
                "threatIntelligenceTags": [
                    "wereplacedthetag"
                ],
                "displayName": "displayfortestmay",
                "threatTypes": [
                    "malicious-activity"
                ],
                "parsedPattern": [
                    {
                        "patternTypeKey": "url",
                        "patternTypeValues": [
                            {
                                "valueType": "url",
                                "value": "‘twitter.com’"  # noqa: RUF001
                            }
                        ]
                    }
                ],
                "pattern": "[url:value = ‘twitter.com’]",  # noqa: RUF001
                "patternType": "twitter.com",
                "validFrom": "2021-11-17T08:20:15.111Z"
            }
        }]
}

MOCKED_CREATE_THREAT_INDICATOR_OUTPUT = {
    "id": "ind_id",
    "name": "ind_name",
    "etag": "\"1f002899-0000-0800-0000-619a3dd40000\"",
    "type": "Microsoft.SecurityInsights/threatIntelligence",
    "kind": "indicator",
    "properties": {
        "confidence": 80,
        "created": "2021-11-21T12:38:43.9928873Z",
        "createdByRef": "",
        "externalId": "indicator--9f973088-3ac8-4391-9eb3-97fa90d3e1b5",
        "lastUpdatedTimeUtc": "2021-11-21T12:38:43.9976961Z",
        "revoked": True,
        "source": "Azure Sentinel",
        "threatIntelligenceTags": [
            "wereplacedthetag"
        ],
        "displayName": 'displayfortestmay',
        "description": "blabla",
        "threatTypes": [
            "compromised"
        ],
        "killChainPhases": [
            {
                "killChainName": "rrr",
                "phaseName": "rrr"
            }
        ],
        "parsedPattern": [
            {
                "patternTypeKey": "file",
                "patternTypeValues": [
                    {
                        "valueType": "hashes.'SHA-1'",
                        "value": "935DA64F08574E820565497C6918C8A17D4567FE"
                    }
                ]
            }
        ],
        "pattern": "[file:hashes.'SHA-1' = '935DA64F08574E820565497C6918C8A17D4567FE']",
        "patternType": "935DA64F08574E820565497C6918C8A17D4567FE",
        "validFrom": "2020-04-15T17:44:00.114052Z"
    }
}

MOCKED_UPDATE_THREAT_INDICATOR = {
    "id": "ind_id",
    "name": "ind_name",
    "etag": "\"1f002899-0000-0800-0000-619a3dd40000\"",
    "type": "Microsoft.SecurityInsights/threatIntelligence",
    "kind": "indicator",
    "properties": {
        "confidence": 80,
        "created": "2021-11-21T12:38:43.9928873Z",
        "createdByRef": "",
        "externalId": "indicator--9f973088-3ac8-4391-9eb3-97fa90d3e1b5",
        "lastUpdatedTimeUtc": "2021-11-21T12:38:43.9976961Z",
        "revoked": True,
        "source": "Azure Sentinel",
        "threatIntelligenceTags": [
            "newTag"
        ],
        "displayName": 'newDisplayName',
        "description": "blabla",
        "threatTypes": [
            "compromised"
        ],
        "killChainPhases": [
            {
                "killChainName": "rrr",
                "phaseName": "rrr"
            }
        ],
        "parsedPattern": [
            {
                "patternTypeKey": "file",
                "patternTypeValues": [
                    {
                        "valueType": "hashes.'SHA-1'",
                        "value": "newValue"
                    }
                ]
            }
        ],
        "pattern": "[domain-name:value = newValue]",
        "patternType": "newValue",
        "validFrom": "2020-04-15T17:44:00.114052Z"
    }
}

MOCKED_ORIGINAL_THREAT_INDICATOR_OUTPUT = {
    "id": "ind_id",
    "name": "ind_name",
    "etag": "\"1200b4fe-0000-0800-0000-6194cfae0000\"",
    "type": "Microsoft.SecurityInsights/threatIntelligence",
    "kind": "indicator",
    "properties": {
        "confidence": 100,
        "created": "2021-11-17T09:43:15.9576155Z",
        "externalId": "indicator--0a1a583a-d801-4b64-9c5b-f595f77aa53d",
        "lastUpdatedTimeUtc": "2021-11-17T09:43:15.9579245Z",
        "source": "Azure Sentinel",
        "threatIntelligenceTags": [
            "wereplacedthetag"
        ],
        "displayName": "displayfortestmay",
        "threatTypes": [
            "malicious-activity"
        ],
        "parsedPattern": [
            {
                "patternTypeKey": "url",
                "patternTypeValues": [
                    {
                        "valueType": "url",
                        "value": "‘twitter.com’"  # noqa: RUF001
                    }
                ]
            }
        ],
        "pattern": "[url:value = ‘twitter.com’]",  # noqa: RUF001
        "patternType": "twitter.com",
        "validFrom": "0001-01-01T00:00:00"
    }
}

ARGS_TO_UPDATE = {
    "indicator_name": "ind_name",
    "displayName": 'newDisplayName',
    "value": 'newValue',
    "indicator_type": 'domain'
}

MOCKED_RAW_INCIDENT_OUTPUT = {
    'value': [
        {
            'ID': 'inc_ID',
            'Name': 'inc_name',
            'IncidentNumber': 2,
            'Title': 'title',
            'Severity': 'High',
            'CreatedTimeUTC': '2020-02-02T14:05:01.5348545Z',
        },
        {
            'ID': 'inc_ID_3',
            'Name': 'inc_name_3',
            'IncidentNumber': 3,
            'Title': 'title',
            'Severity': 'Low',
            'CreatedTimeUTC': '2020-02-02T14:05:01.5348545Z',
        }
    ]
}


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
        args = {'labels': ['label_after_1', 'label_after_2'], 'assignee_email': 'bob@example.com',
                'user_principal_name': 'booUserPrincipalName'}
        mocker.patch.object(client, 'http_request', return_value=MOCKED_UPDATE_INCIDENT)

        # run
        incident_data = get_update_incident_request_data(client, args)

        # validate
        properties = incident_data['properties']
        assert properties['labels'] == [{'labelName': 'label_after_1', 'labelType': 'User'},
                                        {'labelName': 'label_after_2', 'labelType': 'User'}]
        assert properties['owner']['email'] == 'bob@example.com'
        assert properties['owner']['userPrincipalName'] == 'booUserPrincipalName'

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
        with open('test_data/expected_entities.json') as file:
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
        with open('test_data/expected_alerts.json') as file:
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
        with open('test_data/expected_watchlists.json') as file:
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
        with open('test_data/expected_watchlists.json') as file:
            expected_watchlist = json.load(file)[0]

        # run
        command_result = list_watchlists_command(client=client, args=args)

        # validate
        assert '### Watchlists results\n|Name|ID|Description|' in command_result.readable_output
        assert '| test_watchlist_name_1 | test_watchlist_id_1 | test_description |' in command_result.readable_output

        assert command_result.raw_response == MOCKED_WATCHLISTS['value'][0]
        assert expected_watchlist == command_result.outputs[0]

    @pytest.mark.parametrize(argnames='deletion_command, args, item_id', argvalues=[
        (delete_incident_command, {'incident_id': TEST_INCIDENT_ID}, TEST_INCIDENT_ID),
        (delete_watchlist_command, {'watchlist_alias': TEST_WATCHLIST_ALIAS}, TEST_WATCHLIST_ALIAS),
        (delete_watchlist_item_command, {'watchlist_item_id': TEST_ITEM_ID,
         'watchlist_alias': TEST_WATCHLIST_ALIAS}, TEST_ITEM_ID)
    ])
    def test_generic_delete_items(self, deletion_command, args, mocker, item_id):
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
        assert f'{item_id} was deleted successfully.' in readable_output

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
        with open('test_data/expected_watchlist_items.json') as file:
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
        with open('test_data/expected_watchlist_items.json') as file:
            expected_item = json.load(file)[0]

        # run
        command_result = list_watchlist_items_command(client=client, args=args)

        # validate
        assert client.http_request.call_args[0][1] == f'watchlists/{TEST_WATCHLIST_ALIAS}/watchlistItems/test_watchlist_item_id_1'
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
        with open('test_data/expected_watchlists.json') as file:
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
        with open('test_data/expected_watchlist_items.json') as file:
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

    @pytest.mark.parametrize('args, expected_next_link, client', [  # disable-secrets-detection
        ({'limit': '50'}, 'https://test.com', mock_client()),
        ({'next_link': 'https://test.com'}, None, mock_client())
    ])
    def test_threat_indicator_list_command(self, args, expected_next_link, client, requests_mock):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - Expected value for next link if exist
                    - An app client object
                When:
                    - Calling function list_threat_indicators_command
                Then:
                    - Ensure the results holds the expected incidents list data
                    - Ensure next link returned as expected
                """

        # prepare
        mocked_indicators = MOCKED_THREAT_INDICATOR_OUTPUT.copy()
        if expected_next_link:
            mocked_indicators['nextLink'] = expected_next_link
            requests_mock.get(
                'https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft'
                '.OperationalInsights/workspaces/workspaceName/providers/Microsoft.SecurityInsights/threatIntelligence'
                '/main/indicators', json=mocked_indicators)
        else:
            requests_mock.get('https://test.com', json=mocked_indicators)

        requests_mock.post('https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token', json={})

        # execute
        command_res = list_threat_indicator_command(client, args=args)
        readable_output, outputs, raw_response = command_res.readable_output, command_res.outputs, command_res.raw_response
        context = outputs['AzureSentinel.ThreatIndicator'][0]

        # validate
        assert 'Threat Indicators (1 results)' in readable_output

        assert context['Name'] == 'ind_name', 'Incident name in Azure Sentinel API is Incident ID in Cortex XSOAR'
        assert context['DisplayName'] == 'displayfortestmay'

        assert len(raw_response['value']) == 1
        next_link = outputs.get(f'AzureSentinel.NextLink(val.Description == "{NEXT_LINK_DESCRIPTION}")', {}).get('URL')
        assert next_link == expected_next_link

    @pytest.mark.parametrize('args, expected_next_link, client', [  # disable-secrets-detection
        ({'limit': '1', 'min_confidence': 0, 'indicator_types': ['url', 'domain']}, 'https://test.com', mock_client()),
        ({'next_link': 'https://test.com'}, None, mock_client())])
    def test_query_threat_indicators_command(self, args, expected_next_link, client, requests_mock):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - Expected value for next link if exist
                    - An app client object
                When:
                    - Calling function query_threat_indicators_command
                Then:
                    - Ensure the results holds the expected incidents list data
                    - Ensure next link returned as expected
        """
        # prepare
        mocked_indicators = MOCKED_THREAT_INDICATOR_OUTPUT.copy()
        if expected_next_link:
            mocked_indicators['nextLink'] = expected_next_link
            requests_mock.post(
                'https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft'
                '.OperationalInsights/workspaces/workspaceName/providers/Microsoft.SecurityInsights/threatIntelligence'
                '/main/queryIndicators', json=mocked_indicators)
        else:
            requests_mock.post('https://test.com', json=mocked_indicators)

        requests_mock.post('https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token', json={})

        # execute
        command_res = query_threat_indicators_command(client, args=args)
        readable_output, outputs, raw_response = command_res.readable_output, command_res.outputs, command_res.raw_response
        context = outputs['AzureSentinel.ThreatIndicator'][0]

        assert 'Threat Indicators (1 results)' in readable_output

        assert context['Name'] == 'ind_name', 'Incident name in Azure Sentinel API is Incident ID in Cortex XSOAR'
        assert context['DisplayName'] == 'displayfortestmay'

        assert len(raw_response['value']) == 1
        next_link = outputs.get(f'AzureSentinel.NextLink(val.Description == "{NEXT_LINK_DESCRIPTION}")', {}).get('URL')
        assert next_link == expected_next_link

    @pytest.mark.parametrize('args, client', [  # disable-secrets-detection
        ({'value': 'twitter.com', 'display_name': 'displaytestformay', 'indicator_types': 'url',
          'threat_types': ["malicious-activity"]}, mock_client())])
    def test_create_threat_indicator_command(self, args, client, mocker):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - An app client object
                When:
                    - Calling function create_threat_indicator_command
                Then:
                    - Ensure the results holds the expected incidents list data
                """

        # prepare
        mocked_indicators = MOCKED_CREATE_THREAT_INDICATOR_OUTPUT
        mocker.patch.object(client, 'http_request', return_value=mocked_indicators)

        # execute
        command_res = create_threat_indicator_command(client, args=args)
        readable_output, outputs = command_res.readable_output, command_res.outputs
        context = outputs[0]

        # validate
        assert 'New threat Indicator was created' in readable_output

        assert context['Name'] == 'ind_name', 'Incident name in Azure Sentinel API is Incident ID in Cortex XSOAR'
        assert context['DisplayName'] == 'displayfortestmay'

        assert context['Tags'][0] == 'wereplacedthetag'

    @pytest.mark.parametrize('args, client', [  # disable-secrets-detection
        ({'indicator_names': ['ind_name', 'ind2_name']}, mock_client())])
    def test_delete_threat_indicator_command(self, args, client, mocker):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - An app client object
                When:
                    - Calling function delete_threat_indicator_command
                Then:
                    - Ensure the results holds the expected readable output
                """
        # prepare
        mocker.patch.object(client, 'http_request', return_value={})

        # execute
        command_res = delete_threat_indicator_command(client, args=args)
        readable_output = command_res.readable_output

        # validate
        assert "Threat Intelligence Indicators ind_name, ind2_name were deleted successfully" in readable_output

    @pytest.mark.parametrize('args, client', [  # disable-secrets-detection
        ({'indicator_name': 'ind_name', 'tags': 'wereplacedthetag'}, mock_client())])
    def test_append_tags_threat_indicator_command(self, args, client, mocker):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - An app client object
                When:
                    - Calling function pend_tags_threat_indicator_command
                Then:
                    - Ensure the results holds the expected incidents list data
                """
        # prepare
        mocked_indicators = MOCKED_CREATE_THREAT_INDICATOR_OUTPUT
        mocker.patch.object(client, 'http_request', return_value=mocked_indicators)

        # execute
        command_res = append_tags_threat_indicator_command(client, args=args)
        readable_output, outputs = command_res.readable_output, command_res.outputs
        context = outputs[0]

        # validate
        assert 'Tags were appended to ind_name Threat Indicator' in readable_output

        assert context['Name'] == 'ind_name'
        assert context['DisplayName'] == 'displayfortestmay'

        assert context['Tags'][0] == 'wereplacedthetag'

    @pytest.mark.parametrize('args, client', [  # disable-secrets-detection
        ({'indicator_name': 'ind_name', 'tags': 'wereplacedthetag'}, mock_client())])
    def test_replace_tags_threat_indicator_command(self, args, client, mocker):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - An app client object
                When:
                    - Calling function replace_tags_threat_indicator_command
                Then:
                    - Ensure the results holds the expected incidents list data
                """
        # prepare
        mocked_indicators = MOCKED_CREATE_THREAT_INDICATOR_OUTPUT
        mocker.patch.object(client, 'http_request', return_value=mocked_indicators)

        # execute
        command_res = replace_tags_threat_indicator_command(client, args=args)
        readable_output, outputs = command_res.readable_output, command_res.outputs
        context = outputs[0]

        # validate
        assert 'Tags were replaced to ind_name Threat Indicator.' in readable_output

        assert context['Name'] == 'ind_name'
        assert context['DisplayName'] == 'displayfortestmay'

        assert context['Tags'][0] == 'wereplacedthetag'

    @pytest.mark.parametrize('args, client', [  # disable-secrets-detection
        (ARGS_TO_UPDATE, mock_client())])
    def test_update_threat_indicator_command(self, args, client, requests_mock):
        """
                Given:
                    - Args with and various limit parameter for the tested command
                    - An app client object
                When:
                    - Calling function update_incident_command
                Then:
                    - Ensure the results holds the expected threat indicator data
                """

        # prepare
        mocked_indicators = MOCKED_ORIGINAL_THREAT_INDICATOR_OUTPUT
        mocked_updated_indicators = MOCKED_UPDATE_THREAT_INDICATOR

        requests_mock.get(
            'https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft'
            '.OperationalInsights/workspaces/workspaceName/providers/Microsoft.SecurityInsights/threatIntelligence'
            '/main/indicators/ind_name', json=mocked_indicators)
        requests_mock.put(
            'https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft'
            '.OperationalInsights/workspaces/workspaceName/providers/Microsoft.SecurityInsights/threatIntelligence'
            '/main/indicators/ind_name', json=mocked_updated_indicators)

        requests_mock.post('https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token', json={})

        # execute

        command_res = update_threat_indicator_command(client, args=args)
        readable_output, outputs = command_res.readable_output, command_res.outputs
        context = outputs[0]

        # validate
        assert 'Threat Indicator ind_name was updated' in readable_output

        assert context['Name'] == 'ind_name', 'Incident name in Azure Sentinel API is Incident ID in Cortex XSOAR'
        assert context['DisplayName'] == 'newDisplayName'

    @pytest.mark.parametrize('args, client, expected_result', [  # disable-secrets-detection
        ({'last_fetch_ids': [], 'min_severity': 3, 'last_incident_number': 1}, mock_client(),
         {'last_fetch_ids': ['inc_ID'], 'last_incident_number': 2}),  # case 1
    ])
    def test_process_incidents(self, args, client, expected_result):
        """
        Given: - Raw_incidents, AzureSentinel client, last_fetched_ids array, last_incident_number,
        latest_created_time,  and a minimum severity.

        When:
            - Calling the process_incidents command.

        Then:
            - Validate the return values based on the scenario:
            case 1: We expect to process the incident, so its ID exists in the expected result.
            case 2: The incident id is in the "last_fetch_ids" array, so we expect to not process the incident.
        """
        # prepare
        raw_incidents = [MOCKED_RAW_INCIDENT_OUTPUT.get('value')[0]]
        min_severity = args.get('min_severity')
        last_incident_number = args.get('last_incident_number')
        latest_created_time = dateparser.parse('2020-02-02T14:05:01.5348545Z')

        # run
        next_run, _ = process_incidents(raw_incidents, min_severity, latest_created_time,
                                        last_incident_number)

        # validate
        assert next_run.get('last_fetch_ids') == expected_result.get('last_fetch_ids')
        assert next_run.get('last_incident_number') == expected_result.get('last_incident_number')

    def test_last_run_in_fetch_incidents(self, mocker):
        """
        Scenario: First time fetching incidents after updating the integration.
        Given:
            - AzureSentinel client, last_run dictionary, first_fetch_time, and a minimum severity.

            The last_run dictionary mimics a last_run dict from a previous version of the integration, containing an
            empty 'last_fetch_ids' array and a valid 'last_fetch_time' string, but does not contain
            'last_incident_number' that was added in the new version.

        When:
            - Calling the fetch_incidents command.

        Then:
            - Validate the call_args had the correct filter and orderby, to check that the fetch was handled by
            created time and not by incident number.
        """
        # prepare
        client = mock_client()
        last_run = {'last_fetch_time': '2022-03-16T13:01:08Z',
                    'last_fetch_ids': []}
        first_fetch_time = '3 days'
        minimum_severity = 0

        mocker.patch('AzureSentinel.process_incidents', return_value=({}, []))
        mocker.patch.object(client, 'http_request', return_value=MOCKED_INCIDENTS_OUTPUT)

        # run
        fetch_incidents(client, last_run, first_fetch_time, minimum_severity)
        call_args = client.http_request.call_args[1]

        # validate
        assert 'properties/createdTimeUtc ge' in call_args.get('params').get('$filter')
        assert call_args.get('params').get('$orderby') == 'properties/createdTimeUtc asc'

    def test_last_run_in_fetch_incidents_duplicates(self, mocker):
        """
        Scenario: Update the last run when duplicates are found.
        Given:
            - AzureSentinel client, last_run dictionary, first_fetch_time, and a minimum severity.

            The last_run dictionary mimics a last_run dict from a previous version of the integration, containing an
            empty 'last_fetch_ids' array with the previous detected incident, and has the same incident ID from the API.

        When:
            - Calling the fetch_incidents command.

        Then:
            - Validate that the incidents was deduped and not processed.
        """
        # prepare
        client = mock_client()
        last_run = {'last_fetch_time': '2022-03-16T13:01:08Z',
                    'last_fetch_ids': ['inc_name']}
        first_fetch_time = '3 days'
        minimum_severity = 0

        process_mock = mocker.patch('AzureSentinel.process_incidents', return_value=({}, []))
        mocker.patch.object(client, 'http_request', return_value=MOCKED_INCIDENTS_OUTPUT)

        # run
        fetch_incidents(client, last_run, first_fetch_time, minimum_severity)

        # validate
        assert not process_mock.call_args[0][0]

    @pytest.mark.parametrize('min_severity, expected_incident_num', [(1, 2), (3, 1)])
    def test_last_fetched_incident_for_various_severity_levels(self, mocker, min_severity, expected_incident_num):
        """
        Given:
            - Fetched incidents are with severity behind and over the lowest level defined in the integration instanse.

        When:
            - Calling the process_incidents function.

        Then:
            - Validate the last fetched incident contain also the low severity incidents.
            - Validate only incidents with the expected severity level is returned.
        """
        # prepare
        raw_incidents = MOCKED_RAW_INCIDENT_OUTPUT['value']
        latest_created_time = dateparser.parse('2020-02-02T14:05:01.5348545Z')

        # run
        next_run, incidents = process_incidents(raw_incidents=raw_incidents,
                                                min_severity=min_severity,
                                                latest_created_time=latest_created_time,
                                                last_incident_number=1)

        # validate
        assert next_run.get('last_fetch_ids') == ['inc_ID', 'inc_ID_3']
        assert next_run.get('last_incident_number') == 3
        assert len(incidents) == expected_incident_num

    def test_build_threat_indicator_data(self):
        """
            Given:
                - Args with values.
            When:
                - Calling function build_threat_indicator_data.
            Then:
                - Ensure the results holds the expected outcomes.
        """
        # prepare
        args = {'display_name': 'displayname',
                'indicator_type': 'ipv4',
                'revoked': 'false',
                'threat_types': 'compromised',
                'value': '1.1.1.1',
                }

        # run
        output = build_threat_indicator_data(args, source=DEFAULT_SOURCE)

        # validate

        assert " '1.1.1.1'" in output.get('pattern')
        assert output.get('patternType') == 'ipv4-addr'
        assert output.get('source') == DEFAULT_SOURCE

    @pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
    def test_test_module_command_with_managed_identities(self, mocker, requests_mock, client_id):
        """
            Given:
                - Managed Identities client id for authentication.
            When:
                - Calling test_module.
            Then:
                - Ensure the output are as expected.
        """

        from AzureSentinel import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
        import AzureSentinel
        import re

        mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
        get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
        requests_mock.get(re.compile(f'^{Resources.management_azure}.*'))

        params = {
            'managed_identities_client_id': {'password': client_id},
            'use_managed_identities': 'True',
            'subscriptionID': 'test_subscription_id',
            'resourceGroupName': 'test_resource_group',
            'tenant_id': 'test_tenant_id',
            'azure_cloud': 'Worldwide',
        }
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'command', return_value='test-module')
        mocker.patch.object(AzureSentinel, 'return_results')
        mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

        main()

        assert 'ok' in AzureSentinel.return_results.call_args[0][0]
        qs = get_mock.last_request.qs
        assert qs['resource'] == [Resources.management_azure]
        assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


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


@pytest.mark.parametrize("incidents", [
    ([{'ID': 'incident-1'}]),
    ([{'ID': 'incident-1'}, {'ID': 'incident-2'}]),
    ({'ID': 'incident-1'}),
    ([]),
])
def test_fetch_incidents_additional_info(mocker, incidents):
    """
    Given:
        - A list of incidents
    When:
        - Calling fetch_incidents_additional_info
    Then:
        - Ensure the client's http_request method was called the expected number of times,
          and the incidents were updated with the additional info
    """
    args = {'fetch_additional_info': ['Alerts', 'Entities']}
    mocker.patch('demistomock.params', return_value=args)
    client = mock_client()
    mocker.patch.object(client, 'http_request', side_effect=[
        {'value': [{'id': 'alert-1'}]},
        {'entities': [{'id': 'entities-1'}]},
        {'value': [{'id': 'alert-2'}]},
        {'entities': [{'id': 'entities-2'}]}
    ])

    fetch_incidents_additional_info(client, incidents)

    if isinstance(incidents, dict):
        incidents = [incidents]

    assert client.http_request.call_count == len(args['fetch_additional_info']) * len(incidents)
    if incidents:
        assert client.http_request.call_args_list[0][0][1] == 'incidents/incident-1/alerts'

    for i, incident in enumerate(incidents):
        assert 'alerts' in incident
        assert incident['alerts'] == [{'id': f'alert-{i + 1}'}]
        assert 'entities' in incident
        assert incident['entities'] == [{'id': f'entities-{i + 1}'}]


@pytest.mark.parametrize("last_update, expected_last_update", [
    ('2023-01-06T08:17:09.001016488+02:00', '2023-01-06T06:17:09.001016Z'),
    ('2023-01-06T08:17:09.001016488Z', '2023-01-06T08:17:09.001016Z')
])
def test_get_modified_remote_data_command(mocker, last_update, expected_last_update):
    """
    Given
        - client
        - args with lastUpdate
    When
        - running get_modified_remote_data_command
    Then
        - Ensure the client's http_request method was called with the expected filter,
          and the modified_incident_ids were returned the expected list of ids.
    """
    client = mock_client()
    mock_response = {'value': [{'name': 'incident-1'}, {'name': 'incident-2'}]}
    mocker.patch.object(client, 'http_request', return_value=mock_response)

    result = get_modified_remote_data_command(client, {'lastUpdate': last_update})
    excepted_filter = f'properties/lastModifiedTimeUtc ge {expected_last_update}'
    assert client.http_request.call_args[1]['params']['$filter'] == excepted_filter
    assert result.modified_incident_ids == [incident['name'] for incident in mock_response['value']]


def test_get_remote_data_command(mocker):
    """
    Given
        - client
        - args with id and lastUpdate
    When
        - running get_remote_data_command
    Then
        - Ensure the mirrored object was returned the expected object
    """

    mocker.patch('AzureSentinel.get_remote_incident_data', return_value=({'name': 'incident-1'}, {'ID': 'incident-1'}))
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})

    result = get_remote_data_command(mock_client(), {'id': 'incident-1', 'lastUpdate': '2023-01-06T08:17:09Z'})
    assert result.mirrored_object == {'ID': 'incident-1'}
    assert result.entries == []


def test_get_remote_incident_data(mocker):
    """
    Given
        - client
        - incident id
    When
        - running get_remote_incident_data
    Then
        Verify the function returns the expected mirrored data and updated object
    """
    client = mock_client()
    mock_response = {'name': 'id-incident-1', 'properties': {'title': 'title-incident-1', 'additionalData': {'alertsCount': 0}}}
    mocker.patch.object(client, 'http_request', return_value=mock_response)

    result = get_remote_incident_data(client, 'id-incident-1')
    assert result == (
        mock_response,
        {'ID': 'id-incident-1', 'Title': 'title-incident-1', 'AlertsCount': 0, 'tags': [], 'relatedAnalyticRuleIds': []}
    )


@pytest.mark.parametrize("incident, expected_contents", [
    (
        {'ID': 'id-incident-1', 'Status': 'Closed', 'classification': 'BenignPositive'},
        {'dbotIncidentClose': True, 'closeReason': 'Resolved', 'closeNotes': 'Closed on Microsoft Sentinel'}
    ),
    (
        {'ID': 'id-incident-1', 'Status': 'Active'},
        {'dbotIncidentReopen': True}
    ),
])
def test_set_xsoar_incident_entries(mocker, incident, expected_contents):
    """
    Given
        - incident
        - entries
    When
        - running set_xsoar_incident_entries
    Then
        - Ensure the entries were updated with the expected contents
    """
    mocker.patch.object(demisto, 'params', return_value={'close_incident': True})
    entries: list = []
    set_xsoar_incident_entries(incident, entries, 'id-incident-1')
    assert entries[0].get('Contents') == expected_contents


def test_get_mapping_fields_command():
    """
    Given
        - nothing
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping scheme
    """
    result = get_mapping_fields_command()
    assert result.scheme_types_mappings[0].type_name == 'Microsoft Sentinel Incident'
    assert result.scheme_types_mappings[0].fields.keys() == {'description', 'status', 'lastActivityTimeUtc',
                                                             'classificationReason', 'tags', 'classificationComment',
                                                             'severity', 'firstActivityTimeUtc', 'classification',
                                                             'title', 'etag'}


def test_update_remote_system_command(mocker):
    """
    Given
        - client
        - args with remoteId, status, data and delta
    When
        - running update_remote_system_command
    Then
        - Ensure the function returns the expected incident id
    """
    mocker.patch('AzureSentinel.update_remote_incident', return_value={})

    args = {'remoteId': 'incident-1',
            'status': 1,
            'data': {'title': 'Title', 'severity': 2, 'status': 1},
            'delta': {'title': 'New Title', 'severity': 3}}

    result = update_remote_system_command(mock_client(), args)
    assert result == 'incident-1'


@pytest.mark.parametrize("incident_status, close_incident_in_remote, delta, expected_update_call", [
    (IncidentStatus.DONE, True, {}, True),
    (IncidentStatus.DONE, False, {}, False),  # delta is empty
    (IncidentStatus.DONE, False, {'classification': 'FalsePositive'}, False),  # delta have only closing fields
    (IncidentStatus.DONE, False, {'title': 'Title'}, True),  # delta have fields except closing fields
    (IncidentStatus.ACTIVE, True, {}, False),  # delta is empty and close_incident_in_remote is False
    (IncidentStatus.ACTIVE, False, {'title': 'Title'}, True),
    (IncidentStatus.PENDING, True, {}, False),
])
def test_update_remote_incident(mocker, incident_status, close_incident_in_remote, delta, expected_update_call):
    """
    Given
        - incident status
    When
        - running update_remote_incident
    Then
        - ensure the function call only when the incident status is DONE and close_incident_in_remote is True
          or when the incident status is ACTIVE
    """
    mocker.patch('AzureSentinel.close_incident_in_remote', return_value=close_incident_in_remote)
    mock_update_status = mocker.patch('AzureSentinel.update_incident_request')
    update_remote_incident(mock_client(), {}, delta, incident_status, 'incident-1')
    assert mock_update_status.called == expected_update_call


@pytest.mark.parametrize('delta, data, close_ticket_param, to_close', [
    ({'classification': 'FalsePositive'}, {}, True, True),
    ({'classification': 'FalsePositive'}, {}, False, False),
    ({}, {}, True, False),
    ({}, {}, False, False),
    # Closing after classification is already present in the data.
    ({}, {'classification': 'FalsePositive'}, True, True),
    # Closing after reopened, before data update
    ({}, {'classification': 'FalsePositive', 'status': 'Closed'}, True, True),
    # Closing after reopened, after data update
    ({}, {'classification': 'FalsePositive', 'status': 'Active'}, True, True)
])
def test_close_incident_in_remote(mocker, delta, data, close_ticket_param, to_close):
    """
    Given
        - one of the close parameters
    When
        - outgoing mirroring triggered by a change in the incident
    Then
        - returns true if the incident was closed in XSOAR and the close_ticket parameter was set to true
    """
    mocker.patch.object(demisto, 'params', return_value={'close_ticket': close_ticket_param})
    assert close_incident_in_remote(delta, data) == to_close


@pytest.mark.parametrize("data, delta, mocked_fetch_data, expected_response, close_ticket", [
    (   # Update description of active incident.
        {'title': 'Title', 'description': 'old desc', 'severity': 2, 'status': 'Active'},
        {'title': 'Title', 'description': 'new desc'},
        {'title': 'Title', 'description': 'old desc', 'severity': 'Medium', 'status': 'Active'},
        {'title': 'Title', 'description': 'new desc', 'severity': 'Medium', 'status': 'Active'},
        False
    ),
    (   # Update runStatus (not mirror field) of active incident - shouldn't run the update,
        # and will return {}
        {'title': 'Title', 'description': 'old desc', 'severity': 2, 'status': 'New'},
        {'runStatus': 'running'},
        {'title': 'Title', 'description': 'old desc', 'severity': 'Medium', 'status': 'New'},
        {},
        False
    ),
    (   # Update runStatus (not mirror field) of Closed incident - should close the ticket,
        {'title': 'Title', 'description': 'old desc', 'severity': 1, 'status': 'New'},
        {'runStatus': 'running', 'classification': 'Undetermined'},
        {'title': 'Title', 'severity': 'Low', 'status': 'Active'},
        {'title': 'Title', 'severity': 'Low', 'status': 'Closed', 'classification': 'Undetermined'},
        True
    ),
    (   # Update description and classification and close incident.
        {'title': 'Title', 'description': 'old desc', 'severity': 1, 'status': 'Active'},
        {'title': 'Title', 'description': 'new desc', 'classification': 'Undetermined'},
        {'title': 'Title', 'description': 'old desc', 'severity': 'Low', 'status': 'Active'},
        {'title': 'Title', 'description': 'new desc', 'severity': 'Low', 'status': 'Closed', 'classification': 'Undetermined'},
        True
    ),
    (   # Update description and classification of active incident without closing. Result in description update only.
        {'title': 'Title', 'description': 'old desc', 'severity': 1, 'status': 'Active'},
        {'title': 'Title', 'description': 'new desc', 'classification': 'Undetermined'},
        {'title': 'Title', 'description': 'old desc', 'severity': 'Low', 'status': 'Active'},
        {'title': 'Title', 'description': 'new desc', 'severity': 'Low', 'status': 'Active'},
        False
    ),
    (   # Update title and close incident with classification already in data. Result in closing with classification.
        {'title': 'Title', 'severity': 1, 'status': 'Active', 'classification': 'Undetermined'},
        {'title': 'Title'},
        {'title': 'Title', 'severity': 'Low', 'status': 'Active', 'classification': 'Undetermined'},
        {'title': 'Title', 'severity': 'Low', 'status': 'Closed', 'classification': 'Undetermined'},
        True
    ),
    (  # Update labels of active incident when no labels exist.
        {'title': 'Title', 'description': 'desc', 'severity': 2, 'status': 'Active', 'tags': []},
        {'title': 'Title', 'tags': ['Test']},
        {'title': 'Title', 'description': 'desc', 'severity': 'Medium', 'status': 'Active'},
        {'title': 'Title', 'severity': 'Medium', 'status': 'Active', 'labels': [{'labelName': 'Test', 'type': 'User'}]},
        False
    ),
    (   # Update labels of active incident when a label already exist.
        {'title': 'Title', 'description': 'desc', 'severity': 2, 'status': 'Active', 'tags': ['Test']},
        {'title': 'Title', 'tags': ['Test2']},
        {'title': 'Title', 'description': 'desc', 'severity': 'Medium', 'status': 'Active',
         'properties': {'labels': [{'labelName': 'Test', 'type': 'User'}]}},
        {'title': 'Title', 'severity': 'Medium', 'status': 'Active',
         'labels': [{'labelName': 'Test', 'type': 'User'}, {'labelName': 'Test2', 'type': 'User'}]},
        False
    )
])
def test_update_incident_request(mocker, data, delta, mocked_fetch_data, expected_response, close_ticket):
    """
    Given
        - data: The incident data before the update in xsoar.
        - delta: The changes in the incident made in xsoar.
        - mocked fetched current data: The incident data before the update in sentinel.
    When
        - running update_incident_request
    Then
        - Ensure the client.http_request was called with the expected data
    """
    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value=mocked_fetch_data)

    update_incident_request(client, 'id-incident-1', data, delta, close_ticket)
    assert not expected_response or client.http_request.call_args[1]['data'].get('properties') == expected_response


@pytest.mark.parametrize("args", [
    ({}),
    ({"limit": 1}),
    ({"limit": 2}),
    ({'rule_id': 'rule1'})
])
def test_list_alert_rule_command(mocker, args):
    """
    Given
        - client
        - args with limit or rule_id
    When
        - running list_alert_rule_command
    Then
        - Ensure the function returns the expected alert rule
    """
    prefix_file = 'get' if args.get('rule_id') else 'list'
    with open(f'test_data/{prefix_file}_alert_rule-mock_response.json') as file:
        mock_response = json.load(file)

    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value=mock_response)
    command_results = list_alert_rule_command(client, args)

    if limit := args.get("limit"):
        assert len(command_results.outputs) == limit
        assert command_results.outputs == mock_response.get("value", [])[:limit]

    elif rule_id := args.get("rule_id"):
        assert command_results.outputs == [mock_response]
        assert command_results.outputs[0].get("name") == rule_id

    else:
        assert command_results.outputs == mock_response.get("value", [])
        assert len(command_results.outputs) == len(mock_response.get("value", []))


@pytest.mark.parametrize("args", [
    ({}),
    ({"limit": 1}),
    ({"limit": 2}),
    ({'template_id': 'template1'})
])
def test_list_alert_rule_template_command(mocker, args):
    """
    Given
        - client
        - args with limit or rule_id
    When
        - running list_alert_rule_template_command
    Then
        - Ensure the function returns the expected alert rule template
    """
    prefix_file = 'get' if args.get('template_id') else 'list'
    with open(f'test_data/{prefix_file}_alert_rule_template-mock_response.json') as file:
        mock_response = json.load(file)

    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value=mock_response)
    command_results = list_alert_rule_template_command(client, args)

    if limit := args.get("limit"):
        assert len(command_results.outputs) == limit
        assert command_results.outputs == mock_response.get("value", [])[:limit]

    elif rule_id := args.get("template_id"):
        assert command_results.outputs == [mock_response]
        assert command_results.outputs[0].get("name") == rule_id

    else:
        assert command_results.outputs == mock_response.get("value", [])
        assert len(command_results.outputs) == len(mock_response.get("value", []))


@pytest.mark.parametrize("mock_response, expected_readable_output, expected_outputs", [
    ({}, 'Alert rule rule1 was deleted successfully.', {'ID': 'rule1', 'Deleted': True}),  # 200 response
    (mock_204_response(), 'Alert rule rule1 does not exist.', None)  # 204 response
])
def test_delete_alert_rule_command(mocker, mock_response, expected_readable_output, expected_outputs):
    """
    Given
        - args with rule_id
    When
        - running delete_alert_rule_command
    Then
        - Ensure the function returns the expected command results
    """
    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value=mock_response)
    command_results = delete_alert_rule_command(client, {'rule_id': 'rule1'})

    assert command_results.readable_output == expected_readable_output


def test_validate_required_arguments_for_alert_rule():
    """
    Given
        - args with all required arguments
        - args with missing required arguments
    When
        - running validate_required_arguments_for_alert_rule
    Then
        - if all required arguments are provided, ensure the function returns nothing
        - if a required argument is missing, ensure the function raises a ValueError
    """
    # Test with a fusion alert rule with all required arguments
    args = {
        'kind': 'fusion',
        'rule_name': 'test_fusion_rule',
        'template_name': 'test_template',
        'enabled': True
    }
    validate_required_arguments_for_alert_rule(args)

    # Test with a scheduled alert rule with all required arguments
    args = {
        'kind': 'scheduled',
        'rule_name': 'test_scheduled_rule',
        'displayName': 'test_display_name',
        'enabled': True,
        'query': 'test_query',
        'query_frequency': 'test_frequency',
        'query_period': 'test_period',
        'severity': 'test_severity',
        'suppression_duration': 'test_duration',
        'suppression_enabled': True,
        'trigger_operator': 'test_operator',
        'trigger_threshold': 10
    }
    validate_required_arguments_for_alert_rule(args)

    # Test with a fusion alert rule with a missing required argument
    args = {
        'kind': 'fusion',
        'rule_name': 'test_fusion_rule',
        'enabled': True
    }
    with pytest.raises(Exception) as e:
        validate_required_arguments_for_alert_rule(args)
    assert str(e.value) == '"template_name" is required for "fusion" alert rule.'

    # Test without a kind argument
    args = {
        'rule_name': 'test_unknown_rule'
    }
    with pytest.raises(Exception) as e:
        validate_required_arguments_for_alert_rule(args)
    assert str(e.value) == 'The "kind" argument is required for alert rule.'


def test_create_data_for_alert_rule():
    """
    Given
        - args
    When
        - running create_data_for_alert_rule
    Then
        - Ensure the function returns the expected data
    """
    args = {
        'kind': 'fusion',
        'rule_name': 'test_fusion_rule',
        'template_name': 'test_template',
        'enabled': True,
        'description': None
    }
    expected_data = {
        'kind': 'Fusion',
        'etag': None,
        'properties': {
            'alertRuleTemplateName': 'test_template',
            'enabled': True
        }
    }
    data = create_data_for_alert_rule(args)
    assert data == expected_data


def test_create_and_update_alert_rule_command(mocker):
    """
    Given
        - client
        - args with all required arguments
    When
        - running create_alert_rule_command
    Then
        - Ensure the function returns the expected command results
    """
    with open('test_data/create_alert_rule-mock_response.json') as file:
        mock_response = json.load(file)

    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value=mock_response)
    args = {
        'kind': 'Fusion',
        "etag": "3d00c3ca-0000-0100-0000-5d42d5010000",
        "properties": {
            "enabled": True,
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8"
        }
    }
    mocker.patch('AzureSentinel.create_data_for_alert_rule', return_value=args)
    command_results = create_and_update_alert_rule_command(client, args)
    assert command_results.outputs == mock_response
    assert command_results.outputs_prefix == 'AzureSentinel.AlertRule'
    assert command_results.outputs_key_field == 'name'
    assert '|ID|Name|Kind|Severity|Display Name|Description|Enabled|Etag|' in command_results.readable_output


def test_list_incident_comments_command_happy_path(mocker):
    """
    Given:
    - Valid incident ID, limit, and next link.

    When:
    - Calling the list_incident_comments_command function.

    Then:
    - Ensure the function successfully retrieves comments for the given incident ID with and without
    a specified limit and next link.
    - Ensure the function returns the expected CommandResults object.
    """

    client = mocker.Mock()
    args = {
        'incident_id': '123',
        'limit': '50',
        'next_link': ''
    }
    result = {
        'value': [
            {
                'name': 'comment1',
                'properties': {
                    'message': 'test comment 1',
                    'author': {
                        'assignedTo': 'test user',
                        'email': 'test@test.com'
                    },
                    'createdTimeUtc': '2022-01-01T00:00:00Z'
                }
            },
            {
                'name': 'comment2',
                'properties': {
                    'message': 'test comment 2',
                    'author': {
                        'assignedTo': 'test user 2',
                        'email': 'test2@test.com'
                    },
                    'createdTimeUtc': '2022-01-02T00:00:00Z'
                }
            }
        ],
        'nextLink': ''
    }
    client.http_request.return_value = result

    expected_comments = [
        {
            'ID': 'comment1',
            'IncidentID': '123',
            'Message': 'test comment 1',
            'AuthorName': 'test user',
            'AuthorEmail': 'test@test.com',
            'CreatedTimeUTC': '2022-01-01T00:00:00Z'
        },
        {
            'ID': 'comment2',
            'IncidentID': '123',
            'Message': 'test comment 2',
            'AuthorName': 'test user 2',
            'AuthorEmail': 'test2@test.com',
            'CreatedTimeUTC': '2022-01-02T00:00:00Z'
        }
    ]

    expected_outputs = {
        'AzureSentinel.IncidentComment(val.ID === obj.ID && val.IncidentID === 123)': expected_comments
    }

    expected_readable_output = tableToMarkdown('Incident 123 Comments (2 results)', expected_comments,
                                               headers=COMMENT_HEADERS, headerTransform=pascalToSpace, removeNull=True)

    # Execute the test
    assert list_incident_comments_command(client, args).readable_output == CommandResults(
        readable_output=expected_readable_output,
        outputs=expected_outputs,
        raw_response=result
    ).readable_output


def test_update_incident_command_table_to_markdown(mocker):
    """
    Given:
    - A valid incident_id and incident data.

    When:
    - Calling update_incident_command function.

    Then:
    - Ensure that the function formats the output table correctly.
    """
    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value={'id': '123', 'title': 'test', 'severity': 'High'})
    args = {'incident_id': '123', 'title': 'new title', 'description': 'new description', 'severity': 'High'}
    result = update_incident_command(client, args)
    expected_output = '### Updated incidents 123 details\n**No entries.**'
    assert result.readable_output.strip() == expected_output


def test_create_incident_command(mocker):
    """
    Given:
    - Valid incident data.

    When:
    - Calling create_incident_command function.

    Then:
    - The command function returns the expected raw response from the API.
    """
    test_data = {'id': '123', 'title': 'test', 'severity': 'High',
                 'description': 'test description', 'labels': [{'LabelName': 'value'}]}

    client = mock_client()
    mocker.patch.object(client, 'http_request', return_value=test_data)

    result = create_incident_command(client, test_data)

    assert result.raw_response == test_data


def test_update_incident_with_client_changed_etag(mocker):
    """
    Given:
        - An old incident to update with a delta from xsoar.
        - A newer version is returned from the client.

    When:
        - Updating the incident.

    Then:
        - Ensure the most updated etag is sent on update to avoid conflicts.
    """
    client = mock_client()
    old_incident_data_in_xsoar = {
        'etag': 'tag-version1', 'title': 'Title version 1', 'severity': 1, 'status': 2, 'classification': 'Undetermined'
    }
    delta_incident_changes = {
        'severity': 2
    }

    # Changed etag and title.
    newer_incident_from_azure = {
        'etag': 'tag-version2',
        'properties': {'title': 'Title version 2', 'severity': 1, 'status': 2, 'classification': 'Undetermined'}
    }

    # return newer version when requesting incident
    http_request_mock = mocker.patch.object(client, 'http_request', side_effect=[newer_incident_from_azure, True])
    update_incident_request(client, 'id-incident-1', old_incident_data_in_xsoar, delta_incident_changes, False)

    assert http_request_mock.call_count == 2
    assert http_request_mock.call_args[1].get('data', {}).get('etag') == newer_incident_from_azure.get('etag')


@pytest.mark.parametrize(
    "delta, data, expected",
    [
        (
            {
                "classification": "FalsePositive",
                "classificationReason": "InaccurateData",
            },
            {},
            "InaccurateData",
        ),
        (
            {"classification": "FalsePositive"},
            {"classificationReason": "SystemError"},
            "SystemError",
        ),
        ({"classification": "FalsePositive"}, {}, "InaccurateData"),
        (
            {
                "classification": "TruePositive",
                "classificationReason": "InaccurateData",
            },
            {},
            "SuspiciousActivity",
        ),
        ({}, {"classification": "BenignPositive"}, "SuspiciousButExpected"),
        ({}, {}, ""),
    ],
    ids=[
        "FalsePositive classification with specific reason in delta",
        "FalsePositive classification with reason in data",
        "FalsePositive classification without specific reason",
        "TruePositive classification with default reason",
        "No classification in delta, but classification in data",
        "No classification in delta or data",
    ],
)
def test_extract_classification_reason(delta, data, expected):
    result = extract_classification_reason(delta, data)
    assert result == expected
