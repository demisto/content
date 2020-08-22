import json
import requests
import pytest
import demistomock as demisto

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# qa multitenant
# integration_params = {
#     'base_url': 'https://172.31.132.110',
#     'username': 'danno@respond-software.com',
#     'password': '7s3&cN#rr05f!eIpLN',
#     'insecure': True
# }

# qa 5
integration_params = {
    'base_url': 'https://172.31.17.138',
    'username': 'danno@respond-software.com',
    'password': '16ohV7QHn5l&hw7#bW',
    'insecure': True
}

params = {
    'base_url': 'https://localhost:6078',
    'username': 'qa-user@respond-software.com',
    'password': 'password',
    'insecure': True
}


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=params)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_fetch_incidents_does_not_get_most_recent_event_again(mocker, requests_mock):
    from Respond_Analyst import fetch_incidents, RestClient, GraphQLClient

    get_ids_response = {'incidents': []}
    get_full_incidents_response = {'fullIncidents': []}

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    last_run = {
        'Tenant 1': {'time': 1593044883}
    }

    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    mocker.patch.object(gql_client, 'construct_and_send_get_incident_ids_query', return_value=get_ids_response)
    mocker.patch.object(gql_client, 'construct_and_send_full_incidents_query', return_value=get_full_incidents_response)

    next_run, incidents = fetch_incidents(client, last_run, gql_client)
    assert len(incidents) == 0
    assert next_run['Tenant 1']['time'] == 1593044883
    assert next_run['Tenant 2']['time'] is None


def test_get_incident_command(mocker, requests_mock):
    from Respond_Analyst import get_incident_command, RestClient, GraphQLClient

    full_incidents_response = {
        "fullIncidents": [
            {
                "assetClass": "Critical",
                "attackStage": "LateralMovement",
                "dateCreated": "1591374021992",
                "eventCount": 24,
                "feedback": {
                    "closedAt": "1593468999299",
                    "closedBy": "qa-user@respond-software.com",
                    "newStatus": "NonActionable",
                    "optionalText": "blah blah blah",
                    "timeGiven": "1593469076049",
                    "userId": "qa-user@respond-software.com"
                },
                "firstEventTime": "1576933531016",
                "id": "6",
                "internalSystems": [
                    {
                        "hostname": "enterprise.com"
                    }
                ],
                "internalSystemsCount": 1,
                "lastEventTime": "1591345217664",
                "priority": "Critical",
                "probabilityBucket": "VeryHigh",
                "status": "Closed",
                "tags": [
                    {
                        "label": "Multiple Network IPS Signatures Triggered by Same Internal Asset"
                    }
                ],
                "title": "Virus Infections, Suspicious Repeated Connections and Int - Int Network IPS Activity",
                "userIds": [
                    "cbe263b5-c2ff-42e9-9d7a-bff7a3261d4a"
                ]
            }
        ]
    }

    expected_result = {'name': 'Tenant 1: 6', 'occurred': '2020-06-05T09:20:21Z',
                       'rawJSON': '{"incidentId": "6", "timeGenerated": "2020-06-05T09:20:21Z", "eventCount": 24, '
                                  '"firstEventTime": "2019-12-21T05:05:31Z", "lastEventTime": "2020-06-05T01:20:17Z", '
                                  '"URL": "https://localhost:6078/secure/incidents/6?tenantId=dev1", "closeURL": '
                                  '"https://localhost:6078/secure/incidents/feedback/6?tenantId=dev1", '
                                  '"title": "Virus Infections, Suspicious Repeated Connections and Int - Int Network '
                                  'IPS Activity", "status": "Closed", "severity": "Critical", "probability": '
                                  '"VeryHigh", "attackStage": "LateralMovement", "attackTactic": null, '
                                  '"assetCriticality": "Critical", "internalSystemsCount": 1, "internalSystems": [{'
                                  '"hostname": "enterprise.com"}], "escalationReasons": [{"label": "Multiple Network '
                                  'IPS Signatures Triggered by Same Internal Asset"}], "assignedUsers": ['
                                  '"cbe263b5-c2ff-42e9-9d7a-bff7a3261d4a"], "feedback": {"timeUpdated": '
                                  '"1593469076049", "userId": "qa-user@respond-software.com", "outcome": '
                                  '"NonActionable", "comments": "blah blah blah"}, "tenantIdRespond": "dev1", '
                                  '"tenantId": "Tenant 1"}'}

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    mocker.patch.object(gql_client, 'construct_and_send_full_incidents_query', return_value=full_incidents_response)
    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 6
    }
    incident = get_incident_command(client, args, gql_client)
    assert incident == expected_result


def test_fetch_incidents_no_new(mocker, requests_mock):
    from Respond_Analyst import fetch_incidents, RestClient, GraphQLClient

    get_ids_response = {'incidents': []}
    get_full_incidents_response = {'fullIncidents': []}

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    last_run = {
        'Tenant 1': {'time': 1593044883}
    }

    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    mocker.patch.object(gql_client, 'construct_and_send_get_incident_ids_query', return_value=get_ids_response)
    mocker.patch.object(gql_client, 'construct_and_send_full_incidents_query', return_value=get_full_incidents_response)

    next_run, incidents = fetch_incidents(client, last_run, gql_client)
    assert len(incidents) == 0
    assert next_run['Tenant 1']['time'] == 1593044883
    assert next_run['Tenant 2']['time'] is None


def test_fetch_incidents(mocker, requests_mock):
    from Respond_Analyst import fetch_incidents, RestClient, GraphQLClient

    get_ids_response = {
        'incidents': [{'id': '6'}, {'id': '8'}, {'id': '11'}, {'id': '14'}, {'id': '16'}, {'id': '27'}]}

    get_full_incidents_response = load_test_data('test_data/full_incidents.json')
    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    mocker.patch.object(gql_client, 'construct_and_send_get_incident_ids_query', return_value=get_ids_response)
    mocker.patch.object(gql_client, 'construct_and_send_full_incidents_query', return_value=get_full_incidents_response)

    expected_output = load_test_data('test_data/fetch_incidents_response.json')

    next_run, response = fetch_incidents(client, None, gql_client)
    assert expected_output == response
    assert next_run['Tenant 1']['time'] == '1591374031591'


def test_remove_user(mocker, requests_mock):
    from Respond_Analyst import remove_user_command, RestClient, GraphQLClient
    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )
    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )
    get_all_users_response = load_test_data('test_data/users.json')
    remove_user_response = {'removeUserFromIncident': {'id': '5', 'userIds': []}}
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(gql_client, 'construct_and_send_remove_user_from_incident_mutation',
                        return_value=remove_user_response)
    requests_mock.get(
        'https://localhost:6078/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        'https://localhost:6078/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1', 'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user2@respond-software.com'
    }
    res = remove_user_command(rest_client, args, gql_client)
    assert res == 'user with email: qa-user2@respond-software.com removed from incident with id 5 on tenant Tenant 1'


def test_assign_user(mocker, requests_mock):
    from Respond_Analyst import assign_user_command, RestClient, GraphQLClient

    assign_user_response = {'addUserToIncident': {'id': '5', 'userIds': ['675ad53a-d8f4-4ae7-9a3a-59de6c70b912']}}
    get_all_users_response = load_test_data('test_data/users.json')
    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )
    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(gql_client, 'construct_and_send_add_user_to_incident_mutation',
                        return_value=assign_user_response)

    requests_mock.get(
        'https://localhost:6078/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        'https://localhost:6078/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1', 'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user2@respond-software.com',
    }
    res = assign_user_command(rest_client, args, gql_client)
    assert res == 'user with email: qa-user2@respond-software.com added to incident with id 5 on tenant Tenant 1'
    # demisto.info.assert_called_with(
    #     'user with email: qa-user2@respond-software.com added to incident with id 5 on tenant Tenant 1')

    # no tenant id provided
    args = {
        'incident_id': 5,
        'username': 'qa-user3@respond-software.com',
    }
    res = assign_user_command(rest_client, args, gql_client)
    assert res == 'user with email: qa-user3@respond-software.com added to incident with id 5 on tenant Tenant 1'
    # demisto.info.assert_called_with(
    #     'user with email: qa-user3@respond-software.com added to incident with id 5 on tenant Tenant 1')


def test_close_incident(mocker, requests_mock):
    from Respond_Analyst import close_incident_command, RestClient, GraphQLClient

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'info')

    get_all_users_response = load_test_data('test_data/users.json')
    close_incident_response = load_test_data('test_data/close_incident_response.json')
    single_full_incident_response = load_test_data('test_data/single_full_incident.json')

    mocker.patch.object(gql_client, 'construct_and_send_close_incident_mutation', return_value=close_incident_response)
    mocker.patch.object(gql_client, 'construct_and_send_full_incidents_query',
                        return_value=single_full_incident_response)
    requests_mock.get(
        'https://localhost:6078/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        'https://localhost:6078/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1', 'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'incident_feedback': 'NonActionable',
        'feedback_selected_options': [{'id': '4', 'key': 'unmonitoredAssets', 'value': 'true'},
                                      {'id': '19', 'key': 'scopedCorrectly', 'value': 'No'}],
        'incident_comments': 'new text',
    }

    res = close_incident_command(rest_client, args, gql_client)
    assert "incident closed and/or feedback updated for incident with id 5 on tenant Tenant 1" in res

    # no tenant id
    args = {
        'incident_id': 6,
        'incident_feedback': 'NonActionable',
        'feedback_selected_options': [{'id': '4', 'key': 'unmonitoredAssets', 'value': 'true'},
                                      {'id': '19', 'key': 'scopedCorrectly', 'value': 'No'}],
        'incident_comments': 'new text',
    }

    # not expecting a different id bc of mocked responses, just expecting a successful response
    res == close_incident_command(rest_client, args, gql_client)
    assert 'incident closed and/or feedback updated for incident with id 5 on tenant Tenant 1' in res


def test_assign_user_raise_exception(mocker, requests_mock):
    from Respond_Analyst import assign_user_command, RestClient, GraphQLClient

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'error')

    get_all_users_response = load_test_data('test_data/users.json')
    mocker.patch.object(gql_client, 'construct_and_send_add_user_to_incident_mutation', return_value=Exception)
    requests_mock.get(
        'https://localhost:6078/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        'https://localhost:6078/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1', 'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )
    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user2@respond-software.com',
    }
    with pytest.raises(Exception):
        assign_user_command(rest_client, args, gql_client)
    demisto.error.assert_any_call("error adding user to incident: type object 'Exception' has no attribute 'get'")


def test_remove_user_raises_exception(mocker, requests_mock):
    from Respond_Analyst import remove_user_command, RestClient, GraphQLClient

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'error')

    get_all_users_response = load_test_data('test_data/users.json')
    mocker.patch.object(gql_client, 'construct_and_send_remove_user_from_incident_mutation', return_value=Exception)
    requests_mock.get(
        'https://localhost:6078/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        'https://localhost:6078/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1', 'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )
    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user4@respond-software.com'
    }
    with pytest.raises(Exception):
        remove_user_command(rest_client, args, gql_client)

    demisto.error.assert_called_once_with(
        'no user found with email qa-user4@respond-software.com')


def test_close_incident_with_bad_responses(mocker, requests_mock):
    from Respond_Analyst import close_incident_command, RestClient, GraphQLClient

    gql_client = GraphQLClient(
        tenant_id='dev1',
        auth=('un', 'pw'),
        fetch_schema_from_transport=False
    )

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'error')

    get_all_users_response = load_test_data('test_data/users.json')

    mocker.patch.object(gql_client, 'construct_and_send_close_incident_mutation', return_value=Exception)
    mocker.patch.object(gql_client, 'construct_and_send_full_incidents_query', return_value=Exception)
    requests_mock.get(
        'https://localhost:6078/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        'https://localhost:6078/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        'https://localhost:6078/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1', 'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'incident_feedback': 'NonActionable',
        'feedback_selected_options': [{'id': '4', 'key': 'unmonitoredAssets', 'value': 'true'},
                                      {'id': '19', 'key': 'scopedCorrectly', 'value': 'No'}],
        'incident_comments': 'new text',
    }
    with pytest.raises(Exception):
        close_incident_command(rest_client, args, gql_client)

    demisto.error.assert_any_call(
        "error closing incident and/or updating feedback: type object 'Exception' has no attribute 'get'")

# INTEGRATION TESTS
# the reason I have these commented out is that they are setup against the mock and thus will fail if mock is not up
# I think it might make some sense to set these up against qa5 or another dev environment
# they are useful to have down here for future testing maybe?
# def test_fetch_incidents():
#     from Respond_Analyst import fetch_incidents, RestClient
#     rest_client = RestClient(
#         base_url=integration_params['base_url'],
#         auth=(integration_params['username'], integration_params['password']),
#         verify=False
#     )
#
#     last_run = {'remote': {'time': '1589088564211'}, 'qadenver': {'time': '1589088563403'},
#                 'qa650castro': {'time': '1589088563246'}, 'qa785castro': {'time': '1589088562685'}}
#
#     # last_run = {'QA 5': {'time': '1594078335866'}}
#
#
#     next_run, incidents = fetch_incidents(rest_client, last_run)
#     print(len(incidents))
#     print(json.dumps(incidents, sort_keys=True, indent=2, separators=(',', ': ')))
#     assert False

# def test_assign_user():
#     from Respond_Analyst import assign_user_command, RestClient
#     rest_client = RestClient(
#         base_url=integration_params['base_url'],
#         auth=(integration_params['username'], integration_params['password']),
#         verify=False
#     )
#
#     args = {
#         'incident_id': 6,
#         'username': 'danno@respond-software.com',
#     }
#
#     result = assign_user_command(rest_client, args)
#     print(result)
#     # print(json.dumps(incidents, sort_keys=True, indent=2, separators=(',', ': ')))
#     assert False


# def test_remove_user():
#     from Respond_Analyst import remove_user_command, RestClient
#     rest_client = RestClient(
#         base_url=integration_params['base_url'],
#         auth=(integration_params['username'], integration_params['password']),
#         verify=False
#     )
#
#     args = {
#         'incident_id': 6,
#         'username': 'danno@respond-software.com',
#     }
#
#     result = remove_user_command(rest_client, args)
#     print(result)
#     # print(json.dumps(incidents, sort_keys=True, indent=2, separators=(',', ': ')))
#     assert False
#
# def test_close_incident():
#     from Respond_Analyst import close_incident_command, RestClient
#     rest_client = RestClient(
#         base_url=integration_params['base_url'],
#         auth=(integration_params['username'], integration_params['password']),
#         verify=False
#     )
#
#     args = {
#         'incident_id': 372,
#         'username': 'danno@respond-software.com',
#         'incident_feedback': 'ConfirmedIncident'
#     }
#
#     result = close_incident_command(rest_client, args)
#     # print(result)
#     # print(json.dumps(incidents, sort_keys=True, indent=2, separators=(',', ': ')))
#     assert False

# def test_get_incident_command():
#     from Respond_Analyst import get_incident_command, GraphQLClient, RestClient
#     rest_client = RestClient(
#         base_url='https://localhost:6078',
#         auth=('qa-user@respond-software.com', 'password'),
#         verify=False
#     )
#     args = {
#         'tenant_id': 'Tenant 1',
#         'incident_id': 6
#     }
#     incident = get_incident_command(rest_client, args)
#     print(json.dumps(incident, sort_keys=True, indent=2, separators=(',', ': ')))
