import json
import requests
import pytest
import demistomock as demisto

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = 'https://localhost:6078'

params = {
    'base_url': BASE_URL,
    'username': 'qa-user@respond-software.com',
    'password': 'password',
    'insecure': True,
    'mirror_direction': 'Incoming'
}


@pytest.fixture(autouse=True)
def set_mocker(mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'integrationInstance', return_value='respond_test')
    mocker.patch.object(demisto, 'findUser', return_value={'username': 'user1'})


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_fetch_incidents_does_not_get_most_recent_event_again(mocker, requests_mock):
    from RespondAnalyst import fetch_incidents, RestClient

    get_ids_response = []
    get_full_incidents_response = []

    client = RestClient(
        base_url=BASE_URL,
        auth=('un', 'pw'),
        verify=False
    )

    last_run = {
        'Tenant 1': {'time': 1593044883}
    }

    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    mocker.patch.object(client, 'construct_and_send_get_incident_ids_query',
                        return_value=get_ids_response)
    mocker.patch.object(client, 'construct_and_send_full_incidents_query',
                        return_value=get_full_incidents_response)

    next_run, incidents = fetch_incidents(client, last_run)
    assert len(incidents) == 0
    assert next_run['Tenant 1']['time'] == 1593044883
    assert next_run['Tenant 2']['time'] is None


def test_get_incident_command(requests_mock):
    from RespondAnalyst import get_incident_command, RestClient

    full_incidents_response = load_test_data(
        'test_data/full_incidents_response_single_full_incident.json')

    expected_result = load_test_data('test_data/get_incident_response.json')

    client = RestClient(
        base_url=BASE_URL,
        auth=('un', 'pw'),
        verify=False
    )

    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    requests_mock.post(
        f'{BASE_URL}/graphql?tenantId=dev1',
        json=full_incidents_response
    )
    args = {
        'respond_tenant_id': 'Tenant 1',
        'incident_id': 6
    }
    incident = get_incident_command(client, args)
    assert incident == expected_result


def test_fetch_incidents_no_new(mocker, requests_mock):
    from RespondAnalyst import fetch_incidents, RestClient

    get_ids_response = []
    get_full_incidents_response = []

    client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    last_run = {
        'Tenant 1': {'time': 1593044883}
    }

    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    mocker.patch.object(client, 'construct_and_send_get_incident_ids_query',
                        return_value=get_ids_response)
    mocker.patch.object(client, 'construct_and_send_full_incidents_query',
                        return_value=get_full_incidents_response)

    next_run, incidents = fetch_incidents(client, last_run)
    assert len(incidents) == 0
    assert next_run['Tenant 1']['time'] == 1593044883
    assert next_run['Tenant 2']['time'] is None


def test_fetch_incidents(mocker, requests_mock):
    from RespondAnalyst import fetch_incidents, RestClient

    get_ids_response = [{'id': '6'}, {'id': '8'}, {'id': '11'}, {'id': '14'}, {'id': '16'},
                        {'id': '27'}]

    get_full_incidents_response = load_test_data('test_data/full_incidents.json')

    client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    mocker.patch.object(client, 'construct_and_send_get_incident_ids_query',
                        return_value=get_ids_response)
    mocker.patch.object(client, 'construct_and_send_full_incidents_query',
                        return_value=get_full_incidents_response)

    expected_output = load_test_data('test_data/fetch_incidents_response.json')

    next_run, response = fetch_incidents(client, None)
    assert expected_output == response
    assert next_run['Tenant 1']['time'] == '1591374031591'


def test_remove_user(mocker, requests_mock):
    from RespondAnalyst import remove_user_command, RestClient

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )
    get_all_users_response = load_test_data('test_data/users.json')
    remove_user_response = {'data': {'removeUserFromIncident': {'id': '5', 'userIds': []}}}
    mocker.patch.object(demisto, 'info')

    requests_mock.post(
        f'{BASE_URL}/graphql?tenantId=dev1',
        json=remove_user_response
    )
    requests_mock.get(
        f'{BASE_URL}/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        f'{BASE_URL}/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1',
              'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user2@respond-software.com'
    }
    res = remove_user_command(rest_client, args)
    assert res == 'user with email: qa-user2@respond-software.com removed from incident with id 5 on tenant Tenant 1'


def test_assign_user(mocker, requests_mock):
    from RespondAnalyst import assign_user_command, RestClient

    assign_user_response = {'data': {
        'addUserToIncident': {'id': '5', 'userIds': ['675ad53a-d8f4-4ae7-9a3a-59de6c70b912']}}}
    get_all_users_response = load_test_data('test_data/users.json')

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )
    mocker.patch.object(demisto, 'info')

    requests_mock.get(
        f'{BASE_URL}/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        f'{BASE_URL}/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1',
              'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )
    requests_mock.post(
        f'{BASE_URL}/graphql?tenantId=dev1',
        json=assign_user_response
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user2@respond-software.com',
    }
    res = assign_user_command(rest_client, args)
    assert res == 'user with email: qa-user2@respond-software.com added to incident with id 5 on tenant Tenant 1'

    # no tenant id provided
    args = {
        'incident_id': 5,
        'username': 'qa-user3@respond-software.com',
    }
    res = assign_user_command(rest_client, args)
    assert res == 'user with email: qa-user3@respond-software.com added to incident with id 5 on tenant Tenant 1'


def test_close_incident(mocker, requests_mock):
    from RespondAnalyst import close_incident_command, RestClient

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )
    # test
    mocker.patch.object(demisto, 'info')

    get_all_users_response = load_test_data('test_data/users.json')
    close_incident_response = load_test_data('test_data/close_incident_response.json')
    single_full_incident_response = load_test_data('test_data/single_full_incident.json')

    mocker.patch.object(rest_client, 'construct_and_send_full_incidents_query',
                        return_value=single_full_incident_response)

    requests_mock.get(
        f'{BASE_URL}/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        f'{BASE_URL}/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1',
              'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )
    requests_mock.post(
        f'{BASE_URL}/graphql?tenantId=dev1',
        json=close_incident_response
    )

    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'incident_feedback': 'NonActionable',
        'feedback_selected_options': [{'id': '4', 'key': 'unmonitoredAssets', 'value': 'true'},
                                      {'id': '19', 'key': 'scopedCorrectly', 'value': 'No'}],
        'incident_comments': 'new text',
    }

    res = close_incident_command(rest_client, args)
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
    res == close_incident_command(rest_client, args)
    assert 'incident closed and/or feedback updated for incident with id 5 on tenant Tenant 1' in res


def test_assign_user_raise_exception(mocker, requests_mock):
    from RespondAnalyst import assign_user_command, RestClient

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'error')

    get_all_users_response = load_test_data('test_data/users.json')
    mocker.patch.object(rest_client, 'construct_and_send_add_user_to_incident_mutation',
                        return_value=Exception)
    requests_mock.get(
        f'{BASE_URL}/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        f'{BASE_URL}/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1',
              'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )
    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user2@respond-software.com',
    }
    with pytest.raises(Exception):
        assign_user_command(rest_client, args)
    demisto.error.assert_any_call(
        "error adding user to incident: type object 'Exception' has no attribute 'get'")


def test_remove_user_raises_exception(mocker, requests_mock):
    from RespondAnalyst import remove_user_command, RestClient

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'error')

    get_all_users_response = load_test_data('test_data/users.json')
    mocker.patch.object(rest_client, 'construct_and_send_remove_user_from_incident_mutation',
                        return_value=Exception)
    requests_mock.get(
        f'{BASE_URL}/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        f'{BASE_URL}/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1',
              'email': 'qa-user@respond-software.com',
              'firstname': 'jay', 'lastname': 'blue'}
    )
    args = {
        'tenant_id': 'Tenant 1',
        'incident_id': 5,
        'username': 'qa-user4@respond-software.com'
    }
    with pytest.raises(Exception):
        remove_user_command(rest_client, args)

    demisto.error.assert_called_once_with(
        'no user found with email qa-user4@respond-software.com')


def test_close_incident_with_bad_responses(mocker, requests_mock):
    from RespondAnalyst import close_incident_command, RestClient

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )

    mocker.patch.object(demisto, 'error')

    get_all_users_response = load_test_data('test_data/users.json')

    mocker.patch.object(rest_client, 'construct_and_send_close_incident_mutation',
                        return_value=Exception)
    mocker.patch.object(rest_client, 'construct_and_send_full_incidents_query',
                        return_value=Exception)
    requests_mock.get(
        f'{BASE_URL}/api/v0/users',
        json=get_all_users_response
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1'}
    )
    requests_mock.get(
        f'{BASE_URL}/session/activeUser',
        json={'userId': 'qa1-user-id', 'currentTenant': 'dev1',
              'email': 'qa-user@respond-software.com',
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
        close_incident_command(rest_client, args)

    demisto.error.assert_any_call(
        "error closing incident and/or updating feedback: 'type' object is not subscriptable")


def test_get_remote_data_command(requests_mock):
    from RespondAnalyst import get_remote_data_command, RestClient
    full_incidents_response = load_test_data(
        'test_data/full_incidents_response_single_full_incident.json')

    rest_client = RestClient(
        base_url='https://localhost:6078',
        auth=('un', 'pw'),
        verify=False
    )
    requests_mock.get(
        f'{BASE_URL}/session/tenantIdMapping',
        json={'dev1': 'Tenant 1', 'dev1_tenant2': 'Tenant 2'}
    )
    requests_mock.post(
        f'{BASE_URL}/graphql?tenantId=dev1',
        json=full_incidents_response
    )

    args = {'id': 'Tenant 1:1'}

    res = get_remote_data_command(rest_client, args)
    expected_result = [
        {"id": "Tenant 1:1","incidentId": "6", "timeGenerated": "2020-06-05T16:20:21Z", "eventCount": 24,
         "firstEventTime": "2019-12-21T13:05:31Z",
         "lastEventTime": "2020-06-05T08:20:17Z",
         "URL": "https://localhost:6078/secure/incidents/6?tenantId=dev1",
         "closeURL": "https://localhost:6078/secure/incidents/feedback/6?tenantId=dev1",
         "title": "Virus Infections, Suspicious Repeated Connections and Int - Int Network IPS Activity",
         "status": "Closed", "severity": "Critical", "probability": "VeryHigh",
         "attackStage": "LateralMovement", "attackTactic": None,
         "assetCriticality": "Critical", "internalSystemsCount": 1,
         "internalSystems": [{"hostname": "enterprise.com"}], "escalationReasons": [
            {"label": "Multiple Network IPS Signatures Triggered by Same Internal Asset"}],
         "assignedUsers": ["cbe263b5-c2ff-42e9-9d7a-bff7a3261d4a"],
         "feedback": {"timeUpdated": "1593469076049",
                      "userId": "qa-user@respond-software.com",
                      "outcome": "Non-Actionable", "comments": "blah blah blah"},
         "tenantIdRespond": "dev1", "tenantId": "Tenant 1",
         "respondRemoteId": "Tenant 1:6", "dbotMirrorDirection": "In",
         "dbotMirrorInstance": "respond_test", "owner": "user1"}, {
            "Contents": {
                "closeNotes": "blah blah blah",
                "closeReason": "Non-Actionable",
                "dbotIncidentClose": True
            },
            "ContentsFormat": "json",
            "Type": 1
        }]
    # print(json.dumps(expected_result, sort_keys=True, indent=2, separators=(',', ': ')))
    assert res == expected_result
