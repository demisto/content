from requests import Response, Session
from Okta_IAM import *
from CommonServerPython import EntryType


OKTA_USER_OUTPUT = {
    "id": "mock_id",
    "status": "PROVISIONED",
    "profile": {
        "firstName": "mock_first_name",
        "lastName": "mock_last_name",
        "login": "testdemisto2@paloaltonetworks.com",
        "email": "testdemisto2@paloaltonetworks.com"
    }
}


OKTA_DISABLED_USER_OUTPUT = {
    "id": "mock_id",
    "status": "DEPROVISIONED",
    "profile": {
        "firstName": "mock_first_name",
        "lastName": "mock_last_name",
        "login": "testdemisto2@paloaltonetworks.com",
        "email": "testdemisto2@paloaltonetworks.com"
    }
}


def mock_client():
    client = Client(base_url='https://test.com')
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


def test_get_user_command__existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user exists in Okta
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds the correct user details
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=OKTA_USER_OUTPUT)
    mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_get_user_command__non_existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email a user
    When:
        - The user does not exist in Okta
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds information about an unsuccessful result.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
    assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_get_user_command__bad_response(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a non-existing user in Okta
    When:
        - Calling function get_user_command
        - A bad response (500) is returned from Okta's API
    Then:
        - Ensure the resulted User Profile object holds information about the bad response.
    """
    import demistomock as demisto

    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    bad_response = Response()
    bad_response.status_code = 500
    bad_response._content = b'{"errorCode": "mock_error_code", ' \
                            b'"errorSummary": "mock_error_summary", ' \
                            b'"errorCauses": [{"errorSummary": "reason_1"}, ' \
                            b'{"errorSummary": "reason_2"}]}'

    mocker.patch.object(demisto, 'error')
    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == 'mock_error_code'
    assert outputs.get('errorMessage') == 'mock_error_summary. Reason:\n1. reason_1\n2. reason_2\n'


def test_create_user_command__success(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a non-existing user in Okta
    When:
        - Calling function create_user_command
    Then:
        - Ensure a User Profile object with the user data is returned
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=OKTA_USER_OUTPUT)

    user_profile = create_user_command(client, args, 'mapper_out',
                                       is_command_enabled=True, is_update_user_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_update_user_command__allow_enable(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains user data
    When:
        - The user is disabled in Okta
        - allow-enable argument is true
        - Calling function update_user_command
    Then:
        - Ensure the user is enabled at the end of the command execution.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'},
            'allow-enable': 'true'}

    mocker.patch.object(client, 'get_user', return_value=OKTA_DISABLED_USER_OUTPUT)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'activate_user', return_value=None)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=False, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.ENABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_update_user_command__non_existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains user data
    When:
        - The user does not exist in Okta
        - create-if-not-exists parameter is checked
        - Create User command is enabled
        - Calling function update_user_command
    Then:
        - Ensure the create action is executed
        - Ensure a User Profile object with the user data is returned
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=OKTA_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=True, create_if_not_exists=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_update_user_command__command_is_disabled(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains user data
    When:
        - Update User command is disabled
        - Calling function update_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'update_user', return_value=OKTA_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=False,
                                       is_create_user_enabled=False, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Command is disabled.'


def test_update_user_command__rate_limit_error(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument
    When:
        - Calling function update_user_command
        - API call exceeded rate limit
    Then:
        - Ensure an error entry is returned, as rate limit error code is in ERROR_CODES_TO_RETURN_ERROR list.
    """
    import demistomock as demisto

    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    bad_response = Response()
    bad_response.status_code = 429
    bad_response._content = b'{"errorCode": "E0000047", ' \
                            b'"errorSummary": "API call exceeded rate limit due to too many requests."}'

    mocker.patch.object(demisto, 'error')
    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=False, create_if_not_exists=False)

    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')

    assert entry_context.get('Type') == EntryType.ERROR
    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == 'E0000047'


def test_disable_user_command__user_is_already_disabled(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user is already disabled in Okta
        - Calling function disable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    import demistomock as demisto

    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    bad_response = Response()
    bad_response.status_code = 400
    bad_response._content = b'{"errorCode": "E0000007", ' \
                            b'"errorSummary": "mock_error_summary", ' \
                            b'"errorCauses": [{"errorSummary": "reason_1"}, ' \
                            b'{"errorSummary": "reason_2"}]}'

    mocker.patch.object(demisto, 'error')
    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = disable_user_command(client, args, is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Action failed because the user is disabled.'


def test_get_mapping_fields_command(mocker):
    """
    Given:
        - An Okta IAM client object
    When:
        - Okta user schema contains the fields 'field1' and 'field2'
        - Calling function get_mapping_fields_command
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the Okta fields is returned
    """
    client = mock_client()

    mocker.patch.object(client, 'get_okta_fields', return_value={'field1': 'description1', 'field2': 'description2'})

    mapping_response = get_mapping_fields_command(client)
    mapping = mapping_response.extract_mapping()[0]

    assert mapping.get(IAMUserProfile.INDICATOR_TYPE, {}).get('field1') == 'description1'
    assert mapping.get(IAMUserProfile.INDICATOR_TYPE, {}).get('field2') == 'description2'


def test_get_app_user_assignment_command(mocker):
    """
    Given:
        - An Okta IAM client object
        - Okta User ID
        - Okta Application ID
    When:
        - Calling function get_assigned_user_for_app_command
    Then:
        - Ensure a User Assignment object to the application is retrieved in the correct format.
    """
    client = mock_client()

    args = {
        'user_id': 'mock_user_id',
        'application_id': 'mock_app_id'
    }

    get_assignment_response = Response()
    get_assignment_response.status_code = 200
    get_assignment_response._content = b'{"id": "mock_user_id", ' \
                                       b'"profile": {}, ' \
                                       b'"created": "2020-11-03T09:59:30.000Z", ' \
                                       b'"credentials": {"userName": "mock_username"}, ' \
                                       b'"externalId": null, ' \
                                       b'"status": "ACTIVE"}'

    mocker.patch.object(Session, 'request', return_value=get_assignment_response)

    command_result = get_app_user_assignment_command(client, args)

    assert command_result.outputs.get('UserID') == 'mock_user_id'
    assert command_result.outputs.get('AppID') == 'mock_app_id'
    assert command_result.outputs.get('IsAssigned') is True


def test_fetch_incidents__two_logs_batches(mocker):
    """
    Given:
        - An Okta IAM client object and fetch-relevant instance parameters
    When:
        - Calling function fetch_incidents
        - Events should come in two batches of two events in the first batch, and one event in the second batch.
    Then:
        - Ensure three events are returned in incident the correct format.
    """
    import json
    mocker.patch.object(Client, 'get_logs_batch', side_effect=mock_get_logs_batch)
    events, _ = fetch_incidents(
        client=mock_client(),
        last_run={},
        query_filter='mock_query_filter',
        first_fetch_str='7 days',
        fetch_limit=5
    )

    assert len(events) == 3
    assert json.loads(events[0]['rawJSON']).get('mock_log1') == 'mock_value1'
    assert json.loads(events[1]['rawJSON']).get('mock_log2') == 'mock_value2'
    assert json.loads(events[2]['rawJSON']).get('mock_log3') == 'mock_value3'


def test_fetch_incidents__fetch_limit(mocker):
    """
    Given:
        - An Okta IAM client object and fetch-relevant instance parameters
    When:
        - Calling function fetch_incidents
        - Three events exist Okta logs.
        - Fetch limit is 2.
    Then:
        - Ensure only two events are returned in incident the correct format.
    """
    mocker.patch.object(Client, 'get_logs_batch', side_effect=mock_get_logs_batch)
    events, _ = fetch_incidents(
        client=mock_client(),
        last_run={},
        query_filter='mock_query_filter',
        first_fetch_str='7 days',
        fetch_limit=2
    )

    assert len(events) == 2


def test_fetch_incidents__last_run():
    """
    Given:
        - An Okta IAM client object and fetch-relevant instance parameters
        - Last run object contains three incidents.
    When:
        - Calling function fetch_incidents
        - Fetch Limit is 2.
    Then:
        - Ensure only the first two incidents from the last run are retrieved.
        - Ensure that the next_run object returned contains the third incident.
        - Ensure 'last_run_time' key exists and holds a datetime string in the correct format.
    """
    from datetime import datetime

    last_run = {
        'incidents': [{'mock_log1': 'mock_value1'}, {'mock_log2': 'mock_value2'}, {'mock_log3': 'mock_value3'}]
    }

    events, next_run = fetch_incidents(
        client=mock_client(),
        last_run=last_run,
        query_filter='mock_query_filter',
        first_fetch_str='7 days',
        fetch_limit=2
    )

    last_run_time = datetime.strptime(next_run.get('last_run_time'), '%Y-%m-%dT%H:%M:%SZ')

    assert len(events) == 2
    assert len(next_run.get('incidents')) == 1
    assert next_run['incidents'][0].get('mock_log3') == 'mock_value3'
    assert isinstance(last_run_time, datetime)


def mock_get_logs_batch(url_suffix='', params=None, full_url=''):
    first_batch = [{'mock_log1': 'mock_value1'}, {'mock_log2': 'mock_value2'}]
    second_batch = [{'mock_log3': 'mock_value3'}]
    if url_suffix:
        # first iteration
        return first_batch, 'mock_next_page'

    elif full_url:
        # second iteration
        return second_batch, None

    # third iteration - nothing is returned
    return None, None
