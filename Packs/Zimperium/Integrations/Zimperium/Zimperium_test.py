import pytest
from Zimperium import Client, events_search, users_search, user_get_by_id, devices_search, device_get_by_id, \
    devices_get_last_updated, app_classification_get, report_get, app_upload_for_analysis
from test_data.response_constants import RESPONSE_SEARCH_EVENTS, RESPONSE_SEARCH_USERS, RESPONSE_USER_GET_BY_ID
from test_data.result_constants import EXPECTED_SEARCH_EVENTS, EXPECTED_SEARCH_USERS, EXPECTED_USER_GET_BY_ID


@pytest.mark.parametrize('command, args, http_response, context', [
    (events_search, {'query': 'eventId==*', 'size': '10', 'page': '0', 'verbose': False}, RESPONSE_SEARCH_EVENTS,
     EXPECTED_SEARCH_EVENTS),
    (users_search, {'query': 'objectId==*', 'size': '10', 'page': '0'}, RESPONSE_SEARCH_USERS, EXPECTED_SEARCH_USERS),
    (user_get_by_id, {'object_id': '1B9182C7-8C12-4499-ADF0-A338DEFDFC33'}, RESPONSE_USER_GET_BY_ID,
     EXPECTED_USER_GET_BY_ID),
])
def test_zimperium_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    client = Client(base_url="https://domain.zimperium.com/", api_key="api_key", verify=False)
    mocker.patch.object(Client, '_http_request', return_value=http_response)
    _, outputs, _ = command(client, args)
    assert outputs == context
