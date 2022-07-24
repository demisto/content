from CrowdStrikeApiModule import CrowdStrikeClient
from TestsInput.http_responses import MULTI_ERRORS_HTTP_RESPONSE, NO_ERRORS_HTTP_RESPONSE
from TestsInput.context import MULTIPLE_ERRORS_RESULT
import pytest
import demistomock as demisto
from datetime import datetime
from datetime import timedelta


class ResMocker:
    def __init__(self, http_response):
        self.http_response = http_response
        self.status_code = 400
        self.reason = 'error'
        self.ok = False

    def json(self):
        return self.http_response


@pytest.mark.parametrize('http_response, output', [
    (MULTI_ERRORS_HTTP_RESPONSE, MULTIPLE_ERRORS_RESULT),
    (NO_ERRORS_HTTP_RESPONSE, "Error in API call [400] - error\n")
])
def test_handle_errors(http_response, output, mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - 1. there are multiple errors in the http request
    - 2. there are no errors in the http request
    Then
    - 1. show the exception content
    - 2. show no errors
    """
    mocker.patch.object(CrowdStrikeClient, '_generate_token')
    params = {
        'insecure': False,
        'credentials': {
            'identifier': 'user1',
            'password:': '12345'
        },
        'proxy': False
    }
    client = CrowdStrikeClient(params)
    try:
        mocker.patch.object(client._session, 'request', return_value=ResMocker(http_response))
        _, output, _ = client.check_quota_status()
    except Exception as e:
        assert (str(e) == str(output))


@pytest.mark.parametrize(argnames="context, expected_call_count", argvalues=[
    ({}, 1),
    ({'generation_time': datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), 'auth_token': 'test'}, 0),
    ({'generation_time': (datetime.now() - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")}, 1),
])
def test_get_token(mocker, context, expected_call_count):
    """
    Given - varios token generation time
    When - try to get access token when init the client
    Then - validate that token was generated only of required (after 28 min)
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=context)
    mocker.patch.object(CrowdStrikeClient, '_generate_token', return_value="test_token_generated")

    CrowdStrikeClient({})

    assert CrowdStrikeClient._generate_token.call_count == expected_call_count
