from CrowdStrikeApiModule import CrowdStrikeClient
from TestsInput.http_responses import MULTI_ERRORS_HTTP_RESPONSE, NO_ERRORS_HTTP_RESPONSE
from TestsInput.context import MULTIPLE_ERRORS_RESULT
import pytest


class ResMocker:
    def __init__(self, http_response):
        self.http_response = http_response
        self.ok = False

    def json(self):
        return self.http_response


@pytest.mark.parametrize('http_response, output', [
    (MULTI_ERRORS_HTTP_RESPONSE, MULTIPLE_ERRORS_RESULT),
    (NO_ERRORS_HTTP_RESPONSE, "")
])
def test_handle_errors(http_response, output, mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - there are or there are no errors
    Then
    - show the exception content
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
