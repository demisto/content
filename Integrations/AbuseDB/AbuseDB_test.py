
RETURN_ERROR_TARGET = 'AbuseDB.return_error'

class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


api_quota_reached_request_response = {
    'status_code': 429
}
api_quota_reached_request_response_with_dot_access = dotdict(api_quota_reached_request_response)

API_QUOTA_REACHED_TEST_CASES = (
    TEST_WITH_a
)
def test_ip_command_when_api_quota_reached(mocker):
    from AbuseDB import check_ip_command, API_QUOTA_REACHED_MESSAGE
    api_quota_reached_request_response = {
        'status_code': 429
    }
    api_quota_reached_request_response_with_dot_access = dotdict(api_quota_reached_request_response)
    # TODO : remove function if not needed
    def return_api_quota_reached_response():
        return api_quota_reached_request_response_with_dot_access

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    mocker.patch.object(session, 'request', return_value=api_quota_reached_request_response_with_dot_access)

    res = check_ip_command(['1.1.1.1'], days=7, verbose=False, threshold=10)

