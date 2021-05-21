from CommonServerPython import *

RETURN_ERROR_TARGET = 'AbuseDB.return_error'


class DotDict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def test_ip_command_when_api_quota_reached(mocker):
    from requests import Session

    def json_func():
        return {}

    api_quota_reached_request_response = {
        'status_code': 429,
        'json': json_func
    }

    params = {
        'server': 'test',
        'proxy': True,
        'disregard_quota': True,
        'integrationReliability': DBotScoreReliability.C
    }

    api_quota_reached_request_response_with_dot_access = DotDict(api_quota_reached_request_response)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(Session, 'request', return_value=api_quota_reached_request_response_with_dot_access)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    from AbuseDB import check_ip_command
    check_ip_command(['1.1.1.1'], DBotScoreReliability.C, days=7, verbose=False, threshold=10)
    assert return_error_mock.call_count == 0
