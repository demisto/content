# import demistomock as demisto
from CommonServerPython import *
import json
import pytest

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

def test_ip_command_when_api_quota_reached(mocker):
    from requests import Session, Response
    def json_func():
        return {}
    api_quota_reached_request_response = {
        'status_code': 429,
        'json':  json_func
    }

    params = {
        'server': 'test',
        'proxy': True,
        'disregard_quota': True
    }
    api_quota_reached_request_response_with_dot_access = dotdict(api_quota_reached_request_response)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(Session, 'request', return_value=api_quota_reached_request_response_with_dot_access)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    from AbuseDB import check_ip_command, API_QUOTA_REACHED_MESSAGE
    res = check_ip_command(['1.1.1.1'], days=7, verbose=False, threshold=10)
    assert return_error_mock.call_count == 0
