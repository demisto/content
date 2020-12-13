import pytest
import demistomock as demisto
import json


RETURN_ERROR_TARGET = 'UrlScan.return_error'
SCAN_URL = 'https://urlscan.io/api/v1/scan/'
RESULT_URL = 'https://urlscan.io/api/v1/result/'


@pytest.mark.parametrize('continue_on_blacklisted_urls', [(True), (False)])
def test_continue_on_blacklisted_error_arg(mocker, requests_mock, continue_on_blacklisted_urls):
    from UrlScan import http_request, BLACKLISTED_URL_ERROR_MESSAGE
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    response_json = {
        'status': 400,
        'message': 'Scan prevented ...',
        'description': BLACKLISTED_URL_ERROR_MESSAGE,
    }
    args = {
        'continue_on_blacklisted_urls': continue_on_blacklisted_urls
    }
    data = {
        'url': 'www.test.com'
    }
    requests_mock.post(SCAN_URL, status_code=400, json=response_json)
    mocker.patch.object(demisto, 'args', return_value=args)

    http_request('POST', 'scan/', json=json.dumps(data))
    if continue_on_blacklisted_urls:
        assert return_error_mock.call_count == 0
    else:
        assert return_error_mock.call_count == 1


def test_endless_loop_on_failed_response(requests_mock, mocker):
    from UrlScan import format_results
    mocker.patch(RETURN_ERROR_TARGET)

    with open('./test_data/capitalne.json', 'r') as f:
        response_data = json.loads(f.read())
    requests_mock.get(RESULT_URL + 'uuid', status_code=200, json=response_data)
    format_results('uuid')
