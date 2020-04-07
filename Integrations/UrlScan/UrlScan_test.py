import pytest
import demistomock as demisto

RETURN_ERROR_TARGET = 'UrlScan.return_error'
# test that if the new argument is False an error is thrown
# test that if the new argument is True an error is not thrown
SCAN_URL = 'https://urlscan.io/api/v1/scan/'

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
    requests_mock.post(SCAN_URL, status_code=400, json=response_json)
    mocker.patch.object(demisto, 'args', return_value=args)

    if continue_on_blacklisted_urls:
        assert return_error_mock.call_count == 0
    else:
        assert return_error_mock.call_count == 1
