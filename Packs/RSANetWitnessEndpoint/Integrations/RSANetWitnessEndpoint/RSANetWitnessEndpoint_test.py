from CommonServerPython import *


class ResponseMock:
    def __init__(self, _json):
        self.status_code = 404
        self._json = _json
        self.headers = {'Content-Type': 'text\html'}
        self.text = "<div>" \
                    "<html> some text </html>" \
                    "</div>"
        self.ResponseStatus = ResponseStatus(_json)

    def json(self):
        return ResponseMock(JSON_RESP)


class ResponseStatus:
    def __init__(self, _json):
        self.ErrorCode = 404
        self.Message = _json


JSON_RESP = {
    "message": "test message"
}


def test_is_html_response(mocker):
    mocker.patch.object(demisto, 'params', return_value={'server': 'mock_server', 'insecure': False,
                                                         'proxy': '',
                                                         'credentials': {'identifier': '', 'password': ''}})
    from RSANetWitnessEndpoint import is_html_response
    assert is_html_response(ResponseMock(JSON_RESP))


def test_get_html_from_response(mocker):
    mocker.patch.object(demisto, 'params', return_value={'server': 'mock_server', 'insecure': False,
                                                         'proxy': '',
                                                         'credentials': {'identifier': '', 'password': ''}})
    from RSANetWitnessEndpoint import get_html_from_response
    assert get_html_from_response(ResponseMock(JSON_RESP)) == '<html> some text </html>'


def test_parse_error_response(mocker):
    mocker.patch.object(demisto, 'params', return_value={'server': 'mock_server', 'insecure': False,
                                                         'proxy': '',
                                                         'credentials': {'identifier': '', 'password': ''}})
    from RSANetWitnessEndpoint import parse_error_response
    assert parse_error_response(ResponseMock(JSON_RESP)) == \
           'Request failed with status code: 404\nReason: 404\n{\'message\': \'test message\'}'
