from CommonServerPython import *


class ResponseMock:
    def __init__(self, _json):
        self.status_code = 200
        self._json = _json
        self.headers = {'Content-Type': 'text\html'}
        self.text = "<div>" \
                    "<html> some text </html>" \
                    "</div>"

    def json(self):
        return self._json


JSON_RESP = {
    "message": "Success"
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
