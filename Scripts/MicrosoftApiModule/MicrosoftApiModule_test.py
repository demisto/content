from requests import Response
from MicrosoftApiModule import *


def test_error_parser():
    err = Response()
    err.status_code = 401
    err._content = b'{"error":{"code":"code","message":"message"}}'
    response = MicrosoftClient.error_parser(err)
    assert response == 'code: message'


def test_epoch_seconds():
    integer = MicrosoftClient.epoch_seconds()
    assert isinstance(integer, int)

