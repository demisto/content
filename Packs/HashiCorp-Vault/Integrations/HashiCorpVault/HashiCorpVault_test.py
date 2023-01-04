from HashiCorpVault import *


def test_get_server_url(mocker):
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com'})
    assert get_server_url() == 'https://test.com'





