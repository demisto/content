from unittest.mock import Mock, patch

from HashiCorpVault import *


class MockHttpResponse:
    def __init__(self, json_data, status_code):
        self.content = json_data
        self.status_code = status_code

    def json(self):
        return self.content


mock_res = {'data': {'keys': ['1']}}
mock_role_data = {'data': {'credential_type': 'iam_user', 'role_arns': 'test'}}
mock_aws_credentials = {'data': {'access_key': 'test', 'secret_key': 'test', 'security_token': 'test'}}
mock = Mock()
mock.side_effect = iter(
    [{}, mock_res, {}, mock_res, mock_role_data, {}, mock_res, mock_role_data, mock_aws_credentials])


def test_send_request(mocker):
    res = MockHttpResponse({'test': 'test'}, 200)
    mocker.patch.object(requests, 'request', return_value=res)
    mocker.patch('HashiCorpVault.get_headers', return_value={})
    mocker.patch('HashiCorpVault.SERVER_URL', return_value='test')
    assert send_request('https://test.com') == {'test': 'test'}


@patch('HashiCorpVault.send_request', mock)
def test_get_aws_secrets(mocker):
    mocker.patch('HashiCorpVault.SERVER_URL', return_value='test')
    get_aws_secrets('test', '999', False)
    assert mock.call_args.args[0] == 'test'
    get_aws_secrets('test', '999', False)
    assert mock.call_args.args[0] == 'test/roles/1'
    get_aws_secrets('test', '999', False)
    assert mock.call_args.args[0] == 'test'


def test_get_headers():
    assert get_headers() == {'Content-Type': 'application/json'}


def test_list_secrets_engines(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert list_secrets_engines() == {}


def test_list_secrets(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert list_secrets('test', '2') == {}


def test_get_secret_metadata(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert get_secret_metadata('test', 'test') == {}


def test_delete_secret(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert delete_secret('test', 'test', 'test') == {}


def test_undelete_secret(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert undelete_secret('test', 'test', 'test') == {}


def test_destroy_secret(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert destroy_secret('test', 'test', 'test') == {}


def test_list_policies(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert list_policies() == {}


def test_get_policy(mocker):
    mocker.patch('HashiCorpVault.send_request', return_value={})
    assert get_policy('test') == {}
