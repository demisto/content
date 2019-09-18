from pytest import raises
from Authentication import Client
from CommonServerPython import DemistoException
import demistomock as demisto

BASE_URL = 'https://example.com/v1/'


def get_credentials():
    return {
        'credential': [
            {'username': 'User1', 'password': 'mj54bk32gb', 'name': 'DBot Demisto'},
            {'username': 'User2', 'password': 'mj54bk32gb', 'name': 'Demisto DBot'}
        ]
    }


def get_user_list():
    return {
        'account': [
            {'username': 'User1', 'name': 'DBot Demisto', 'isLocked': False},
            {'username': 'User2', 'name': 'Demisto DBot', 'isLocked': True}
        ]
    }


def get_client():
    return Client('Authentication Integration', 'authentication', 'AuthenticationIntegration',
                  'https://example.com',
                  '/v1/')


class TestBuildContext:
    client = get_client()

    def test_build_fetch_creds(self):
        from Authentication import build_credentials_fetch
        results = build_credentials_fetch([{'username': 'user1', 'name': 'name1', 'password': 'password'}])
        assert results == [{'name': 'name1', 'password': 'password', 'user': 'user1'}]

    def test_build_account_context(self):
        from Authentication import build_account_context
        results = build_account_context(get_user_list()['account'])
        assert results == [
            {'IsLocked': False, 'Name': 'DBot Demisto', 'Username': 'User1'},
            {'IsLocked': True, 'Name': 'Demisto DBot', 'Username': 'User2'}]


class TestCredentialsOperations:
    client = get_client()

    def test_fetch_credentials_positive(self, mocker, requests_mock):
        from Authentication import fetch_credentials
        mocker.patch.object(demisto, 'credentials')
        # list
        requests_mock.get(
            f'{BASE_URL}credential',
            json=get_credentials())
        fetch_credentials(self.client)
        results = demisto.credentials.call_args[0][0]
        assert results == [{'user': 'User1', 'name': 'DBot Demisto', 'password': 'mj54bk32gb'},
                           {'user': 'User2', 'name': 'Demisto DBot', 'password': 'mj54bk32gb'}]

    def test_fetch_credentials_negative(self, mocker, requests_mock):
        from Authentication import fetch_credentials
        mocker.patch.object(demisto, 'credentials')
        # list
        requests_mock.get(
            f'{BASE_URL}credential',
            json={})
        with raises(DemistoException, match='`fetch-incidents` failed in'):
            fetch_credentials(self.client)

    def test_list_accounts_full(self, mocker):
        from Authentication import list_accounts
        mocker.patch.object(self.client, 'list_accounts_request', return_value=get_user_list())
        _, _, raw_response = list_accounts(self.client)
        assert raw_response == {'account': [{'username': 'User1', 'name': 'DBot Demisto', 'isLocked': False},
                                            {'username': 'User2', 'name': 'Demisto DBot', 'isLocked': True}]}

    def test_list_accounts_negative(self, mocker):
        from Authentication import list_accounts
        mocker.patch.object(self.client, 'list_accounts_request', return_value={'account': []})
        human_readable, _, _ = list_accounts(self.client)
        assert 'Could not find any users' in human_readable


class TestTestModule:
    client = get_client()

    def test_test_module_positive(self, mocker):
        from Authentication import test_module
        mocker.patch.object(self.client, 'test_module_request', return_value={'version': '1'})
        results = test_module(self.client, None)
        assert results[0]

    def test_test_module_false(self, mocker):
        from Authentication import test_module
        mocker.patch.object(self.client, 'test_module_request', return_value={})
        with raises(DemistoException, match='Test module failed'):
            test_module(self.client, None)


class TestAccountOperations:
    client = get_client()

    def test_lock_account_positive(self, mocker):
        from Authentication import lock_account
        mocker.patch.object(self.client, 'lock_account_request', return_value={'username': '111', 'isLocked': True})
        results = lock_account(self.client, {'account_id': '111'})
        assert 'Authentication Integration - Account `111`' in results[0]

    def test_lock_account_negative(self, mocker):
        from Authentication import lock_account
        mocker.patch.object(self.client, 'lock_account_request', return_value={})
        with raises(DemistoException, match='Could not lock account'):
            lock_account(self.client, {'account_id': '111'})

    def test_unlock_account_positive(self, mocker):
        from Authentication import unlock_account
        mocker.patch.object(self.client, 'unlock_account_request', return_value={'username': '111', 'isLocked': True})
        results = unlock_account(self.client, {'account_id': '111'})
        assert 'Authentication Integration - Account `111`' in results[0]

    def test_unlock_account_negative(self, mocker):
        from Authentication import unlock_account
        mocker.patch.object(self.client, 'unlock_account_request', return_value={})
        with raises(DemistoException, match='Could not unlock account'):
            unlock_account(self.client, {'account_id': '111'})

    def test_reset_account_positive(self, mocker):
        from Authentication import reset_account
        mocker.patch.object(self.client, 'reset_account_request', return_value={'account': '111', 'isLocked': False})
        results = reset_account(self.client, {'account_id': '111'})
        assert 'Authentication Integration - Account `111`' in results[0]

    def test_reset_account_negative(self, mocker):
        from Authentication import reset_account
        mocker.patch.object(self.client, 'reset_account_request', return_value={})
        with raises(DemistoException, match='Could not reset account'):
            reset_account(self.client, {'account_id': '111'})


class TestVaultOperations:
    client = get_client()

    def test_lock_vault_positive(self, mocker):
        from Authentication import lock_vault
        mocker.patch.object(self.client, 'lock_vault_request', return_value={'vault_id': '111', 'isLocked': True})
        results = lock_vault(self.client, {'vault_id': '111'})
        assert 'Vault 111 has been locked' in results[0]

    def test_lock_vault_negative(self, mocker):
        from Authentication import lock_vault
        mocker.patch.object(self.client, 'lock_vault_request', return_value={'vault_id': '111', 'isLocked': False})
        with raises(DemistoException, match='Could not lock vault'):
            lock_vault(self.client, {'vault_id': '111'})

    def test_unlock_vault_positive(self, mocker):
        from Authentication import unlock_vault
        mocker.patch.object(self.client, 'unlock_vault_request', return_value={'vault_id': '111', 'isLocked': False})
        results = unlock_vault(self.client, {'vault_id': '111'})
        assert 'Vault 111 has been unlocked' in results[0]

    def test_unlock_vault_negative(self, mocker):
        from Authentication import unlock_vault
        mocker.patch.object(self.client, 'unlock_vault_request', return_value={'vault_id': '111', 'isLocked': True})
        with raises(DemistoException, match='Could not unlock vault'):
            unlock_vault(self.client, {'vault_id': '111'})
