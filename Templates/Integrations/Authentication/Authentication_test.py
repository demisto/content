from pytest import raises
from Authentication import Client
from CommonServerPython import DemistoException
import demistomock as demisto

BASE_URL = 'https://example.com/v1/'

GET_CREDENTIALS = {
    'credential': [
        {'username': 'User1', 'password': 'mj54bk32gb', 'name': 'DBot Demisto'},
        {'username': 'User2', 'password': 'mj54bk32gb', 'name': 'Demisto DBot'}
    ]
}

GET_USER_LIST = {
    'account': [
        {'username': 'User1', 'name': 'DBot Demisto', 'isLocked': False},
        {'username': 'User2', 'name': 'Demisto DBot', 'isLocked': True}
    ]
}

client = Client('https://example.com/v1/')


class TestBuildContext:
    def test_build_fetch_creds(self):
        from Authentication import build_credentials_fetch
        results = build_credentials_fetch([{'username': 'user1', 'name': 'name1', 'password': 'password'}])
        assert results == [{'name': 'name1', 'password': 'password', 'user': 'user1'}]

    def test_account_response_to_context(self):
        from Authentication import account_response_to_context
        results = account_response_to_context(GET_USER_LIST['account'])
        assert results == [
            {'IsLocked': False, 'Name': 'DBot Demisto', 'Username': 'User1'},
            {'IsLocked': True, 'Name': 'Demisto DBot', 'Username': 'User2'}]


class TestCredentialsOperations:
    def test_fetch_credentials_positive(self, mocker, requests_mock):
        from Authentication import fetch_credentials
        mocker.patch.object(demisto, 'credentials')
        # list
        requests_mock.get(
            f'{BASE_URL}credential',
            json=GET_CREDENTIALS)
        results = fetch_credentials(client)
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
            fetch_credentials(client)

    def test_list_accounts_full(self, mocker):
        from Authentication import list_accounts_command
        mocker.patch.object(client, 'list_accounts', return_value=GET_USER_LIST)
        _, _, raw_response = list_accounts_command(client, {})
        assert raw_response == {'account': [{'username': 'User1', 'name': 'DBot Demisto', 'isLocked': False},
                                            {'username': 'User2', 'name': 'Demisto DBot', 'isLocked': True}]}

    def test_list_accounts_negative(self, requests_mock):
        from Authentication import list_accounts_command
        requests_mock.get(BASE_URL + 'account', json={'account': []})
        human_readable, _, _ = list_accounts_command(client, {})
        assert 'Could not find any users' in human_readable


class TestTestModule:
    def test_test_module_positive(self, requests_mock):
        from Authentication import test_module_command
        requests_mock.get(BASE_URL + 'version', json={'version': '1'})
        human_readable = test_module_command(client, None)
        assert human_readable == 'ok'

    def test_test_module_false(self, requests_mock):
        from Authentication import test_module_command
        requests_mock.get(BASE_URL + 'version', json={})
        with raises(DemistoException, match='Test module failed'):
            test_module_command(client, None)


class TestAccountOperations:
    def test_lock_account_positive(self, requests_mock):
        from Authentication import lock_account_command
        requests_mock.post(BASE_URL + 'account/lock?account=111', json={
            'account': [{'username': '111', 'isLocked': True}]})
        human_readable, _, _ = lock_account_command(client, {'username': '111'})
        assert 'Authentication Integration - Account `111`' in human_readable

    def test_lock_account_negative(self, requests_mock):
        from Authentication import lock_account_command
        requests_mock.post(BASE_URL + 'account/lock?account=111', json={})
        with raises(DemistoException, match='Could not lock account'):
            lock_account_command(client, {'username': '111'})

    def test_unlock_account_positive(self, requests_mock):
        from Authentication import unlock_account_command
        requests_mock.post(BASE_URL + 'account/unlock?account=111', json={
            'account': [{'username': '111', 'isLocked': False}]})
        human_readable, _, _ = unlock_account_command(client, {'username': '111'})
        assert 'Authentication Integration - Account `111`' in human_readable

    def test_unlock_account_negative(self, requests_mock):
        from Authentication import unlock_account_command
        requests_mock.post(BASE_URL + 'account/unlock?account=111', json={})
        with raises(DemistoException, match='Could not unlock account'):
            unlock_account_command(client, {'username': '111'})

    def test_reset_account_positive(self, requests_mock):
        from Authentication import reset_account_command
        requests_mock.post(BASE_URL + 'account/reset?account=111', json={
            'account': [{'username': '111', 'isLocked': False}]})
        human_readable, _, _ = reset_account_command(client, {'username': '111'})
        assert 'Authentication Integration - Account `111`' in human_readable

    def test_reset_account_negative(self, requests_mock):
        from Authentication import reset_account_command
        requests_mock.post(BASE_URL + 'account/reset?account=111', json={})
        with raises(DemistoException, match='Could not reset account'):
            reset_account_command(client, {'username': '111'})


class TestVaultOperations:
    def test_lock_vault_positive(self, requests_mock):
        from Authentication import lock_vault_command
        requests_mock.post(BASE_URL + 'vault/lock?vaultId=111', json={
            'vault': [{'vaultId': '111', 'isLocked': True}]})
        results = lock_vault_command(client, {'vault_id': '111'})
        assert 'Vault 111 has been locked' in results[0]

    def test_lock_vault_negative(self, requests_mock):
        from Authentication import lock_vault_command
        requests_mock.post(BASE_URL + 'vault/lock?vaultId=111', json={
            'vault': [{'vaultId': '111', 'isLocked': False}]})
        with raises(DemistoException, match='Could not lock vault'):
            lock_vault_command(client, {'vault_id': '111'})

    def test_unlock_vault_positive(self, requests_mock):
        from Authentication import unlock_vault_command
        requests_mock.post(BASE_URL + 'vault/unlock?vaultId=111', json={
            'vault': [{'vaultId': '111', 'isLocked': False}]})
        results = unlock_vault_command(client, {'vault_id': '111'})
        assert 'Vault 111 has been unlocked' in results[0]

    def test_unlock_vault_negative(self, requests_mock):
        from Authentication import unlock_vault_command
        requests_mock.post(BASE_URL + 'vault/unlock?vaultId=111', json={
            'vault': [{'vaultId': '111', 'isLocked': True}]})
        with raises(DemistoException, match='Could not unlock vault'):
            unlock_vault_command(client, {'vault_id': '111'})

    def test_list_vaults_positive(self, requests_mock):
        from Authentication import list_vaults_command
        requests_mock.get(BASE_URL + 'vault', json={
            'vault': [
                {'vaultId': '111', 'isLocked': True},
                {'vaultId': '121', 'isLocked': False},
                {'vaultId': '164', 'isLocked': False}
            ]})
        human_readable, _, _ = list_vaults_command(client, {})
        assert 'Total of 3 has been found' in human_readable

    def test_list_vaults_negative(self, requests_mock):
        from Authentication import list_vaults_command
        requests_mock.get(BASE_URL + 'vault', json={'vault': []})
        human_readable, _, _ = list_vaults_command(client, {})
        assert 'No vaults found' in human_readable
