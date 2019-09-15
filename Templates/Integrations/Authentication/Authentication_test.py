from Authentication import Client
import demistomock as demisto
import pytest

BASE_URL = 'https://example.com/v1/'


def get_credentials():
    return {
        'credentials': [
            {'username': 'User1', 'password': 'mj54bk32gb', 'name': 'DBot Demisto'},
            {'username': 'User2', 'password': 'mj54bk32gb', 'name': 'Demisto DBot'}
        ]
    }


def get_client():
    return Client('Authentication Integration', 'authentication', 'AuthenticationIntegration',
                  'https://example.com',
                  '/v1/')


class TestFetchCredentials:
    def test_fetch_credentials_positive(self, mocker, requests_mock):
        from Authentication import fetch_credentials
        client = get_client()
        mocker.patch.object(demisto, 'credentials')
        requests_mock.get(
            f'{BASE_URL}credentials',
            json=get_credentials())
        fetch_credentials(client)
        results = demisto.credentials.call_args[0][0]
        assert results == [{'user': 'User1', 'name': 'DBot Demisto', 'password': 'mj54bk32gb'},
                           {'user': 'User2', 'name': 'Demisto DBot', 'password': 'mj54bk32gb'}]
