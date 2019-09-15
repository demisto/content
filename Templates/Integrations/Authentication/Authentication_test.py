from Authentication import Client


def get_client():
    return Client('Authentication Integration', 'authentication', 'AuthenticationIntegration',
                  'https://example.com',
                  '/v1/')


def test_remove_password_key():
    from Authentication import remove_password_key
    assert remove_password_key({'password': 'oyvey'}) == {}

    assert remove_password_key([{'password': 'oyvey'}]) == [{}]

    assert remove_password_key('oyvey') == 'oyvey'


class TestFetchCredentials:
    def test_fetch_credentials_positive(self, monkeypatch):
        from Authentication import fetch_credentials
        client = get_client()
        monkeypatch.setattr(client, 'list_credentials_request', lambda: [{''}])

