from requests import Response
from MicrosoftApiModule import MicrosoftClient
import demistomock as demisto
import pytest
import datetime


TOKEN = 'dummy_token'
TENANT = 'dummy_tenant'
REFRESH_TOKEN = 'dummy_refresh'
AUTH_ID = 'dummy_auth_id'
ENC_KEY = 'dummy_enc_key'
TOKEN_URL = 'mock://dummy_url'
APP_NAME = 'ms-graph-mail-listener'
BASE_URL = 'https://graph.microsoft.com/v1.0/'
OK_CODES = (200, 201, 202)

CLIENT_ID = 'dummy_client'
CLIENT_SECRET = 'dummy_secret'
APP_URL = 'https://login.microsoftonline.com/dummy_tenant/oauth2/v2.0/token'
SCOPE = 'https://graph.microsoft.com/.default'
RESOURCE = 'https://defender.windows.com/shtak'


def oproxy_client_tenant():
    tenant_id = TENANT
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=False, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                           tenant_id=tenant_id, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes)


def oproxy_client_refresh():
    refresh_token = REFRESH_TOKEN
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=False, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                           refresh_token=refresh_token, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes)


def self_deployed_client():
    tenant_id = TENANT
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    base_url = BASE_URL
    resource = RESOURCE
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=True, tenant_id=tenant_id, auth_id=client_id, enc_key=client_secret,
                           resource=resource, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes)


def test_error_parser(mocker):
    mocker.patch.object(demisto, 'error')
    err = Response()
    err.status_code = 401
    err._content = b'{"error":{"code":"code","message":"message"}}'
    response = MicrosoftClient.error_parser(err)
    assert response == 'code: message'


def test_epoch_seconds(mocker):
    mocker.patch.object(MicrosoftClient, '_get_utcnow', return_value=datetime.datetime(2019, 12, 24, 14, 12, 0, 586636))
    mocker.patch.object(MicrosoftClient, '_get_utcfromtimestamp', return_value=datetime.datetime(1970, 1, 1, 0, 0))
    integer = MicrosoftClient.epoch_seconds()
    assert integer == 1577196720


@pytest.mark.parametrize('client, tokens, context', [(oproxy_client_refresh(), (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN}),
                                                     (oproxy_client_tenant(), (TOKEN, 3600, ''),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': ''}),
                                                     (self_deployed_client(),
                                                      (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN})])
def test_get_access_token_no_context(mocker, client, tokens, context):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(client, '_oproxy_authorize', return_value=tokens)
    mocker.patch.object(client, '_get_self_deployed_token', return_value=tokens)
    mocker.patch.object(client, 'epoch_seconds', return_value=10)

    # Arrange
    token = client.get_access_token()

    integration_context = demisto.setIntegrationContext.call_args[0][0]

    # Assert
    assert token == TOKEN
    assert integration_context == context


@pytest.mark.parametrize('client, tokens, context', [(oproxy_client_refresh(),
                                                      (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN}),
                                                     (oproxy_client_tenant(), (TOKEN, 3600, ''),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN}),
                                                     (self_deployed_client(), (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN})])
def test_get_access_token_with_context_valid(mocker, client, tokens, context):
    # Set
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=context)
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(client, '_oproxy_authorize', return_value=tokens)
    mocker.patch.object(client, '_get_self_deployed_token', return_value=tokens)
    mocker.patch.object(client, 'epoch_seconds', return_value=3600)

    # Arrange
    token = client.get_access_token()

    set_context_count = demisto.setIntegrationContext.call_count
    auth_call_oproxy = client._oproxy_authorize.call_count
    auth_call_self_deployed = client._get_self_deployed_token.call_count

    # Assert
    assert set_context_count == 0
    assert auth_call_oproxy == 0
    assert auth_call_self_deployed == 0
    assert token == TOKEN


@pytest.mark.parametrize('client, tokens, context_invalid, context_valid',
                         [(oproxy_client_refresh(),
                           (TOKEN, 3600, REFRESH_TOKEN),
                           {'access_token': TOKEN,
                            'valid_until': 3605,
                            'current_refresh_token': REFRESH_TOKEN},
                           {'access_token': TOKEN,
                            'valid_until': 8595,
                            'current_refresh_token': REFRESH_TOKEN}),
                          (oproxy_client_tenant(),
                           (TOKEN, 3600, ''),
                           {'access_token': TOKEN,
                            'valid_until': 3605,
                            'current_refresh_token': REFRESH_TOKEN},
                           {'access_token': TOKEN,
                            'valid_until': 8595,
                            'current_refresh_token': ''}),
                          (self_deployed_client(),
                           (TOKEN, 3600, ''),
                           {'access_token': TOKEN,
                            'valid_until': 3605,
                            'current_refresh_token': ''},
                           {'access_token': TOKEN,
                            'valid_until': 8595,
                            'current_refresh_token': ''})])
def test_get_access_token_with_context_invalid(mocker, client, tokens, context_invalid, context_valid):
    # Set
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=context_invalid)
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(client, '_oproxy_authorize', return_value=tokens)
    mocker.patch.object(client, '_get_self_deployed_token', return_value=tokens)
    mocker.patch.object(client, 'epoch_seconds', side_effect=[4000, 5000])

    # Arrange
    token = client.get_access_token()

    integration_context = demisto.setIntegrationContext.call_args[0][0]

    # Assert
    assert token == TOKEN
    assert integration_context == context_valid


@pytest.mark.parametrize('client, enc_content, tokens, res', [(oproxy_client_tenant(), TENANT,
                                                               {'access_token': TOKEN, 'expires_in': 3600},
                                                               (TOKEN, 3600, '')),
                                                              (oproxy_client_refresh(), REFRESH_TOKEN,
                                                               {'access_token': TOKEN,
                                                                'expires_in': 3600,
                                                                'refresh_token': REFRESH_TOKEN},
                                                               (TOKEN, 3600, REFRESH_TOKEN))])
def test_oproxy_request(mocker, requests_mock, client, enc_content, tokens, res):
    def get_encrypted(content, key):
        return content + key

    # Set
    body = {
        'app_name': APP_NAME,
        'registration_id': AUTH_ID,
        'encrypted_token': enc_content + ENC_KEY,
        'scope': None
    }
    mocker.patch.object(client, '_add_info_headers')
    mocker.patch.object(client, 'get_encrypted', side_effect=get_encrypted)
    requests_mock.post(
        TOKEN_URL,
        json=tokens)

    # Arrange
    req_res = client._oproxy_authorize()
    req_body = requests_mock._adapter.last_request.json()
    assert req_body == body
    assert req_res == res


def test_self_deployed_request(requests_mock):
    import urllib
    # Set
    client = self_deployed_client()

    body = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials',
        'scope': SCOPE,
        'resource': RESOURCE
    }

    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    # Arrange
    req_res = client._get_self_deployed_token()
    req_body = requests_mock._adapter.last_request._request.body
    assert req_body == urllib.parse.urlencode(body)
    assert req_res == (TOKEN, 3600, '')
