import pytest
from EWSApiModule import EWSClient, IncidentFilter
import exchangelib
from exchangelib import (
    BASIC,
    DELEGATE,
    OAUTH2,
    OAuth2AuthorizationCodeCredentials,
    Version,
    Configuration,
)
from exchangelib.protocol import Protocol

import json

from MicrosoftApiModule import AzureCloud, AzureCloudEndpoints

''' Constants '''

CLIENT_ID='test_client_id'
CLIENT_SECRET='test_client_secret'
ACCESS_TYPE=DELEGATE
TARGET_MAILBOX='test_default_target_mailbox'
EWS_SERVER='http://test_ews_server.com'
MAX_FETCH = 10
FOLDER='test_folder'
REQUEST_TIMEOUT='120'
INCIDENT_FILTER=IncidentFilter.RECEIVED_FILTER
VERSION='2013'

''' Utilities '''

def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())



''' Tests '''

def test_client_configure_oauth(mocker):
    """
    Given:
        - EWSClient configured with OAuth
    When:
        - Client is initialized
    Then:
        - The Credentials and Configuration objects are created correctly
    """
    ACCESS_TOKEN = 'test_access_token'
    class MockMSClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_access_token(self):
            return ACCESS_TOKEN

    mocker.patch('EWSApiModule.MicrosoftClient', MockMSClient)

    azure_cloud = AzureCloud(
            origin='test_origin',
            name='test_name',
            abbreviation='test_abrv',
            endpoints=AzureCloudEndpoints(active_directory='', exchange_online='https://outlook.office365.com')
    )


    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=OAUTH2,
        azure_cloud=azure_cloud,
    )

    credentials = client.credentials
    assert isinstance(credentials, OAuth2AuthorizationCodeCredentials)
    assert credentials.client_id == CLIENT_ID
    assert credentials.client_secret == CLIENT_SECRET
    assert credentials.access_token['access_token'] == ACCESS_TOKEN

    config = client.config
    assert config
    assert config.credentials == credentials
    assert config.auth_type == OAUTH2
    assert config.version == Version(exchangelib.version.EXCHANGE_O365)
    assert config.service_endpoint == 'https://outlook.office365.com/EWS/Exchange.asmx'

@pytest.mark.parametrize('manual_username, expected_username', [(None, CLIENT_ID),
                                                                 ('test_manual_username', 'test_manual_username')])
def test_client_configure_onprem(mocker, manual_username, expected_username):
    """
    Given:
        - EWSClient configured with auth_type other than OAUTH2
        - EWS server is specified
    When:
        - Client is initialized
    Then:
        - The Credentials and Configuration objects are created correctly
    """
    mocked_account = mocker.patch('EWSApiModule.Account')

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=BASIC,
        version=VERSION,
        manual_username=manual_username,
    )

    assert not client.auto_discover
    mocked_account.assert_not_called()
    assert client.server_build == exchangelib.version.EXCHANGE_2013
    credentials = client.credentials
    assert isinstance(credentials, exchangelib.Credentials)
    assert credentials.username == expected_username
    assert credentials.password == CLIENT_SECRET

    config = client.config
    assert config
    assert config.credentials == credentials
    assert config.auth_type == BASIC
    assert config.version == Version(exchangelib.version.EXCHANGE_2013)
    assert config.service_endpoint == EWS_SERVER
    
    
def test_client_configure_onprem_autodiscover(mocker):
    """
    Given:
        - EWSClient configured with any auth_type other than OAUTH2
        - EWS server is not specified
        - No previous clients were configured
    When:
        - Client is initialized
    Then:
        - The exchangelib auto-discover mechanism is used to configure the client
        - The Credentials, server and build are set correctly based on the auto-discovered configuration
        - Results are cached - subsequent client initializations should not trigger auto-discovery
    """
    expected_ews_server = 'https://discovered_server.com'
    expected_server_build = exchangelib.version.EXCHANGE_2016
    expected_version = Version(expected_server_build)
    
    class Account:
        def __init__(self, primary_smtp_address, access_type, autodiscover, credentials):
            config = Configuration(
                service_endpoint = expected_ews_server,
                credentials = credentials,
                auth_type = BASIC,
                version = expected_version,
            )
            self.protocol = Protocol(config=config)
    
    MockAccount = mocker.MagicMock(wraps=Account)
    mocker.patch('EWSApiModule.Account', MockAccount)

    # First client, should trigger autodiscover
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=TARGET_MAILBOX,
        max_fetch=MAX_FETCH,
    )

    assert client.auto_discover
    assert client.server_build == expected_server_build
    assert client.ews_server == expected_ews_server

    credentials = client.credentials
    assert isinstance(credentials, exchangelib.Credentials)
    assert credentials.username == CLIENT_ID
    assert credentials.password == CLIENT_SECRET
    
    MockAccount.assert_called_once_with(
        primary_smtp_address=TARGET_MAILBOX,
        autodiscover=True,
        access_type=ACCESS_TYPE,
        credentials=credentials,
    )
    
    # Subsequent client, should not trigger autodiscover (No additional calls to MockAccount)
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=TARGET_MAILBOX,
        max_fetch=MAX_FETCH,
    )

    assert client.auto_discover
    assert client.server_build == expected_server_build
    assert client.ews_server == expected_ews_server

    credentials = client.credentials
    assert isinstance(credentials, exchangelib.Credentials)
    assert credentials.username == CLIENT_ID
    assert credentials.password == CLIENT_SECRET
    
    MockAccount.assert_called_once()


def test_client_get_protocol():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_get_account():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_get_account_autodiscover():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_get_items_from_mailbox():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_get_item_from_mailbox():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_get_attachments_for_item():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_is_default_folder():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_get_folder_by_path():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_send_email():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_client_reply_email():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_handle_html():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_get_config_from_context():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_get_build_from_context():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_get_endpoint_from_context():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_cache_autodiscover_results():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_get_onprem_build():
    """
    Given:
    
    When:
    
    Then:
    """
    return

def test_get_onprem_version():
    """
    Given:
    
    When:
    
    Then:
    """
    return
