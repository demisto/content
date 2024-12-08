import pytest
from EWSApiModule import EWSClient, IncidentFilter
import exchangelib
from exchangelib import (
    BASIC,
    DELEGATE,
    OAUTH2,
    Account,
    Credentials,
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
DEFAULT_TARGET_MAILBOX='test_default_target_mailbox'
EWS_SERVER='http://test_ews_server.com'
MAX_FETCH = 10
FOLDER='test_folder'
REQUEST_TIMEOUT='120'
INCIDENT_FILTER=IncidentFilter.RECEIVED_FILTER
VERSION='2013'
BUILD = exchangelib.version.EXCHANGE_2013
AUTH_TYPE = BASIC

''' Utilities '''

def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())

def assert_configs_equal(config1: Configuration, config2: Configuration):
    assert config1.credentials == config2.credentials
    assert config1.auth_type == config2.auth_type
    assert config1.version == config2.version
    assert config1.service_endpoint == config2.service_endpoint
    assert config1.server == config2.server

DICSOVERY_EWS_SERVER = 'https://auto-discovered-server.com'
DISCOVERY_SERVER_BUILD = exchangelib.version.EXCHANGE_2016
DISCOVERY_VERSION = Version(DISCOVERY_SERVER_BUILD)
class MockAccount(Account):
    class MockRoot:
        class MockRights:
            def __init__(self, *args, **kwargs):
                self.read = True

        def __init__(self, *args, **kwargs):
            self.effective_rights = self.MockRights()

    def __init__(self, primary_smtp_address, access_type, autodiscover, credentials=None, config=None, default_timezone=None,
                 *args, **kwargs):
        self.smtp_address=primary_smtp_address
        self.access_type=access_type
        self.autodiscover=autodiscover
        self.credentials=credentials
        self.config=config
        self.default_timezone=default_timezone

        if autodiscover:
            if not credentials:
                raise ValueError('Credentials must be provided for autodiscovery')

            config = Configuration(
                service_endpoint = DICSOVERY_EWS_SERVER,
                credentials = credentials,
                auth_type = AUTH_TYPE,
                version = DISCOVERY_VERSION,
            )
        elif not config:
            raise ValueError('Autodiscovery is false and no config was provided')

        self.protocol = Protocol(config=config)
        self.root = self.MockRoot() # type:ignore

@pytest.fixture()
def mock_account(mocker):
    mockAccount = mocker.MagicMock(wraps=MockAccount)
    mocker.patch('EWSApiModule.Account', mockAccount)
    return mockAccount

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
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=OAUTH2,
        azure_cloud=azure_cloud,
        version='O365',
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
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
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
    assert config.auth_type == AUTH_TYPE
    assert config.version == Version(exchangelib.version.EXCHANGE_2013)
    assert config.service_endpoint == EWS_SERVER
    
    
def test_client_configure_onprem_autodiscover(mock_account):
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
    # First client, should trigger autodiscover
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        max_fetch=MAX_FETCH,
    )

    assert client.auto_discover
    assert client.server_build == DISCOVERY_SERVER_BUILD
    assert client.ews_server == DICSOVERY_EWS_SERVER

    credentials = client.credentials
    assert isinstance(credentials, exchangelib.Credentials)
    assert credentials.username == CLIENT_ID
    assert credentials.password == CLIENT_SECRET
    
    mock_account.assert_called_once_with(
        primary_smtp_address=DEFAULT_TARGET_MAILBOX,
        autodiscover=True,
        access_type=ACCESS_TYPE,
        credentials=credentials,
    )
    
    # Subsequent client, should not trigger autodiscover (No additional calls to MockAccount)
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        max_fetch=MAX_FETCH,
    )

    assert client.auto_discover
    assert client.server_build == DISCOVERY_SERVER_BUILD
    assert client.ews_server == DICSOVERY_EWS_SERVER

    credentials = client.credentials
    assert isinstance(credentials, exchangelib.Credentials)
    assert credentials.username == CLIENT_ID
    assert credentials.password == CLIENT_SECRET
    
    mock_account.assert_called_once()


def test_client_get_protocol():
    """
    Given:
        - EWSClient is configured with EWS server
    When:
        - client.get_protocol is called
    Then:
        - The Protocol object is returned correctly
    """
    expected_protocol = Protocol(config=Configuration(
        service_endpoint=EWS_SERVER,
        credentials=Credentials(username=CLIENT_ID, password=CLIENT_SECRET),
        auth_type=AUTH_TYPE,
        version=Version(exchangelib.version.EXCHANGE_2013),
    ))

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION,
    )

    assert client.get_protocol() == expected_protocol

def test_client_get_protocol_autodiscover(mock_account):
    """
    Given:
        - EWSClient is configured without EWS server
    When:
        - client.get_protocol is called
    Then:
        - The Protocol object is returned correctly based on the auto-discovered configuration
    """
    expected_protocol = Protocol(config=Configuration(
        service_endpoint=DICSOVERY_EWS_SERVER,
        credentials=Credentials(username=CLIENT_ID, password=CLIENT_SECRET),
        auth_type=AUTH_TYPE,
        version=DISCOVERY_VERSION,
    ))

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
    )

    assert client.get_protocol() == expected_protocol

@pytest.mark.parametrize('target_mailbox', [None, 'test_target_mailbox'])
def test_client_get_account(mock_account, target_mailbox):
    """
    Given:
        - EWSClient is configured with EWS server
    When:
        - client.get_account() is called
    Then:
        - The Account object is returned correctly
    """
    time_zone = 'test_tz'
    
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION,
    )

    account = client.get_account(target_mailbox=target_mailbox, time_zone=time_zone)
    assert isinstance(account, MockAccount)

    expected_smtp_address = target_mailbox if target_mailbox else DEFAULT_TARGET_MAILBOX
    expected_config = Configuration(
        service_endpoint=EWS_SERVER,
        credentials=Credentials(username=CLIENT_ID, password=CLIENT_SECRET),
        auth_type=AUTH_TYPE,
        version=Version(BUILD),
    )

    assert account.smtp_address == expected_smtp_address
    assert account.config
    assert_configs_equal(expected_config, account.config)
    assert account.access_type == ACCESS_TYPE
    assert account.default_timezone == time_zone
    assert not account.autodiscover

def test_client_get_account_autodiscover(mock_account):
    """
    Given:
        - EWSClient is configured without EWS server
    When:
        - client.get_account() is called
    Then:
        - The Account object is returned correctly based on the auto-discovered configuration
    """
    time_zone = 'test_tz'
    
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
    )

    account = client.get_account(time_zone=time_zone)
    assert isinstance(account, MockAccount)

    expected_smtp_address = DEFAULT_TARGET_MAILBOX
    expected_config = Configuration(
        service_endpoint=DICSOVERY_EWS_SERVER,
        credentials=Credentials(username=CLIENT_ID, password=CLIENT_SECRET),
        auth_type=AUTH_TYPE,
        version=DISCOVERY_VERSION,
    )

    assert account.smtp_address == expected_smtp_address
    assert account.config
    assert_configs_equal(expected_config, account.config)
    assert account.access_type == ACCESS_TYPE
    assert account.default_timezone == time_zone
    assert not account.autodiscover

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
