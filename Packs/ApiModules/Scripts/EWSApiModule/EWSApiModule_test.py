import EWSApiModule
from EWSApiModule import (
    EWSClient,
    get_build_from_context,
    get_config_args_from_context,
    get_on_prem_build,
    handle_html
)

import pytest
from unittest.mock import MagicMock
import json
import base64
import uuid

import exchangelib
from exchangelib import (
    BASIC,
    DELEGATE,
    OAUTH2,
    Credentials,
    Configuration,
    FileAttachment,
    Message,
)
from exchangelib.protocol import Protocol
from MicrosoftApiModule import AzureCloud, AzureCloudEndpoints

''' Constants '''

CLIENT_ID = 'test_client_id'
CLIENT_SECRET = 'test_client_secret'
ACCESS_TYPE = DELEGATE
DEFAULT_TARGET_MAILBOX = 'test@default_target_mailbox.com'
EWS_SERVER = 'http://test_ews_server.com'
MAX_FETCH = 10
FOLDER = 'test_folder'
REQUEST_TIMEOUT = '120'
VERSION_STR = '2013'
BUILD = exchangelib.version.EXCHANGE_2013
VERSION = exchangelib.Version(BUILD)
AUTH_TYPE = BASIC
MSG_ID = 'message_1'
DICSOVERY_EWS_SERVER = 'https://auto-discovered-server.com'
DISCOVERY_SERVER_BUILD = exchangelib.version.EXCHANGE_2016
DISCOVERY_VERSION = exchangelib.Version(DISCOVERY_SERVER_BUILD)

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


class MockAccount():
    class MockRights:
        def __init__(self, *args, **kwargs):
            self.read = True

    def __init__(self, primary_smtp_address, access_type, autodiscover, credentials=None, config=None, default_timezone=None,
                 *args, **kwargs):
        self.smtp_address = primary_smtp_address
        self.access_type = access_type
        self.autodiscover = autodiscover
        self.credentials = credentials
        self.config = config
        self.default_timezone = default_timezone

        if autodiscover:
            if not credentials:
                raise ValueError('Credentials must be provided for autodiscovery')

            config = Configuration(
                service_endpoint=DICSOVERY_EWS_SERVER,
                credentials=credentials,
                auth_type=AUTH_TYPE,
                version=DISCOVERY_VERSION,
            )
        elif not config:
            raise ValueError('Autodiscovery is false and no config was provided')

        self.version = config.version
        self.protocol = Protocol(config=config)

        self.root = MagicMock()
        self.root.tois = MagicMock()

        def mock_floordiv(name):
            return self.root.tois
        self.root.tois.__floordiv__.side_effect = mock_floordiv
        self.root.effective_rights = MagicMock()
        self.root.effective_rights.read = True

        self.inbox = MagicMock()
        self.drafts = MagicMock()
        self.drafts.messages = {MSG_ID: Message(account=MagicMock(spec=exchangelib.Account),
                                                id=MSG_ID, subject='Test subject', body='Test body')}
        self.inbox.get = MagicMock(side_effect=lambda id: self.drafts.messages.get(id))


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
    assert isinstance(credentials, exchangelib.OAuth2AuthorizationCodeCredentials)
    assert credentials.client_id == CLIENT_ID
    assert credentials.client_secret == CLIENT_SECRET
    assert credentials.access_token['access_token'] == ACCESS_TOKEN

    config = client.config
    assert config
    assert config.credentials == credentials
    assert config.auth_type == OAUTH2
    assert config.version == exchangelib.Version(exchangelib.version.EXCHANGE_O365)
    assert config.service_endpoint == 'https://outlook.office365.com/EWS/Exchange.asmx'


def test_client_configure_onprem(mocker):
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
        version=VERSION_STR,
    )

    assert not client.auto_discover
    mocked_account.assert_not_called()
    assert client.server_build == exchangelib.version.EXCHANGE_2013
    credentials = client.credentials
    assert isinstance(credentials, exchangelib.Credentials)
    assert credentials.username == CLIENT_ID
    assert credentials.password == CLIENT_SECRET

    config = client.config
    assert config
    assert config.credentials == credentials
    assert config.auth_type == AUTH_TYPE
    assert config.version == VERSION
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
        version=VERSION,
    ))

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
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
        version=VERSION_STR,
    )

    account = client.get_account(target_mailbox=target_mailbox, time_zone=time_zone)
    assert isinstance(account, MockAccount)

    expected_smtp_address = target_mailbox if target_mailbox else DEFAULT_TARGET_MAILBOX
    expected_config = Configuration(
        service_endpoint=EWS_SERVER,
        credentials=Credentials(username=CLIENT_ID, password=CLIENT_SECRET),
        auth_type=AUTH_TYPE,
        version=VERSION,
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


def test_client_get_items_from_mailbox(mocker):
    """
    Given:
        - Configured EWSClient
    When:
        - client.get_items_from_mailbox is called
    Then:
        - Mailbox items are returned as expected
    """
    mock_items = {'item_id_1': 'item_1',
                  'item_id_2': 'item_2',
                  'item_id_3': 'item_3',
                  }

    def mock_account_fetch(self, ids: list[exchangelib.items.Item]):
        mocked_items = []
        for item in ids:
            id = item.id
            if id not in mock_items:
                raise ValueError(f"Item with ID {id} not found in mock items")
            mocked_item = mocker.MagicMock()
            mocked_item.id = id
            mocked_item.value = mock_items.get(id)
            mocked_items.append(mocked_item)
        return mocked_items

    mocker.patch.object(EWSApiModule.Account, 'fetch', mock_account_fetch)

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
    )
    items = client.get_items_from_mailbox(client.get_account(), list(mock_items.keys()))

    for item in items:
        assert item.id in mock_items
        assert item.value == mock_items[item.id]


def test_client_get_item_from_mailbox(mocker):
    """
    Given:
        - Configured EWSClient
    When:
        - client.get_item_from_mailbox is called
    Then:
        - The item is returned as expected
    """
    mock_items = {'item_id_1': 'item_1',
                  'item_id_2': 'item_2',
                  'item_id_3': 'item_3',
                  }

    def mock_account_fetch(self, ids: list[exchangelib.items.Item]):
        mocked_items = []
        for item in ids:
            id = item.id
            if id not in mock_items:
                raise ValueError(f"Item with ID {id} not found in mock items")
            mocked_item = mocker.MagicMock()
            mocked_item.id = id
            mocked_item.value = mock_items.get(id)
            mocked_items.append(mocked_item)
        return mocked_items

    mocker.patch.object(EWSApiModule.Account, 'fetch', mock_account_fetch)

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
    )
    item = client.get_item_from_mailbox(client.get_account(), list(mock_items.keys())[0])

    assert item.id == list(mock_items.keys())[0]
    assert item.value == mock_items[item.id]


def test_client_get_attachments_for_item(mocker):
    """
    Given:
        - Configured EWSClient
    When:
        - client.get_attachments_for_item is called
    Then:
        - The attachments for the item are returned as expected
    """
    item_id = 'item_id_1'
    attach_ids = ['attach_id_1', 'attach_id_2', 'attach_id_3']
    mock_item = mocker.MagicMock()
    mock_item.id = item_id
    mock_item.attachments = [mocker.MagicMock(attachment_id=mocker.MagicMock(id=id)) for id in attach_ids]

    mocker.patch.object(EWSClient, 'get_item_from_mailbox', return_value=mock_item)

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
    )
    expected_attach_ids = attach_ids[:2]
    attachments = client.get_attachments_for_item(item_id, client.get_account(), expected_attach_ids)

    for attachment in attachments:
        assert attachment in mock_item.attachments
        assert attachment.attachment_id.id in expected_attach_ids


@pytest.mark.parametrize('folder_path, is_public, expected_is_public', [
    (FOLDER, True, True),
    (FOLDER, False, False),
    ('Calendar', True, False),
    ('Deleted Items', True, False)])
def test_client_is_default_folder(folder_path, is_public, expected_is_public):
    """
    Given:
        - Configured EWSClient
    When:
        - client.get_default_folder is called
    Then:
        - The return value indicates if the folder is a known public folder (i.e. default and public folder)
    """
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
        folder=FOLDER,
        is_public_folder=is_public,
    )

    assert client.is_default_folder(folder_path) == expected_is_public


@pytest.mark.parametrize('is_public', [True, False])
def test_client_is_default_folder_with_override(is_public):
    """
    Given:
        - Configured EWSClient
    When:
        - client.get_default_folder is called with is_public argument
    Then:
        - The return value is overriden by the is_public argument
    """
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
        folder=FOLDER,
        is_public_folder=True,
    )

    assert client.is_default_folder(FOLDER, is_public) == is_public


def test_client_get_folder_by_path(mocker, mock_account):
    """
    Given:
        - Configured EWSClient
    When:
        - client.get_folder_by_path is called
    Then:
        - The folder at the specified path is returned
    """
    path = 'Inbox/Subfolder/Test'

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
        folder=FOLDER,
        is_public_folder=True,
    )
    account = client.get_account()

    client.get_folder_by_path(path, account)

    expected_calls = [mocker.call(part) for part in path.split('/')]
    assert account.root.tois.__floordiv__.call_args_list == expected_calls  # type: ignore


def test_client_send_email(mocker, mock_account):
    """
    Given:
        - A configured EWSClient instance
    When:
        -  client.send_email is called
    Then:
        - The email is saved and sent successfully
        - The account field of the message is set
    """
    send_and_save_mock = mocker.patch.object(EWSApiModule.Message, 'send_and_save')
    message = Message(
        subject='Test subject',
        body='Test message',
    )

    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
        folder=FOLDER,
    )

    client.send_email(message)

    send_and_save_mock.assert_called_once()
    assert message.account


def test_client_reply_email(mocker, mock_account):
    """
    Given:
        - A configured EWSClient instance
        - Arguments for a reply email
    When:
        -  client.reply_email is called
    Then:
        - The reply is created and sent successfully
    """

    def mock_save(self, folder):
        folder.messages['reply_1'] = self
        return mocker.MagicMock(id='reply_1')

    mocker.patch.object(exchangelib.items.ReplyToItem, 'save', mock_save)
    mocked_reply_send = mocker.patch.object(exchangelib.items.ReplyToItem, 'send')
    client = EWSClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        access_type=ACCESS_TYPE,
        default_target_mailbox=DEFAULT_TARGET_MAILBOX,
        ews_server=EWS_SERVER,
        max_fetch=MAX_FETCH,
        auth_type=AUTH_TYPE,
        version=VERSION_STR,
        folder=FOLDER,
    )

    reply_body = 'This is a reply'
    reply_to = ['recipient@example.com']
    reply_cc = ['cc_recipient@example.com']
    reply_bcc = []
    message = client.reply_email(
        inReplyTo=MSG_ID,
        to=reply_to,
        body=reply_body,
        subject='',
        bcc=reply_bcc,
        cc=reply_cc,
        htmlBody=None,
        attachments=[],
    )

    assert isinstance(message, exchangelib.items.ReplyToItem)
    assert 'Re:' in str(message.subject)
    assert message.new_body == reply_body
    assert message.to_recipients == reply_to
    assert message.cc_recipients == reply_cc
    assert message.bcc_recipients == reply_bcc

    mocked_reply_send.assert_called_once()


def test_handle_html(mocker):
    """
    Given:
        - HTML string containing inline images
    When:
        - Parsing the HTML string to incorporate the inline images
    Then:
        - Clean the HTML string and add the relevant references to image files
    """
    mocker.patch.object(uuid, 'uuid4', return_value='abcd1234')

    html_input = '<html><body>some text <img src="data:image/abcd;base64,abcd"></body></html>'
    expected_clean_body = '<html><body>some text <img src="cid:image0@abcd1234_abcd1234"></body></html>'
    expected_attachment_params = [{'data': b'i\xb7\x1d', 'name': 'image0', 'cid': 'image0@abcd1234_abcd1234'}]

    clean_body, attachments = handle_html(html_input)
    assert clean_body == expected_clean_body
    assert len(attachments) == len(expected_attachment_params)
    for i, attachment in enumerate(attachments):
        assert isinstance(attachment, FileAttachment)
        attachment_params = {'data': attachment.content, 'name': attachment.name, 'cid': attachment.content_id}
        assert attachment_params == expected_attachment_params[i]


def test_handle_html_no_images(mocker):
    """
    Given:
        - HTML string with no inline images
    When:
        - The handle_html function is called with the given HTML content
    Then:
        - No images will be detected and the output will be the original HTML content
    """
    mocker.patch.object(uuid, 'uuid4', return_value='abcd1234')

    html_input = '<html><body>some text</body></html>'
    expected_clean_body = '<html><body>some text</body></html>'
    expected_attachment_params = []

    clean_body, attachments = handle_html(html_input)

    assert clean_body == expected_clean_body
    assert len(attachments) == len(expected_attachment_params)
    for i, attachment in enumerate(attachments):
        assert isinstance(attachment, FileAttachment)
        attachment_params = {'data': attachment.content, 'name': attachment.name, 'cid': attachment.content_id}
        assert attachment_params == expected_attachment_params[i]


def test_handle_html_longer_input():
    """
    Given:
        - HTML string with multiple inline images and html elements
    When:
        - The handle_html function is called with the given HTML content
    Then:
        - The function correctly extracts all image sources
    """
    html_content = '''<html>
    <body>
        <h1>Test Email</h1>
        <p>This is a test email with attached images.</p>
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgA==">
        <div>
            <p>Another paragraph with an embedded image:</p>
            <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2w==">
        </div>
        <p>This paragraph has no image.</p>
        <a href="https://example.com">A link without an image</a>
    </body>
    </html>
    '''

    expected_image_data = [
        base64.b64decode("iVBORw0KGgoAAAANSUhEUgA=="),
        base64.b64decode("/9j/4AAQSkZJRgABAQEAYABgAAD/2w=="),
    ]
    expected_parsed_html = '''<html>
    <body>
        <h1>Test Email</h1>
        <p>This is a test email with attached images.</p>
        <img src="cid:{image0_cid}">
        <div>
            <p>Another paragraph with an embedded image:</p>
            <img src="cid:{image1_cid}">
        </div>
        <p>This paragraph has no image.</p>
        <a href="https://example.com">A link without an image</a>
    </body>
    </html>
    '''

    clean_body, extracted_images = handle_html(html_content)

    assert clean_body == expected_parsed_html.format(image0_cid=extracted_images[0].content_id,
                                                     image1_cid=extracted_images[1].content_id)
    assert len(extracted_images) == 2
    for i, image in enumerate(extracted_images):
        assert image.content == expected_image_data[i]


def test_get_config_args_from_context(mocker):
    """
    Given:
     - The integration context contains cached auto-discovery information
    When:
     - Trying to create a configuration object
    Then:
     - A configuration object is created based on the context information
    """
    mocker.patch('EWSApiModule.get_build_from_context', return_value=BUILD)
    context = {
        'auth_type': 'test_auth_type',
        'api_version': VERSION_STR,
        'service_endpoint': 'test_service_endpoint'
    }
    credentials = Credentials(username=CLIENT_ID, password=CLIENT_SECRET)
    expected_args = {
        'credentials': credentials,
        'auth_type': context['auth_type'],
        'version': exchangelib.Version(BUILD, VERSION_STR),
        'service_endpoint': context['service_endpoint'],
    }
    config_args = get_config_args_from_context(context, credentials)

    assert config_args == expected_args


def test_get_build_from_context():
    """
    Given:
     - The integration context contains cached auto-discovery information
    When:
     - Trying to get the discovered build data
    Then:
     - A Build object is returned based on the context information
    """
    context = {'build': '10.0.10.1'}

    build = get_build_from_context(context)

    assert build == exchangelib.Build(10, 0, 10, 1)


@pytest.mark.parametrize('version, expected', [
    ('2013', exchangelib.version.EXCHANGE_2013),
    ('2016', exchangelib.version.EXCHANGE_2016),
    ('2013_SP1', exchangelib.version.EXCHANGE_2013_SP1),
])
def test_get_onprem_build(version, expected):
    """
    Given:
        - A valid string representing a supported onprem exchange version
    When:
        - Converting the string to a Build object
    Then:
        - A Build object of the requested version is returned
    """
    assert get_on_prem_build(version) == expected


@pytest.mark.parametrize('version', [
    ('2004'),
    ('test_version'),
    ('2003_SP1')
])
def test_get_onprem_build_bad_version(version):
    """
    Given:
        - An invalid string input to get_onprem_build
    When:
        - Converting the string to a Build object
    Then:
        - A ValueError should be raised
    """
    with pytest.raises(ValueError):
        get_on_prem_build(version)
