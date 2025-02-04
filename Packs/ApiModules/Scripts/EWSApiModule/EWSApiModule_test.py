import EWSApiModule
from EWSApiModule import (
    EWSClient,
    GetSearchableMailboxes,
    delete_attachments_for_message,
    delete_items,
    filter_dict_null,
    get_build_from_context,
    get_config_args_from_context,
    get_entry_for_object,
    get_on_prem_build,
    get_out_of_office_state,
    get_searchable_mailboxes,
    handle_html,
    move_item,
    move_item_between_mailboxes,
    recover_soft_delete_item,
    switch_hr_headers
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
    EWSDateTime,
    EWSTimeZone,
    FileAttachment,
    Message,
)
from exchangelib.protocol import Protocol
from exchangelib.attachments import AttachmentId
from exchangelib.util import TNS
from exchangelib.settings import OofSettings
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
        self.primary_smtp_address = primary_smtp_address
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

        self.oof_settings = MagicMock(spec=OofSettings, state='Disabled', external_audience='All',
                                      start=EWSDateTime(2025, 2, 4, 8, 0, tzinfo=EWSTimeZone(key='UTC')),
                                      end=EWSDateTime(2025, 2, 5, 8, 0, tzinfo=EWSTimeZone(key='UTC')),
                                      internal_reply='reply_internal', external_reply='reply_external')

        self.recoverable_items_deletions = MagicMock()
        self.mock_deleted_messages = [MagicMock(spec=Message, subject="Test Subject 1", id="id1", message_id="message1"),
                                      MagicMock(spec=Message, subject="Test Subject 2", id="id2", message_id="message2"),
                                      MagicMock(spec=Message, subject="Test Subject 3", id="id3", message_id="message3")]

        def mock_filter(message_id__in):
            output = MagicMock()
            output.all = lambda: [msg for msg in self.mock_deleted_messages if msg.message_id in message_id__in]
            return output
        self.recoverable_items_deletions.filter = mock_filter
        self.save_instance()

    def save_instance(self):
        pass

    def export(self, items):
        pass

    def upload(self, items):
        pass

    def bulk_delete(self, items):
        pass


@pytest.fixture()
def mock_account(mocker):
    mockAccount = mocker.MagicMock(wraps=MockAccount, instances=[])
    mocker.patch('EWSApiModule.Account', mockAccount)
    mocker.patch.object(MockAccount, 'save_instance', side_effect=lambda self: mockAccount.instances.append(self), autospec=True)
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

    assert account.primary_smtp_address == expected_smtp_address
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

    assert account.primary_smtp_address == expected_smtp_address
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

    assert item.id
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


def test_filter_dict_null():
    """
    Given:
        - Some dict
    When:
        - Dict has None values
    Then:
        - New dict is returned with the None values filtered out
    """
    test_dict = {
        'some_val': 0,
        'bad_val': None,
        'another_val': 'val',
        'another_bad_one': None,
    }
    expected_output = {
        'some_val': 0,
        'another_val': 'val',
    }

    assert filter_dict_null(test_dict) == expected_output


def test_switch_hr_headers():
    """
    Given:
        - A context object
    When:
        - Switching headers using a given header switch dict
    Then:
        - The keys that are present are switched
    """
    test_context = {
        'willswitch': '1234',
        'wontswitch': '111',
        'alsoswitch': 5555,
    }

    header_changes = {
        'willswitch': 'newkey',
        'alsoswitch': 'annothernewkey',
        'doesnt_exiest': 'doesnt break'
    }

    expected_output = {
        'annothernewkey': 5555,
        'newkey': '1234',
        'wontswitch': '111'
    }

    assert switch_hr_headers(test_context, header_changes) == expected_output


def test_get_entry_for_object():
    """
    Given:
        - Results from a command
    When:
        - Creating the command output
    Then:
        - All empty values are filtered from the results object
        - Readable output table is created correctly with the requested swapped headers
    """
    obj = [{'a': 1, 'b': 2, 'c': None, 'd': 3}, {'a': 11, 'b': None, 'c': 5, 'd': 6}, {'a': 3}]

    expected_output = [{'a': 1, 'b': 2, 'd': 3}, {'a': 11, 'c': 5, 'd': 6}, {'a': 3}]
    expected_hr = '### test\n|a|b|col|\n|---|---|---|\n| 1 | 2 |  |\n| 11 |  | 5 |\n| 3 |  |  |\n'

    entry = get_entry_for_object('test', 'test_key', obj, headers=['a', 'b', 'col'], hr_header_changes={'c': 'col'})

    assert entry.readable_output == expected_hr
    assert entry.outputs == expected_output
    assert entry.outputs_prefix == 'test_key'


def test_get_entry_for_object_empty():
    """
    Given:
        - Results from a command
    When:
        - The result object is empty
    Then:
        - A message indicating there is no result is returned
    """
    entry = get_entry_for_object('empty_obj', 'test_key', {})

    assert 'There is no output' in entry.readable_output


def test_delete_attachments_for_message(mocker):
    """
    Given:
        - Id of some email
        - Ids of attachments to delete
    When:
        - Calling the delete-attachments command
    Then:
        - The requested attachments are deleted from the given email
    """
    mock_items = {
        'itemid_1': [FileAttachment(name='attach_1', content='test_content_1', attachment_id=AttachmentId(id='attach1')),
                     FileAttachment(name='attach_2', content='test_content_2', attachment_id=AttachmentId(id='attach2'))],
        'itemid_2': [],
    }
    mocker.patch.object(EWSClient, 'get_attachments_for_item',
                        side_effect=lambda item_id, _account, _attach_ids: mock_items.get(item_id, f'Item {item_id} not found'))
    attachment_detach_mock = mocker.patch.object(FileAttachment, 'detach')

    expected_output = [
        {'attachmentId': 'attach1', 'action': 'deleted'},
        {'attachmentId': 'attach2', 'action': 'deleted'},
    ]

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

    result = delete_attachments_for_message(client, 'itemid_1')

    assert result[0].outputs == expected_output
    assert attachment_detach_mock.call_count == len(expected_output)


def test_get_searchable_mailboxes(mocker):
    """
    Given:
        - A configured EWS Client
    When:
        - The get_searchable_mailboxes function is called
    Then:
        - A list containing the relevant details for each searchable mailbox is returned
    """
    from xml.etree import ElementTree as ET
    mock_elements = [
        ET.fromstring(f'''
            <t:SearchableMailbox xmlns:t="{TNS}">
                <t:PrimarySmtpAddress>user1@example.com</t:PrimarySmtpAddress>
                <t:ReferenceId>00000000-0000-0000-0000-000000000001</t:ReferenceId>
                <t:DisplayName>User One</t:DisplayName>
                <t:IsExternalMailbox>false</t:IsExternalMailbox>
                <t:ExternalEmailAddress></t:ExternalEmailAddress>
            </t:SearchableMailbox>
        '''),
        ET.fromstring(f'''
            <t:SearchableMailbox xmlns:t="{TNS}">
                <t:PrimarySmtpAddress>user2@example.com</t:PrimarySmtpAddress>
                <t:ReferenceId>00000000-0000-0000-0000-000000000002</t:ReferenceId>
                <t:DisplayName>User Two</t:DisplayName>
                <t:IsExternalMailbox>false</t:IsExternalMailbox>
                <t:ExternalEmailAddress></t:ExternalEmailAddress>
            </t:SearchableMailbox>
        '''),
        ET.fromstring(f'''
            <t:SearchableMailbox xmlns:t="{TNS}">
                <t:PrimarySmtpAddress>external@otherdomain.com</t:PrimarySmtpAddress>
                <t:ReferenceId>00000000-0000-0000-0000-000000000003</t:ReferenceId>
                <t:DisplayName>External User</t:DisplayName>
                <t:IsExternalMailbox>true</t:IsExternalMailbox>
                <t:ExternalEmailAddress>external@otherdomain.com</t:ExternalEmailAddress>
            </t:SearchableMailbox>
        ''')
    ]

    expected_output = [
        {'mailbox': 'user1@example.com', 'mailboxId': '00000000-0000-0000-0000-000000000001',
         'displayName': 'User One', 'isExternal': 'false'},
        {'mailbox': 'user2@example.com', 'mailboxId': '00000000-0000-0000-0000-000000000002',
         'displayName': 'User Two', 'isExternal': 'false'},
        {'mailbox': 'external@otherdomain.com', 'mailboxId': '00000000-0000-0000-0000-000000000003',
         'displayName': 'External User', 'isExternal': 'true', 'externalEmailAddress': 'external@otherdomain.com'}
    ]

    mocker.patch.object(GetSearchableMailboxes, '_get_elements', return_value=mock_elements)

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
    results = get_searchable_mailboxes(client)

    assert results.outputs == expected_output


def test_move_item_between_mailboxes(mocker, mock_account):
    """
    Given:
        - ItemId to move between mailboxes
    When:
        - Calling the move-item-between-mailboxes command
    Then:
        - The requested item is exported to the destination mailbox and deleted from the source mailbox
    """
    mocker.patch.object(EWSClient, 'get_item_from_mailbox', return_value='item_to_move')
    mocker.patch.object(EWSClient, 'get_folder_by_path', side_effect=lambda path, _account, _is_public: f'folder-{path}')

    export_mock = mocker.patch.object(MockAccount, 'export', side_effect=lambda items: items)
    upload_mock = mocker.patch.object(MockAccount, 'upload')
    bulk_delete_mock = mocker.patch.object(MockAccount, 'bulk_delete')

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
    move_item_between_mailboxes(src_client=client,
                                item_id='item_id',
                                destination_mailbox='dest_mailbox',
                                destination_folder_path='dest_folder')

    export_mock.assert_called_once_with(['item_to_move'])
    upload_mock.assert_called_once_with([('folder-dest_folder', 'item_to_move')])
    bulk_delete_mock.assert_called_once_with(['item_to_move'])


def test_move_item(mocker, mock_account):
    """
    Given:
        - ItemId of the item to move
    When:
        - Calling the move_item function with an item ID and a destination folder path
    Then:
        - The requested item is moved to the specified destination folder
    """
    message_mock = MagicMock(spec=Message)
    get_item_mock = mocker.patch.object(EWSClient, 'get_item_from_mailbox', return_value=message_mock)
    mocker.patch.object(EWSClient, 'get_folder_by_path', side_effect=lambda path, is_public: f'folder-{path}')

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
    move_item(client, 'item1', 'dest_folder')

    assert get_item_mock.call_args[0][1] == 'item1'
    message_mock.move.assert_called_once_with('folder-dest_folder')


@pytest.mark.parametrize('delete_type', ['trash', 'soft', 'hard'])
def test_delete_items(mocker, delete_type):
    """
    Given:
        - ItemIds of the items to delete
    When:
        - Calling the delete_items function with the given ids
    Then:
        - The requested items are deleted from the mailbox
    """
    mock_items = {
        'item1': MagicMock(spec=Message, id='item1', message_id='msg1'),
        'item2': MagicMock(spec=Message, id='item2', message_id='msg2'),
        'item3': MagicMock(spec=Message, id='item3', message_id='msg3'),
    }
    mocker.patch.object(EWSClient, 'get_items_from_mailbox',
                        side_effect=lambda _target_mailbox, item_ids: [mock_items[item_id] for item_id in item_ids])

    item_ids = 'item1, item3'
    expect_deleted = ['item1', 'item3']
    expected_methods = {
        'trash': 'move_to_trash',
        'soft': 'soft_delete',
        'hard': 'delete',
    }

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

    delete_items(client, item_ids, delete_type)

    # Ensure only the expected delete function was called and the others were not
    for item_id, item in mock_items.items():
        expected_del_method = expected_methods[delete_type] if item_id in expect_deleted else None
        if expected_del_method:
            getattr(item, expected_del_method).assert_called_once()

        for delete_method in expected_methods.values():
            if delete_method != expected_del_method:
                getattr(item, delete_method).assert_not_called()


def test_get_out_of_office_state(mock_account):
    """
    Given:
        - Configured EWSClient instance
    When:
        - Getting the out of office state
    Then:
        - The out of office state is returned with the expected fields and values
    """
    expected_output = {  # Defined in MockAccount self.oof_settings
        'state': 'Disabled',
        'externalAudience': 'All',
        'start': '2025-02-04T08:00:00Z',
        'end': '2025-02-05T08:00:00Z',
        'internalReply': 'reply_internal',
        'externalReply': 'reply_external',
        'mailbox': 'test@default_target_mailbox.com',
    }

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
    result = get_out_of_office_state(client)

    assert result.outputs == expected_output


def test_recover_soft_delete_item(mock_account):
    """
    Given:
        - List of message ids to recover
    When:
        - The requested messages are in the recoverable messages object
    Then:
        - The messages are recovered and moved to the target folder
    """
    ids_to_recover = 'message1, message3'
    target_folder = 'target'
    expected_recovered_ids = {'message1', 'message3'}
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
    result = recover_soft_delete_item(client, ids_to_recover, target_folder)

    assert isinstance(result.outputs, list)
    assert {entry['messageId'] for entry in result.outputs} == expected_recovered_ids
    for message in mock_account.instances[0].mock_deleted_messages:
        if message.message_id in expected_recovered_ids:
            message.move.assert_called_once()


def test_create_folder():
    """
    Given:
        - 
    When:
        - 
    Then:
        -
    """


def test_mark_item_as_junk():
    """
    Given:
        - 
    When:
        - 
    Then:
        -
    """


def test_folder_to_context_entry():
    """
    Given:
        - 
    When:
        - 
    Then:
        -
    """


def test_get_folder():
    """
    Given:
        - 
    When:
        - 
    Then:
        -
    """


def test_get_expanded_group():
    """
    Given:
        - 
    When:
        - 
    Then:
        -
    """


def test_mark_item_as_read():
    """
    Given:
        - 
    When:
        - 
    Then:
        -
    """
