from enum import Enum
import uuid
from urllib.parse import urlparse

from CommonServerPython import *  # noqa: F401

from MicrosoftApiModule import *
from exchangelib import (
    OAUTH2,
    BASIC,
    NTLM,
    DIGEST,
    Account,
    Build,
    Configuration,
    Credentials,
    FileAttachment,
    Folder,
    HTMLBody,
    Identity,
    Version,
)
from exchangelib.errors import (
    ErrorInvalidIdMalformed,
    ErrorItemNotFound,
    AutoDiscoverFailed,
    ResponseMessageError,
    ErrorNameResolutionNoResults,
)
from exchangelib.items import Item, Message
from exchangelib.protocol import BaseProtocol, FaultTolerance, Protocol
from exchangelib.folders.base import BaseFolder
from exchangelib.credentials import BaseCredentials, OAuth2AuthorizationCodeCredentials
from exchangelib.services.common import EWSService, EWSAccountService
from exchangelib.util import MNS, TNS, create_element, add_xml_child
from oauthlib.oauth2 import OAuth2Token
from exchangelib.version import (
    EXCHANGE_O365,
    EXCHANGE_2007,
    EXCHANGE_2010,
    EXCHANGE_2010_SP2,
    EXCHANGE_2013,
    EXCHANGE_2013_SP1,
    EXCHANGE_2016,
    EXCHANGE_2019,
)

""" Constants """
INTEGRATION_NAME = get_integration_name()
FOLDER_ID_LEN = 120

SUPPORTED_ON_PREM_BUILDS = {
    '2007': EXCHANGE_2007,
    '2010': EXCHANGE_2010,
    '2010_SP2': EXCHANGE_2010_SP2,
    '2013': EXCHANGE_2013,
    '2013_SP1': EXCHANGE_2013_SP1,
    '2016': EXCHANGE_2016,
    '2019': EXCHANGE_2019,
}

""" Context Keys """
ATTACHMENT_ID = 'attachmentId'
ACTION = 'action'
MAILBOX = 'mailbox'
MAILBOX_ID = 'mailboxId'
MOVED_TO_MAILBOX = 'movedToMailbox'
MOVED_TO_FOLDER = 'movedToFolder'
NEW_ITEM_ID = 'newItemId'
MESSAGE_ID = 'messageId'
ITEM_ID = 'itemId'
TARGET_MAILBOX = 'receivedBy'
FOLDER_ID = 'id'

""" Context Paths """
CONTEXT_UPDATE_ITEM_ATTACHMENT = f'.ItemAttachments(val.{ATTACHMENT_ID} == obj.{ATTACHMENT_ID})'
CONTEXT_UPDATE_FILE_ATTACHMENT = f'.FileAttachments(val.{ATTACHMENT_ID} == obj.{ATTACHMENT_ID})'
CONTEXT_UPDATE_FOLDER = f'EWS.Folders(val.{FOLDER_ID} == obj.{FOLDER_ID})'
CONTEXT_UPDATE_EWS_ITEM = f'EWS.Items((val.{ITEM_ID} === obj.{ITEM_ID} || ' \
    f'(val.{MESSAGE_ID} && obj.{MESSAGE_ID} && val.{MESSAGE_ID} === obj.{MESSAGE_ID}))' \
    f' && val.{TARGET_MAILBOX} === obj.{TARGET_MAILBOX})'


class IncidentFilter(str, Enum):
    MODIFIED_FILTER = 'modified-time'
    RECEIVED_FILTER = 'received-time'


class CustomDomainOAuth2Credentials(OAuth2AuthorizationCodeCredentials):
    def __init__(self, azure_cloud: AzureCloud, **kwargs):
        self.ad_base_url = azure_cloud.endpoints.active_directory or 'https://login.microsoftonline.com'
        self.exchange_online_scope = azure_cloud.endpoints.exchange_online or 'https://outlook.office365.com'
        demisto.debug(f'Initializing {self.__class__}: '
                      f'{azure_cloud.abbreviation=} | {self.ad_base_url=} | {self.exchange_online_scope}')
        super().__init__(**kwargs)

    @property
    def token_url(self):
        """
            The URL to request tokens from.
            Overrides the token_url property to specify custom token retrieval endpoints for different authority's cloud env.
        """
        # We may not know (or need) the Microsoft tenant ID. If not, use common/ to let Microsoft select the appropriate
        # tenant for the provided authorization code or refresh token.
        return f'{self.ad_base_url}/{self.tenant_id or "common"}/oauth2/v2.0/token'

    @property
    def scope(self):
        """
            The scope we ask for the token to have
            Overrides the scope property to specify custom token retrieval endpoints for different authority's cloud env.
        """
        return [f'{self.exchange_online_scope}/.default']


class ProxyAdapter(HTTPAdapter):
    """
    Proxy Adapter used to add PROXY to requests
    """

    def send(self, *args, **kwargs):
        kwargs['proxies'] = handle_proxy()
        return super().send(*args, **kwargs)


class InsecureSSLAdapter(SSLAdapter):
    """
    Insecure SSL Adapter used to disable SSL verification for requests.
    """

    def __init__(self, *args, **kwargs):
        # Processing before init call
        kwargs.pop('verify', None)
        super().__init__(verify=False, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        # We're overriding a method, so we have to keep the signature, although verify is unused
        del verify
        super().cert_verify(conn=conn, url=url, verify=False, cert=cert)


class InsecureProxyAdapter(InsecureSSLAdapter):
    """
    Insecure Proxy Adapter used to add proxy to requests.
    """

    def send(self, *args, **kwargs):
        kwargs['proxies'] = handle_proxy()
        return super().send(*args, **kwargs)


class GetSearchableMailboxes(EWSService):
    """
    EWSAccountService class used for getting Searchable Mailboxes
    """
    SERVICE_NAME = 'GetSearchableMailboxes'
    element_container_name = f'{{{MNS}}}SearchableMailboxes'

    @staticmethod
    def parse_element(element):
        return {
            MAILBOX: element.find(f'{{{TNS}}}PrimarySmtpAddress').text
            if element.find(f'{{{TNS}}}PrimarySmtpAddress') is not None else None,
            MAILBOX_ID: element.find(f'{{{TNS}}}ReferenceId').text
            if element.find(f'{{{TNS}}}ReferenceId') is not None else None,
            'displayName': element.find(f'{{{TNS}}}DisplayName').text
            if element.find(f'{{{TNS}}}DisplayName') is not None else None,
            'isExternal': element.find(f'{{{TNS}}}IsExternalMailbox').text
            if element.find(f'{{{TNS}}}IsExternalMailbox') is not None else None,
            'externalEmailAddress': element.find(f'{{{TNS}}}ExternalEmailAddress').text
            if element.find(f'{{{TNS}}}ExternalEmailAddress') is not None else None,
        }

    def call(self):
        if self.protocol.version.build < EXCHANGE_2013:
            raise NotImplementedError(f'{self.SERVICE_NAME} is only supported for Exchange 2013 servers and later')
        elements = self._get_elements(payload=self.get_payload())
        return [self.parse_element(e) for e in elements if e.find(f"{{{TNS}}}ReferenceId").text]

    def get_payload(self):
        element = create_element(f'm:{self.SERVICE_NAME}')
        return element


class MarkAsJunk(EWSAccountService):
    """
    EWSAccountService class used for marking items as junk
    """
    SERVICE_NAME = 'MarkAsJunk'

    def call(self, item_id, move_item):
        elements = list(self._get_elements(payload=self.get_payload(item_id=item_id, move_item=move_item)))
        for element in elements:
            if isinstance(element, ResponseMessageError):
                return str(element)
        return 'Success'

    def get_payload(self, item_id, move_item):
        junk = create_element(f'm:{self.SERVICE_NAME}',
                              {'IsJunk': 'true',
                               'MoveItem': 'true' if move_item else 'false'})

        items_list = create_element('m:ItemIds')
        item_element = create_element('t:ItemId', {'Id': item_id})
        items_list.append(item_element)
        junk.append(items_list)

        return junk


class ExpandGroup(EWSService):
    """
    EWSAccountService class used for expanding groups
    """
    SERVICE_NAME = 'ExpandDL'
    element_container_name = f'{{{MNS}}}DLExpansion'

    @staticmethod
    def parse_element(element):
        return {
            MAILBOX: element.find(f'{{{TNS}}}EmailAddress').text
            if element.find(f'{{{TNS}}}EmailAddress') is not None
            else None,
            'displayName': element.find(f'{{{TNS}}}Name').text
            if element.find(f'{{{TNS}}}Name') is not None
            else None,
            'mailboxType': element.find(f'{{{TNS}}}MailboxType').text
            if element.find(f'{{{TNS}}}MailboxType') is not None
            else None,
        }

    def call(self, email_address, recursive_expansion=False):
        if self.protocol.version.build < EXCHANGE_2010:
            raise NotImplementedError(f'{self.SERVICE_NAME} is only supported for Exchange 2010 servers and later')
        try:
            if recursive_expansion == 'True':
                group_members: dict = {}
                self.expand_group_recursive(email_address, group_members)
                return list(group_members.values())
            else:
                return self.expand_group(email_address)

        except ErrorNameResolutionNoResults:
            demisto.results('No results were found.')
            sys.exit()

    def get_payload(self, email_address):
        element = create_element(f'm:{self.SERVICE_NAME}')
        mailbox_element = create_element('m:Mailbox')
        add_xml_child(mailbox_element, 't:EmailAddress', email_address)
        element.append(mailbox_element)
        return element

    def expand_group(self, email_address):
        """
        Expand given group
        :param email_address: email address of the group to expand
        :return: list dict with parsed expanded group data
        """
        elements = self._get_elements(payload=self.get_payload(email_address))
        return [self.parse_element(x) for x in elements]

    def expand_group_recursive(self, email_address, non_dl_emails, dl_emails=None):
        """
        Expand group recursively
        :param email_address: email address of the group to expand
        :param non_dl_emails: non distribution only emails
        :param dl_emails: (Optional) distribution only emails
        :return: Set of dl emails and non dl emails (returned via reference)
        """
        if dl_emails is None:
            dl_emails = set()

        if email_address in non_dl_emails or email_address in dl_emails:
            return

        dl_emails.add(email_address)

        for member in self.expand_group(email_address):
            if (member['mailboxType'] == 'PublicDL' or member['mailboxType'] == 'PrivateDL'):
                self.expand_group_recursive(member.get('mailbox'), non_dl_emails, dl_emails)
            else:
                if member['mailbox'] not in non_dl_emails:
                    non_dl_emails[member['mailbox']] = member


class EWSClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        access_type: str,
        default_target_mailbox: str,
        max_fetch: int,
        ews_server: str = '',
        auth_type: str = '',
        version: str = '',
        folder: str = 'Inbox',
        is_public_folder: bool = False,
        request_timeout: int = 120,
        mark_as_read: bool = False,
        incident_filter: IncidentFilter = IncidentFilter.RECEIVED_FILTER,
        azure_cloud: Optional[AzureCloud] = None,
        tenant_id: str = '',
        self_deployed: bool = True,
        log_memory: bool = False,
        app_name: str = 'EWS',
        insecure: bool = True,
        proxy: bool = False,
    ):
        """
        Client used to communicate with EWS

        :param client_id: Application client ID
        :param client_secret: Application client secret
        :param access_type: Access type for authentication (delegate or impersonation)
        :param default_target_mailbox: Email address from which to fetch incidents
        :param max_fetch: Max incidents per fetch
        :param ews_server: The EWS Server address.
        :param auth_type: Authentication type (OAUTH2, BASIC, NTLM or DIGEST)
        :param version: Exchange version to use (O365, 2007, 2010, 2010_SP2, 2013, 2013_SP1, 2016, 2019)
        :param folder: Name of the folder from which to fetch incidents
        :param is_public_folder: Public Folder flag
        :param request_timeout: Timeout (in seconds) for HTTP requests to Exchange Server
        :param mark_as_read: Whether to mark fetched incidents as read
        :param incident_filter: The type of time filter to use for incidents (modified or received time)
        :param azure_cloud: (O365 only) The Azure cloud environment for authentication to O365 services
        :param tenant_id: (O365 only) Tenant id used for O365 authentication
        :param self_deployed: (O365 only) Whether the Azure app is self-deployed or part of a managed service
        :param log_memory: Whether to enable memory usage logging for various commands
        :param app_name: The name of the app. (Used for logging purposes only)
        :param insecure: Trust any certificate (not secure)
        :param proxy: Whether to use a proxy for the connection
        """
        if auth_type and auth_type not in (OAUTH2, BASIC, NTLM, DIGEST):
            raise ValueError(f'Invalid auth_type: {auth_type}')

        if ews_server and not version:
            raise ValueError('Version must be provided if EWS Server is specified.')

        BaseProtocol.TIMEOUT = request_timeout  # type: ignore
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_type = access_type.lower()
        self.account_email = default_target_mailbox
        self.ews_server = ews_server
        self.max_fetch = max_fetch
        self.auth_type = auth_type
        self.version = version
        self.folder_name = folder
        self.is_public_folder = is_public_folder
        self.mark_as_read = mark_as_read
        self.incident_filter = incident_filter
        self.azure_cloud = azure_cloud
        self.tenant_id = tenant_id
        self.self_deployed = self_deployed
        self.log_memory = log_memory
        self.app_name = app_name
        self.insecure = insecure
        self.proxy = proxy

        self.auto_discover = not ews_server

        self.config, self.credentials, self.server_build = self._configure_auth()

    def _configure_auth(self) -> tuple[Optional[Configuration], BaseCredentials, Optional[Build]]:
        """
        Prepares the client protocol, credentials and configuration based on the authentication type.

        :return: Configuration and Credentials objects.
        """
        if self.auth_type == OAUTH2:
            return self._configure_oauth()

        return self._configure_onprem()

    def _configure_oauth(self) -> tuple[Configuration, CustomDomainOAuth2Credentials, Build]:
        """
        Prepares the client PROTOCOL, CREDENTIALS and CONFIGURATION

        :return: OAuth 2 Configuration and Credentials
        """
        if self.version != 'O365':
            raise ValueError('Error, only the O365 version is supported for OAuth2 authentication.')

        if not self.azure_cloud:
            raise ValueError('Error, failed to get Azure cloud object required for OAuth2 authentication.')

        BaseProtocol.HTTP_ADAPTER_CLS = InsecureProxyAdapter if self.insecure else ProxyAdapter

        self.ms_client = ms_client = MicrosoftClient(
            tenant_id=self.tenant_id,
            auth_id=self.client_id,
            enc_key=self.client_secret,
            app_name=self.app_name,
            base_url=self.ews_server,
            verify=not self.insecure,
            proxy=self.proxy,
            self_deployed=self.self_deployed,
            scope=f'{self.azure_cloud.endpoints.exchange_online}/.default',
            command_prefix='ews',
            azure_cloud=self.azure_cloud
        )

        access_token = ms_client.get_access_token()
        oauth2_token = OAuth2Token({'access_token': access_token})
        credentials = CustomDomainOAuth2Credentials(
            azure_cloud=self.azure_cloud,
            client_id=self.client_id,
            client_secret=self.client_secret,
            access_token=oauth2_token,
        )
        # need to add identity for protocol OAuth header
        credentials.identity = Identity(upn=self.account_email)
        config = Configuration(
            credentials=credentials,
            auth_type=OAUTH2,
            version=Version(EXCHANGE_O365),
            service_endpoint=f'{self.azure_cloud.endpoints.exchange_online}/EWS/Exchange.asmx',
        )
        return config, credentials, EXCHANGE_O365

    def _configure_onprem(self) -> tuple[Optional[Configuration], Credentials, Optional[Build]]:
        """
        Prepares the client protocol, credentials and configuration based on the authentication type.
        For auto_discovery, the configuration object will be created as needed from the discovered connection parameters.

        :return: Configuration and Credentials objects.
        """
        BaseProtocol.HTTP_ADAPTER_CLS = InsecureSSLAdapter if self.insecure else HTTPAdapter

        if self.auto_discover:
            # Discover the server params using the exchange auto discovery mechanism
            # The discovered config params will be cached in the integration context for subsequent runs
            credentials = Credentials(username=self.client_id, password=self.client_secret)
            self.ews_server, server_build = self.get_autodiscover_server_params(credentials)
            return None, credentials, server_build

        # Check params and set defaults where necessary
        if urlparse(self.ews_server.lower()).hostname == 'outlook.office365.com':  # Legacy O365 logic
            if not self.auth_type:
                self.auth_type = BASIC
            self.version = '2016'

        if not self.auth_type:
            self.auth_type = NTLM

        if not self.version:
            raise DemistoException('Exchange Server Version is required for on-premise Exchange Servers.')

        # Configure the on-prem Exchange Server connection
        credentials = Credentials(username=self.client_id, password=self.client_secret)
        config_args = {
            'credentials': credentials,
            'auth_type': self.auth_type,
            'version': get_on_prem_version(self.version)
        }
        if 'http' in self.ews_server.lower():
            config_args['service_endpoint'] = self.ews_server
        else:
            config_args['server'] = self.ews_server

        return (
            Configuration(**config_args, retry_policy=FaultTolerance(max_wait=60)),
            credentials,
            get_on_prem_build(self.version),
        )

    def get_autodiscover_server_params(self, credentials) -> tuple[str, Optional[Build]]:
        """
        Get the server parameters from the cached autodiscover results and update the integration context.
        If there are no cached results, attempt Account creation with autodiscover to get the parameters, and cache the results.

        :param credentials: Credentials object for authentication

        :return: ews_server, server_build: The discovered Exchange server URL and build version
        """
        context_dict = demisto.getIntegrationContext()
        if context_dict:
            ews_server = get_endpoint_from_context(context_dict)
            server_build = get_build_from_context(context_dict)
        else:
            try:
                account = Account(
                    primary_smtp_address=self.account_email, autodiscover=True,
                    access_type=self.access_type, credentials=credentials,
                )
                ews_server = account.protocol.service_endpoint
                server_build = account.protocol.version.build
                demisto.setIntegrationContext(cache_autodiscover_results(context_dict, account))
            except AutoDiscoverFailed:
                raise DemistoException('Auto discovery failed. Check credentials or configure manually')

        return ews_server, server_build

    def get_protocol(self) -> Protocol:
        """
        Get the EWS protocol with the configured settings.

        :return: The EWS protocol instance.
        """
        if self.auto_discover:
            return self.get_account_autodiscover(self.account_email).protocol

        return Protocol(config=self.config)

    def get_account(self, target_mailbox: Optional[str] = None, time_zone=None) -> Account:
        """
        Request an account from EWS

        :param: target_mailbox: Mailbox associated with the requested account

        :return: exchangelib Account
        """
        if not target_mailbox:
            target_mailbox = self.account_email

        if self.auto_discover:
            return self.get_account_autodiscover(target_mailbox, time_zone)

        return Account(
            primary_smtp_address=target_mailbox,
            autodiscover=False,
            config=self.config,
            access_type=self.access_type,
            default_timezone=time_zone,
        )

    def get_account_autodiscover(self, target_mailbox: str, time_zone=None) -> Account:
        """
        Request an account from EWS using the autodiscovery mechanism

        :param target_mailbox: Mailbox associated with the requested account
        :param time_zone: Timezone associated with the requested account

        :return: exchangelib Account
        """
        original_exc = None
        context_dict = demisto.getIntegrationContext()

        if context_dict:
            try:
                config_args = get_config_args_from_context(context_dict, self.credentials)
                account = Account(
                    primary_smtp_address=target_mailbox,
                    autodiscover=False,
                    config=Configuration(**config_args),
                    access_type=self.access_type,
                    default_timezone=time_zone
                )
                account.root.effective_rights.read  # noqa: B018 pylint: disable=E1101
                return account
            except Exception as e:
                # fixing flake8 correction where original_exc is assigned but unused
                original_exc = e

        try:
            account = Account(
                primary_smtp_address=self.account_email,
                autodiscover=True,
                credentials=self.credentials,
                access_type=self.access_type,
            )
        except AutoDiscoverFailed:
            raise DemistoException('Auto discovery failed. Check credentials or configure manually')

        new_context = cache_autodiscover_results(context_dict, account)
        if new_context == context_dict and original_exc:
            # Autodiscovery returned the same connection params as the cached ones we failed to use
            raise original_exc  # pylint: disable=E0702

        if target_mailbox == self.account_email:
            demisto.setIntegrationContext(new_context)

        return account

    def get_items_from_mailbox(self, account: Optional[Union[Account, str]], item_ids) -> list[Item]:
        """
        Request specific items from a mailbox associated with an account

        :param account: EWS account or target_mailbox associated with that account
        :param item_ids: item_ids of the requested items

        :return: list of exchangelib Items
        """
        # allow user to pass target_mailbox as account
        if not isinstance(account, Account):
            account = self.get_account(account) if isinstance(account, str) else self.get_account(self.account_email)

        if not isinstance(item_ids, list):
            item_ids = [item_ids]

        items = [Item(id=x) for x in item_ids]
        result = list(account.fetch(ids=items))
        result = [x for x in result if not (isinstance(x, ErrorItemNotFound | ErrorInvalidIdMalformed))]
        if len(result) != len(item_ids):
            result_ids = {item.id for item in result}
            missing_ids = set(item_ids) - result_ids
            raise Exception(f'One or more items were not found/malformed. Could not find the following IDs: {missing_ids}')
        return result

    def get_item_from_mailbox(self, account: Optional[Union[Account, str]], item_id) -> Item:
        """
        Request a single item from a mailbox associated with an account

        :param account: EWS account or target_mailbox associated with that account
        :param item_id: item_id of the requested item

        :return: exchangelib Item
        """
        result = self.get_items_from_mailbox(account, [item_id])
        return result[0]

    def get_attachments_for_item(self, item_id, account: Optional[Union[Account, str]], attachment_ids: list = []):
        """
        Request attachments for an item

        :param item_id: item_id of the item to retrieve attachments from
        :param account: EWS account or target_mailbox associated with that account
        :param (Optional) attachment_ids: attachment_ids to retrieve, empty list will get all available attachments

        :return: list of exchangelib Item.attachments
        """
        item = self.get_item_from_mailbox(account, item_id)
        if not item:
            raise DemistoException(f'Message item not found: {item_id}')

        attachments = []
        for attachment in item.attachments or []:
            if attachment is None:
                continue

            if not attachment_ids or attachment.attachment_id.id in attachment_ids:
                attachments.append(attachment)

        if attachment_ids and len(attachments) < len(attachment_ids):
            found_ids = {attachment.attachment_id.id for attachment in attachments}
            missing_ids = set(attachment_ids) - found_ids
            raise DemistoException(f'Some attachment ids were not found for the given message id: {missing_ids}')

        return attachments

    def is_default_folder(self, folder_path: str, is_public: Optional[bool] = None) -> bool:
        """
        Check whether the given folder_path is known to be public,
        determined either by the is_public argument, or in the case where folder_path is the
        configured instance folder name and the is_public instance variable is set.

        :param folder_path: folder path to check if is public
        :param is_public: (Optional) if provided, will return this value

        :return: Boolean
        """
        if is_public is not None:
            return is_public

        if folder_path == self.folder_name:
            return self.is_public_folder

        return False

    def get_folder_by_path(self, path: str, account: Optional[Account] = None, is_public: bool = False
                           ) -> BaseFolder:
        """
        Retrieve folder by path

        :param path: path of the folder
        :param account: account associated with the requested path
        :param is_public: is the requested folder public

        :return: exchangelib Folder
        """
        if account is None:
            account = self.get_account()
        # handle exchange folder id
        if len(path) == FOLDER_ID_LEN:
            folders_map = account.root._folders_map
            if path in folders_map:
                return account.root._folders_map[path]

        if is_public:
            folder = account.public_folders_root
        elif self.version == 'O365' and path == 'AllItems':
            # AllItems is only available on Office365, directly under root
            folder = account.root
        else:
            # Default, contains all of the standard folders (Inbox, Calendar, trash, etc.)
            folder = account.root.tois

        path = path.replace('/', '\\')
        path_parts = path.split('\\')
        for part in path_parts:
            try:
                demisto.debug(f'resolving {part=} {path_parts=}')
                folder = folder // part
            except Exception as e:
                demisto.debug(f'got error {e}')
                raise ValueError(f'No such folder {path_parts}')
        return folder

    def send_email(self, message: Message):
        """
        Send message using the EWS account associated with this client instance.

        :param message: Message to be sent
        """
        account = self.get_account()
        message.account = account
        message.send_and_save()

    def reply_email(self, inReplyTo: str, to: list[str], body: str, subject: str, bcc: list[str], cc: list[str],
                    htmlBody: Optional[str], attachments: list, from_mailbox: Optional[str] = None,
                    account: Optional[Account] = None) -> Message:
        """
        Send a reply email using the EWS account associated with this client or the provided account,
        based on the provided parameters.

        :param inReplyTo: ID of the email to reply to
        :param to: List of email addresses for the "To" field
        :param body: Body of the email
        :param subject: Subject of the email
        :param bcc: List of 'BCC' email addresses
        :param cc: List of 'CC' email addresses
        :param htmlBody: HTML body of the email (overrides body)
        :param attachments: List of attachments to include in the email
        :param from_mailbox: Email address of the sender (optional)
        :param account: Account for the mailbox containing the email to reply to (optional)

        :return: The sent message
        """
        if not account:
            account = self.get_account()
        item_to_reply_to = account.inbox.get(id=inReplyTo)  # pylint: disable=E1101
        if isinstance(item_to_reply_to, ErrorItemNotFound):
            raise Exception(item_to_reply_to)

        subject = subject or item_to_reply_to.subject
        htmlBody, htmlAttachments = handle_html(htmlBody) if htmlBody else (None, [])
        message_body = HTMLBody(htmlBody) if htmlBody else body
        reply = item_to_reply_to.create_reply(subject='Re: ' + subject, body=message_body, to_recipients=to,
                                              cc_recipients=cc, bcc_recipients=bcc, author=from_mailbox)
        reply = reply.save(account.drafts)
        m = account.inbox.get(id=reply.id)  # pylint: disable=E1101

        attachments += htmlAttachments
        for attachment in attachments:
            if not isinstance(attachment, FileAttachment):
                if not attachment.get('cid'):
                    attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'))
                else:
                    attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'),
                                                is_inline=True, content_id=attachment.get('cid'))
            m.attach(attachment)
        m.send()

        return m


def handle_html(html_body) -> tuple[str, List[Dict[str, Any]]]:
    """
    Extract all data-url content from within the html and return as separate attachments.
    Due to security implications, we support only images here
    We might not have Beautiful Soup so just do regex search

    :param html_body: HTML content string

    :return: clean_body, attachments: cleaned HTML body and a list of the extracted attachments.
    """
    attachments = []
    clean_body = ''
    last_index = 0
    for i, m in enumerate(
            re.finditer(r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"', html_body, re.I)):
        name = f'image{i}'
        cid = (f'{name}@{str(uuid.uuid4())[:8]}_{str(uuid.uuid4())[:8]}')
        attachment = {
            'data': base64.b64decode(m.group(3)),
            'name': name
        }
        attachment['cid'] = cid
        clean_body += html_body[last_index:m.start(1)] + 'cid:' + attachment['cid']
        last_index = m.end() - 1
        new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'),
                                        content_id=attachment.get('cid'), is_inline=True)
        attachments.append(new_attachment)

    clean_body += html_body[last_index:]
    return clean_body, attachments


def get_config_args_from_context(context: dict, credentials: BaseCredentials):
    """
    Create a configuration obj from the cached autodiscovery results in the provided integration context.

    :param context: the integration context dict
    :param credentials: the credentials

    :return: config: a configuration object for the previously discovered connection params
    """
    auth_type = context['auth_type']
    api_version = context['api_version']
    version = Version(get_build_from_context(context), api_version)
    service_endpoint = context['service_endpoint']

    config_args = {
        'credentials': credentials,
        'auth_type': auth_type,
        'version': version,
        'service_endpoint': service_endpoint
    }
    return config_args


def get_build_from_context(context: dict):
    """
    Create a Build object from the cached autodiscovery results in the provided integration context.

    :param context: the integration context dict

    :return: build: a Build object for the previously discovered connection params
    """
    build_params = context['build'].split('.')
    build_params = [int(i) for i in build_params]
    return Build(*build_params)


def get_endpoint_from_context(context_dict: dict):
    """
    Get the EWS Server endpoint from the cached autodiscovery results in the provided integration context.

    :param context: the integration context dict

    :return: endpoint: The endpoint from the previously discovered connection params
    """
    return context_dict['service_endpoint']


def cache_autodiscover_results(context: dict, account: Account):
    """
    Add the autodiscovery results to the integration context for later reuse.

    :param context: the integration context dict
    :param account: the discovered account object

    :return: the updated context
    """
    context['auth_type'] = account.protocol.auth_type
    context['service_endpoint'] = account.protocol.service_endpoint
    context['build'] = str(account.protocol.version.build)
    context['api_version'] = account.protocol.version.api_version

    return context


def get_on_prem_build(version: str):
    """
    Convert a version string to a Build object for supported on-prem Exchange Server versions.

    :param version: The version string (e.g. '2013', '2016', '2019')

    :return: A Build object representing the on-premises Exchange Server build
    """
    if version not in SUPPORTED_ON_PREM_BUILDS:
        supported_versions = '\\'.join(list(SUPPORTED_ON_PREM_BUILDS.keys()))
        raise ValueError(f'{version} is not a supported version. Choose one of: {supported_versions}.')

    return SUPPORTED_ON_PREM_BUILDS[version]


def get_on_prem_version(version: str):
    """
    Convert a version string to a Version object for supported on-prem Exchange Server versions.

    :param version: The version string (e.g. '2013', '2016', '2019')

    :return: A Version object representing the on-premises Exchange Server version
    """
    return Version(get_on_prem_build(version))

# Command functions and helpers


def is_empty_object(obj) -> bool:
    """
    Checks if the given object is empty.
    :param obj: The object to check.

    :return: True if the object is empty, False otherwise.
    """
    return (obj.__sizeof__() if isinstance(obj, map) else len(obj)) == 0


def filter_dict_null(d):
    """
    Filters out any none values from a dictionary.
    :param d: The dictionary to filter.

    :return: A new dictionary with all the none values removed.
    """
    if isinstance(d, dict):
        return {k: v for k, v in list(d.items()) if v is not None}
    return d


def switch_hr_headers(obj, hr_header_changes: dict):
    """
    Will swap keys according to hr_header_changes.
    hr_header_changes: a dict, keys are the old value, value is the new value
    """
    if not isinstance(obj, dict):
        return obj
    obj_copy = obj.copy()
    for old_header, new_header in hr_header_changes.items():
        if old_header in obj:
            obj_copy[new_header] = obj_copy.pop(old_header)
    return obj_copy


def get_entry_for_object(title: str, context_key: str, obj, headers: Optional[list] = None,
                         hr_header_changes: dict = {}) -> CommandResults:
    """
    Create an entry for a given object
    :param title: Title of the human readable
    :param context_key: Context key used for entry context
    :param obj: Object to create entry for
    :param headers: (Optional) headers used in the tableToMarkDown
    :param hr_header_changes: (Optional) a dict to map the header names used in the human readable output
    :return: Entry object to be used with demisto.results()
    """
    if is_empty_object(obj):
        return CommandResults(readable_output='There is no output results')
    obj = filter_dict_null(obj)
    hr_obj = switch_hr_headers(obj, hr_header_changes)
    if isinstance(obj, list):
        obj = [filter_dict_null(k) for k in obj]
        hr_obj = [switch_hr_headers(k, hr_header_changes) for k in obj]

    if headers and isinstance(obj, dict):
        headers = list(set(headers).intersection(set(obj.keys())))

    return CommandResults(
        outputs=obj,
        outputs_prefix=context_key,
        readable_output=tableToMarkdown(title, hr_obj, headers),
    )


def delete_attachments_for_message(client: EWSClient, item_id: str, target_mailbox: Optional[str] = None,
                                   attachment_ids=None) -> list[CommandResults]:
    """
    Deletes attachments for a given message
    :param client: EWS Client
    :param item_id: item id
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) attachment_ids: attachment ids to delete
    :return: entries that were deleted
    """
    attachment_ids = argToList(attachment_ids)
    attachments = client.get_attachments_for_item(item_id, target_mailbox, attachment_ids)
    deleted_file_attachments = []
    deleted_item_attachments = []
    for attachment in attachments:
        attachment_deleted_action = {
            ATTACHMENT_ID: attachment.attachment_id.id,
            ACTION: "deleted",
        }
        if isinstance(attachment, FileAttachment):
            deleted_file_attachments.append(attachment_deleted_action)
        else:
            deleted_item_attachments.append(attachment_deleted_action)

        attachment.detach()

    entries = []
    if len(deleted_file_attachments) > 0:
        entry = get_entry_for_object("Deleted file attachments",
                                     "EWS.Items" + CONTEXT_UPDATE_FILE_ATTACHMENT,
                                     deleted_file_attachments)
        entries.append(entry)

    if len(deleted_item_attachments) > 0:
        entry = get_entry_for_object("Deleted item attachments",
                                     "EWS.Items" + CONTEXT_UPDATE_ITEM_ATTACHMENT,
                                     deleted_item_attachments)
        entries.append(entry)

    return entries


def get_searchable_mailboxes(client: EWSClient) -> CommandResults:
    """
    Retrieve searchable mailboxes command
    :param client: EWS Client
    :return: Context entry containing searchable mailboxes
    """
    searchable_mailboxes = GetSearchableMailboxes(protocol=client.get_protocol()).call()
    return get_entry_for_object("Searchable mailboxes", 'EWS.Mailboxes',
                                searchable_mailboxes, ['displayName', 'mailbox'])


def move_item_between_mailboxes(client: EWSClient, item_id, destination_mailbox: str, destination_folder_path: str,
                                source_mailbox: Optional[str] = None, is_public: Optional[bool] = None) -> CommandResults:
    """
    Moves item between mailboxes
    :param client: EWS Client
    :param item_id: item id
    :param destination_mailbox: destination mailbox
    :param destination_folder_path: destination folder path
    :param (Optional) source_mailbox: source mailbox
    :param (Optional) is_public: is the destination folder public
    :return: result object
    """
    source_account = client.get_account(source_mailbox)
    destination_account = client.get_account(destination_mailbox)
    is_public = client.is_default_folder(destination_folder_path, is_public)
    destination_folder = client.get_folder_by_path(destination_folder_path, destination_account, is_public)

    item = client.get_item_from_mailbox(source_account, item_id)
    exported_items = source_account.export([item])
    destination_account.upload([(destination_folder, exported_items[0])])
    source_account.bulk_delete([item])

    move_result = {
        MOVED_TO_MAILBOX: destination_mailbox,
        MOVED_TO_FOLDER: destination_folder_path,
    }

    return CommandResults(
        outputs=move_result,
        outputs_prefix='EWS.Items',
        outputs_key_field='itemId',
        raw_response='Item was moved successfully.',
        readable_output=f'Item was moved successfully to mailbox: {destination_mailbox}, folder: {destination_folder_path}.'
    )


def move_item(client: EWSClient, item_id: str, target_folder_path: str, target_mailbox: Optional[str] = None,
              is_public: Optional[bool] = None) -> CommandResults:
    """
    Moves an item within the same mailbox
    :param client: EWS Client
    :param item_id: item id
    :param target_folder_path: target folder path
    :param (Optional) target_mailbox: mailbox containing the item (defaults to account email)
    :param (Optional) is_public: is the destination folder public (default - False)
    :return: result object
    """
    account = client.get_account(target_mailbox)
    is_public = client.is_default_folder(target_folder_path, is_public)
    target_folder = client.get_folder_by_path(target_folder_path, is_public=is_public)
    item = client.get_item_from_mailbox(account, item_id)
    if isinstance(item, ErrorInvalidIdMalformed):
        raise Exception('Item not found')

    item.move(target_folder)
    move_result = {
        NEW_ITEM_ID: item.id,
        ITEM_ID: item_id,
        MESSAGE_ID: item.message_id,
        ACTION: 'moved',
    }

    return get_entry_for_object('Moved items', CONTEXT_UPDATE_EWS_ITEM, move_result)


def delete_items(client: EWSClient, item_ids, delete_type: str, target_mailbox: Optional[str] = None) -> CommandResults:
    """
    Delete items in a mailbox
    :param client: EWS Client
    :param item_ids: items ids to delete
    :param delete_type: delete type soft/hard
    :param (Optional) target_mailbox: mailbox containing the items (defaults to account email)
    :return: result object
    """
    deleted_items = []
    item_ids = argToList(item_ids)
    items = client.get_items_from_mailbox(target_mailbox, item_ids)
    delete_type = delete_type.lower()

    for item in items:
        item_id = item.id
        if delete_type == 'trash':
            item.move_to_trash()
        elif delete_type == 'soft':
            item.soft_delete()
        elif delete_type == 'hard':
            item.delete()
        else:
            raise Exception(f'invalid delete type: {delete_type}. Use "trash" \\ "soft" \\ "hard"')

        deleted_items.append({
            ITEM_ID: item_id,
            MESSAGE_ID: item.message_id,
            ACTION: f'{delete_type}-deleted',
        }
        )

    return get_entry_for_object(f'Deleted items ({delete_type} delete type)', CONTEXT_UPDATE_EWS_ITEM, deleted_items)


def get_out_of_office_state(client: EWSClient, target_mailbox: Optional[str] = None) -> CommandResults:
    """
    Retrieve get out of office state of the targeted mailbox
    :param client: EWS Client
    :param (Optional) target_mailbox: target mailbox
    :return: result object
    """
    account = client.get_account(target_mailbox)
    oof = account.oof_settings
    oof_dict = {
        'state': oof.state,  # pylint: disable=E1101
        'externalAudience': getattr(oof, 'external_audience', None),
        'start': oof.start.ewsformat() if oof.start else None,  # pylint: disable=E1101
        'end': oof.end.ewsformat() if oof.end else None,  # pylint: disable=E1101
        'internalReply': getattr(oof, 'internal_replay', None),
        'externalReply': getattr(oof, 'external_replay', None),
        MAILBOX: account.primary_smtp_address,
    }

    return get_entry_for_object(f'Out of office state for {account.primary_smtp_address}',
                                f'Account.Email(val.Address == obj.{MAILBOX}).OutOfOffice',
                                oof_dict)


def recover_soft_delete_item(client: EWSClient, message_ids, target_folder_path: str = 'Inbox',
                             target_mailbox: Optional[str] = None, is_public: Optional[bool] = None) -> CommandResults:
    """
    Recovers soft deleted items
    :param client: EWS Client
    :param message_ids: Message ids to recover
    :param (Optional) target_folder_path: target folder path
    :param (Optional) target_mailbox: target mailbox
    :param (Optional) is_public: is the target folder public
    :return: result object
    """
    account = client.get_account(target_mailbox)
    is_public = client.is_default_folder(target_folder_path, is_public)
    target_folder = client.get_folder_by_path(target_folder_path, account, is_public)
    recovered_messages = []
    message_ids = argToList(message_ids)

    items_to_recover = account.recoverable_items_deletions.filter(message_id__in=message_ids).all()  # pylint: disable=E1101

    recovered_items = set()
    for item in items_to_recover:
        recovered_items.add(item)

    if len(recovered_items) != len(message_ids):
        missing_items = set(message_ids).difference(recovered_items)
        raise Exception(f'Some message ids are missing in recoverable items directory: {missing_items}')

    for item in recovered_items:
        item.move(target_folder)
        recovered_messages.append({ITEM_ID: item.id, MESSAGE_ID: item.message_id, ACTION: 'recovered'})

    return get_entry_for_object('Recovered messages', CONTEXT_UPDATE_EWS_ITEM, recovered_messages)


def create_folder(client: EWSClient, new_folder_name: str, folder_path: str,
                  target_mailbox: Optional[str] = None) -> str:
    """
    Creates a folder in the target mailbox or the client mailbox
    :param client: EWS Client
    :param new_folder_name: new folder name
    :param folder_path: path of the new folder
    :param (Optional) target_mailbox: target mailbox
    :return: Result message
    """
    account = client.get_account(target_mailbox)
    full_path = os.path.join(folder_path, new_folder_name)
    try:
        demisto.debug('Checking if folder exists')
        if client.get_folder_by_path(full_path, account):
            return f'Folder {full_path} already exists'
    except Exception:
        pass
    demisto.debug('Folder doesnt already exist. Getting path to add folder')
    parent_folder = client.get_folder_by_path(folder_path, account)

    demisto.debug('Saving folder')
    f = Folder(parent=parent_folder, name=new_folder_name)
    f.save()
    demisto.debug('Verifying folder was saved')
    client.get_folder_by_path(full_path, account)
    return f'Folder {full_path} created successfully'


def mark_item_as_junk(client: EWSClient, item_id, move_items: str, target_mailbox: Optional[str] = None) -> CommandResults:
    """
    Marks item as junk in the target mailbox or client mailbox
    :param client: EWS Client
    :param item_id: item ids to mark as junk
    :param move_items: 'yes' or 'no' - to move or not to move to the junk folder
    :param (Optional) target_mailbox: target mailbox the item is in
    :return: Results object
    """
    account = client.get_account(target_mailbox)
    move_to_junk: bool = (move_items.lower() == 'yes')
    ews_result = MarkAsJunk(account=account).call(item_id=item_id, move_item=move_to_junk)
    mark_as_junk_result = {
        ITEM_ID: item_id,
    }
    if ews_result == 'Success':
        mark_as_junk_result[ACTION] = 'marked-as-junk'
    else:
        raise Exception(f'Failed mark-item-as-junk with error: {ews_result}')

    return get_entry_for_object('Mark item as junk', CONTEXT_UPDATE_EWS_ITEM, mark_as_junk_result)


def folder_to_context_entry(f) -> dict:
    """
    Create a context entry from a folder response
    :param f: folder response
    :return: dict context entry
    """
    try:
        f_entry = {
            'name': f.name,
            'totalCount': f.total_count,
            'id': f.id,
            'childrenFolderCount': f.child_folder_count,
            'changeKey': f.changekey,
        }

        if 'unread_count' in [x.name for x in Folder.FIELDS]:
            f_entry['unreadCount'] = f.unread_count
        return f_entry

    except AttributeError:
        if isinstance(f, dict):
            return {
                'name': f.get('name'),
                'totalCount': f.get('total_count'),
                'id': f.get('id'),
                'childrenFolderCount': f.get('child_folder_count'),
                'changeKey': f.get('changekey'),
                'unreadCount': f.get('unread_count'),
            }

    return {}


def get_folder(client: EWSClient, folder_path: str, target_mailbox:
               Optional[str] = None, is_public: Optional[bool] = None) -> CommandResults:
    """
    Retrieve a folder from the target mailbox or client mailbox
    :param client: EWS Client
    :param folder_path: folder path to retrieve
    :param (Optional) target_mailbox: target mailbox to get the folder from
    :param (Optional) is_public: is the folder public
    :return: Results object
    """
    account = client.get_account(target_mailbox)
    is_public = client.is_default_folder(folder_path, is_public)
    folder = folder_to_context_entry(
        client.get_folder_by_path(folder_path, account=account, is_public=is_public)
    )

    return get_entry_for_object(f'Folder {folder_path}', CONTEXT_UPDATE_FOLDER, folder)


def get_expanded_group(client: EWSClient, email_address, recursive_expansion: bool = False) -> CommandResults:
    """
    Retrieve expanded group command
    :param client: EWS Client
    :param email_address: Email address of the group to expand
    :param (Optional) recursive_expansion: Whether to enable recursive expansion. Default is 'False'.
    :return: Results object containing expanded groups
    """
    group_members = ExpandGroup(protocol=client.get_protocol()).call(email_address, recursive_expansion)
    group_details = {
        'name': email_address,
        'members': group_members
    }
    entry_for_object = get_entry_for_object('Expanded group', 'EWS.ExpandGroup', group_details)
    entry_for_object.readable_output = tableToMarkdown('Group Members', group_members)
    return entry_for_object


def mark_item_as_read(client: EWSClient, item_ids, operation: str = 'read',
                      target_mailbox: Optional[str] = None) -> CommandResults:
    """
    Marks item as read
    :param client: EWS Client
    :param item_ids: items ids to mark as read
    :param (Optional) operation: operation to execute
    :param (Optional) target_mailbox: target mailbox
    :return: results object
    """
    marked_items = []
    item_ids = argToList(item_ids)
    items = client.get_items_from_mailbox(target_mailbox, item_ids)
    items = [x for x in items if isinstance(x, Message)]

    for item in items:
        item.is_read = (operation == 'read')
        item.save()

        marked_items.append({
            ITEM_ID: item.id,
            MESSAGE_ID: item.message_id,
            ACTION: f'marked-as-{operation}',
        })

    return get_entry_for_object(f'Marked items ({operation} marked operation)', CONTEXT_UPDATE_EWS_ITEM, marked_items)
