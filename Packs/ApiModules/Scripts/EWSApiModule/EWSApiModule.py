from enum import Enum
import uuid

from CommonServerPython import *  # noqa: F401

from MicrosoftApiModule import *
from exchangelib import (
    Account,
    FileAttachment,
    Folder,
    HTMLBody
)
from exchangelib.errors import (
    ErrorInvalidIdMalformed,
    ErrorItemNotFound,
)
from exchangelib.items import Item, Message
from exchangelib.protocol import BaseProtocol

""" Constants """
INTEGRATION_NAME = get_integration_name()
FOLDER_ID_LEN = 120


class IncidentFilter(str, Enum):
    MODIFIED_FILTER = 'modified-time'
    RECEIVED_FILTER = 'received-time'


class EWSClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        access_type: str,
        default_target_mailbox: str,
        max_fetch: int,
        folder: str = 'Inbox',
        is_public_folder: bool = False,
        request_timeout: str = '120',
        mark_as_read: bool = False,
        legacy_name: bool = False,
        incident_filter: IncidentFilter = IncidentFilter.RECEIVED_FILTER,
        log_memory: bool = False,
        app_name: str = 'EWS',
        insecure: bool = True,
        proxy: bool = False,
    ):
        """
        Client used to communicate with EWS

        :param client_id: Application client ID
        :param client_secret: Application client secret
        :param access_type: Access type for authentication
        :param default_target_mailbox: Email address from which to fetch incidents
        :param max_fetch: Max incidents per fetch
        :param folder: Name of the folder from which to fetch incidents
        :param is_public_folder: Public Folder flag
        :param request_timeout: Timeout (in seconds) for HTTP requests to Exchange Server
        :param mark_as_read: Whether to mark fetched incidents as read
        :param legacy_name: Whether to use the legacy naming convention for attachments
        :param incident_filter: The type of time filter to use for incidents (modified or received time)
        :param log_memory: Whether to log memory usage
        :param app_name: The name of the app (e.g. EWSv2 or EWSO365)
        :param insecure: Trust any certificate (not secure)
        :param proxy: Whether to use a proxy for the connection
        """
        BaseProtocol.TIMEOUT = int(request_timeout)  # type: ignore
        self.folder_name = folder
        self.is_public_folder = is_public_folder
        self.access_type = (access_type[0] if isinstance(access_type, list) else access_type).lower()
        self.max_fetch = max_fetch
        self.client_id = client_id
        self.client_secret = client_secret
        self.account_email = default_target_mailbox
        self.config = None
        self.mark_as_read = mark_as_read
        self.legacy_name = legacy_name
        self.incident_filter = incident_filter
        self.log_memory = log_memory
        self.app_name = app_name
        self.insecure = insecure
        self.proxy = proxy

    def get_protocol(self):
        """
        Get the EWS protocol with the configured settings.
        
        :return: The EWS protocol instance.
        """
        return BaseProtocol(self.config)

    def get_account(self, target_mailbox: Optional[str]=None, time_zone=None) -> Account:
        """
        Request an account from EWS
        
        :param: target_mailbox: Mailbox associated with the requested account

        :return: exchangelib Account
        """
        if not target_mailbox:
            target_mailbox = self.account_email

        return Account(
            primary_smtp_address=target_mailbox,
            autodiscover=False,
            config=self.config,
            access_type=self.access_type,
            default_timezone=time_zone,
        )

    def get_items_from_mailbox(self, account, item_ids):
        """
        Request specific items from a mailbox associated with an account

        :param account: EWS account or target_mailbox associated with that account
        :param item_ids: item_ids of the requested items

        :return: list of exchangelib Items
        """
        # allow user to pass target_mailbox as account
        if not isinstance(account, Account):
            account = self.get_account(account) if isinstance(account, str) else self.get_account(self.account_email)
        if type(item_ids) is not list:
            item_ids = [item_ids]
        items = [Item(id=x) for x in item_ids]
        result = list(account.fetch(ids=items))
        result = [x for x in result if not (isinstance(x, ErrorItemNotFound | ErrorInvalidIdMalformed))]
        if len(result) != len(item_ids):
            raise Exception("One or more items were not found/malformed. Check the input item ids")
        return result

    def get_item_from_mailbox(self, account, item_id):
        """
        Request a single item from a mailbox associated with an account
        :param account: EWS account or target_mailbox associated with that account
        :param item_id: item_id of the requested item
        :return: exchangelib Item
        """
        result = self.get_items_from_mailbox(account, [item_id])
        if len(result) == 0:
            raise Exception(f"ItemId {str(item_id)} not found")
        return result[0]

    def get_attachments_for_item(self, item_id, account, attachment_ids=None):
        """
        Request attachments for an item
        :param item_id: item_id of the item to retrieve attachments from
        :param account: EWS account or target_mailbox associated with that account
        :param (Optional) attachment_ids: attachment_ids: attachment_ids to retrieve
        :return: list of exchangelib Item.attachments
        """
        item = self.get_item_from_mailbox(account, item_id)
        attachments = []
        attachment_ids = argToList(attachment_ids)
        if item:
            if item.attachments:
                for attachment in item.attachments:
                    if (
                        attachment_ids
                        and attachment.attachment_id.id not in attachment_ids
                    ):
                        continue
                    attachments.append(attachment)

        else:
            raise Exception("Message item not found: " + item_id)

        if attachment_ids and len(attachments) < len(attachment_ids):
            raise Exception(
                "Some attachment id did not found for message:" + str(attachment_ids)
            )

        return attachments

    def is_default_folder(self, folder_path, is_public=None):
        """
        Is the given folder_path public
        :param folder_path: folder path to check if is public
        :param is_public: (Optional) if provided, will return this value
        :return: Boolean
        """
        if is_public is not None:
            return is_public

        if folder_path == self.folder_name:
            return self.is_public_folder

        return False

    def get_folder_by_path(self, path: Optional[str] = None, account: Optional[Account] = None, is_public: bool = False
                           ) -> Folder:
        """
        Retrieve folder by path
        :param path: path of the folder
        :param account: account associated with the requested path
        :param is_public: is the requested folder public
        :return: exchangelib Folder
        """
        if path is None:
            path = self.folder_name
        if account is None:
            account = self.get_account()
        # handle exchange folder id
        if len(path) == FOLDER_ID_LEN:
            folders_map = account.root._folders_map  # type: ignore
            if path in folders_map:
                return account.root._folders_map[path]  # type: ignore

        root = account.public_folders_root if is_public else account.root
        folder = root if path == 'AllItems' else root.tois  # type: ignore
        path = path.replace("/", "\\")
        path_parts = path.split("\\")
        for part in path_parts:
            try:
                demisto.debug(f'resolving {part=} {path_parts=}')
                folder = folder // part  # type: ignore
            except Exception as e:
                demisto.debug(f'got error {e}')
                raise ValueError(f'No such folder {path_parts}')
        return folder  # type: ignore

    def send_email(self, message: Message):
        account = self.get_account()
        message.account = account
        message.send_and_save()

    def reply_mail(self, inReplyTo, to, body, subject, bcc, cc, htmlBody, attachments):
        account = self.get_account()
        item_to_reply_to = account.inbox.get(id=inReplyTo)  # type: ignore
        if isinstance(item_to_reply_to, ErrorItemNotFound):
            raise Exception(item_to_reply_to)

        subject = subject or item_to_reply_to.subject
        htmlBody, htmlAttachments = handle_html(htmlBody) if htmlBody else (None, [])
        message_body = HTMLBody(htmlBody) if htmlBody else body
        reply = item_to_reply_to.create_reply(subject='Re: ' + subject, body=message_body, to_recipients=to,
                                              cc_recipients=cc,
                                              bcc_recipients=bcc)
        reply = reply.save(account.drafts)
        m = account.inbox.get(id=reply.id)  # type: ignore

        attachments += htmlAttachments
        for attachment in attachments:
            if not attachment.get('cid'):
                new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'))
            else:
                new_attachment = FileAttachment(name=attachment.get('name'), content=attachment.get('data'),
                                                is_inline=True, content_id=attachment.get('cid'))
            m.attach(new_attachment)
        m.send()

        return m
    
    
def handle_html(html_body) -> tuple[str, List[Dict[str, Any]]]:
    """
    Extract all data-url content from within the html and return as separate attachments.
    Due to security implications, we support only images here
    We might not have Beautiful Soup so just do regex search
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
        attachments.append(attachment)
        clean_body += html_body[last_index:m.start(1)] + 'cid:' + attachment['cid']
        last_index = m.end() - 1

    clean_body += html_body[last_index:]
    return clean_body, attachments
