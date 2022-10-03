
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Union, Optional

''' IMPORTS '''
import base64
from bs4 import BeautifulSoup
import binascii
import urllib3
from urllib.parse import quote

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''

CONTEXT_FOLDER_PATH = 'MSGraphMail.Folders(val.ID && val.ID === obj.ID)'
CONTEXT_COPIED_EMAIL = 'MSGraphMail.MovedEmails(val.ID && val.ID === obj.ID)'
CONTEXT_DRAFT_PATH = 'MicrosoftGraph.Draft(val.ID && val.ID == obj.ID)'
CONTEXT_SENT_EMAIL_PATH = 'MicrosoftGraph.Email'
API_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

EMAIL_DATA_MAPPING = {
    'id': 'ID',
    'createdDateTime': 'CreatedTime',
    'lastModifiedDateTime': 'ModifiedTime',
    'receivedDateTime': 'ReceivedTime',
    'sentDateTime': 'SentTime',
    'subject': 'Subject',
    'importance': 'Importance',
    'conversationId': 'ConversationID',
    'isRead': 'IsRead',
    'isDraft': 'IsDraft',
    'internetMessageId': 'MessageID'
}

FOLDER_MAPPING = {
    'id': 'ID',
    'displayName': 'DisplayName',
    'parentFolderId': 'ParentFolderID',
    'childFolderCount': 'ChildFolderCount',
    'unreadItemCount': 'UnreadItemCount',
    'totalItemCount': 'TotalItemCount'
}

# Well known folders shortcut in MS Graph API
# For more information: https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0
WELL_KNOWN_FOLDERS = {
    'archive': 'archive',
    'conversation history': 'conversationhistory',
    'deleted items': 'deleteditems',
    'drafts': 'drafts',
    'inbox': 'inbox',
    'junk email': 'junkemail',
    'outbox': 'outbox',
    'sent items': 'sentitems',
}

''' CLIENT '''


class MsGraphClient:
    ITEM_ATTACHMENT = '#microsoft.graph.itemAttachment'
    FILE_ATTACHMENT = '#microsoft.graph.fileAttachment'
    # maximum attachment size to be sent through the api, files larger must be uploaded via upload session
    MAX_ATTACHMENT_SIZE = 3145728  # 3mb = 3145728 bytes

    def __init__(self, self_deployed, tenant_id, auth_and_token_url, enc_key,
                 app_name, base_url, use_ssl, proxy, ok_codes, mailbox_to_fetch, folder_to_fetch, first_fetch_interval,
                 emails_fetch_limit, timeout=10, endpoint='com', certificate_thumbprint=None, private_key=None,
                 display_full_email_body=False, look_back=0):

        self.ms_client = MicrosoftClient(self_deployed=self_deployed, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                         enc_key=enc_key, app_name=app_name, base_url=base_url, verify=use_ssl,
                                         proxy=proxy, ok_codes=ok_codes, timeout=timeout, endpoint=endpoint,
                                         certificate_thumbprint=certificate_thumbprint, private_key=private_key,
                                         retry_on_rate_limit=True)

        self._mailbox_to_fetch = mailbox_to_fetch
        self._folder_to_fetch = folder_to_fetch
        self._first_fetch_interval = first_fetch_interval
        self._emails_fetch_limit = emails_fetch_limit
        # whether to display the full email body for the fetch-incidents
        self.display_full_email_body = display_full_email_body
        self.look_back = look_back

    def pages_puller(self, response: dict, page_count: int) -> list:
        """ Gets first response from API and returns all pages

        Args:
            response (dict):
            page_count (int):

        Returns:
            list: list of all pages
        """
        responses = [response]
        for i in range(page_count - 1):
            next_link = response.get('@odata.nextLink')
            if next_link:
                response = self.ms_client.http_request('GET', full_url=next_link, url_suffix=None)
                responses.append(response)
            else:
                return responses
        return responses

    def list_mails(self, user_id: str, folder_id: str = '', search: str = None, odata: str = None) -> Union[dict, list]:
        """Returning all mails from given user

        Args:
            user_id (str):
            folder_id (str):
            search (str):
            odata (str):

        Returns:
            dict or list:
        """
        no_folder = f'/users/{user_id}/messages'
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages'
        pages_to_pull = demisto.args().get('pages_to_pull', 1)
        page_size = demisto.args().get('page_size', 20)
        odata = f'{odata}&$top={page_size}' if odata else f'$top={page_size}'

        if search:
            # Data is being handled as a JSON so in cases the search phrase contains double quote ",
            # we should escape it.
            search = search.replace('"', '\\"')
            odata = f'{odata}&$search="{quote(search)}"'
        suffix = with_folder if folder_id else no_folder
        if odata:
            suffix += f'?{odata}'
        demisto.debug(f"URL suffix is {suffix}")
        response = self.ms_client.http_request('GET', suffix)
        return self.pages_puller(response, assert_pages(pages_to_pull))

    def delete_mail(self, user_id: str, message_id: str, folder_id: str = None) -> bool:
        """

        Args:
            user_id (str):
            message_id (str):
            folder_id (str):

        Returns:
            bool
        """
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages/{message_id}'  # type: ignore
        no_folder = f'/users/{user_id}/messages/{message_id}'
        suffix = with_folder if folder_id else no_folder
        self.ms_client.http_request('DELETE', suffix, resp_type="")
        return True

    def get_attachment(self, message_id: str, user_id: str, attachment_id: str, folder_id: str = None) -> dict:
        """

        Args:
            message_id (str):
            user_id (str_:
            attachment_id (str):
            folder_id (str):

        Returns:
            dict:
        """
        no_folder = f'/users/{user_id}/messages/{message_id}/attachments/{attachment_id}' \
                    f'/?$expand=microsoft.graph.itemattachment/item'
        with_folder = (f'/users/{user_id}/{build_folders_path(folder_id)}/'  # type: ignore
                       f'messages/{message_id}/attachments/{attachment_id}/'
                       f'?$expand=microsoft.graph.itemattachment/item')
        suffix = with_folder if folder_id else no_folder
        response = self.ms_client.http_request('GET', suffix)
        return response

    def get_message(self, user_id: str, message_id: str, folder_id: str = '', odata: str = '') -> dict:
        """

        Args:
            user_id (str): User ID to pull message from
            message_id (str): Message ID to pull
            folder_id: (str) Folder ID to pull from
            odata (str): OData query

        Returns
            dict: request json
        """
        no_folder = f'/users/{user_id}/messages/{message_id}/'
        with_folder = (f'/users/{user_id}/{build_folders_path(folder_id)}'  # type: ignore
                       f'/messages/{message_id}/')

        suffix = with_folder if folder_id else no_folder
        if odata:
            suffix += f'?{odata}'
        response = self.ms_client.http_request('GET', suffix)

        # Add user ID
        response['userId'] = user_id
        return response

    def list_attachments(self, user_id: str, message_id: str, folder_id: str) -> dict:
        """Listing all the attachments

        Args:
            user_id (str):
            message_id (str):
            folder_id (str):

        Returns:
            dict:
        """
        no_folder = f'/users/{user_id}/messages/{message_id}/attachments/'
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages/{message_id}/attachments/'
        suffix = with_folder if folder_id else no_folder
        return self.ms_client.http_request('GET', suffix)

    def list_folders(self, user_id: str, limit: str = '20') -> dict:
        """List folder under root folder (Top of information store)

        Args:
            user_id (str): User id or mailbox address
            limit (str): Limit number of returned folder collection

        Returns:
            dict: Collection of folders under root folder
        """
        suffix = f'/users/{user_id}/mailFolders?$top={limit}'
        return self.ms_client.http_request('GET', suffix)

    def list_child_folders(self, user_id: str, parent_folder_id: str, limit: str = '20') -> list:
        """List child folder under specified folder.

        Args:
            user_id (str): User id or mailbox address
            parent_folder_id (str): Parent folder id
            limit (str): Limit number of returned folder collection

        Returns:
            list: Collection of folders under specified folder
        """
        # for additional info regarding OData query https://docs.microsoft.com/en-us/graph/query-parameters
        suffix = f'/users/{user_id}/mailFolders/{parent_folder_id}/childFolders?$top={limit}'
        return self.ms_client.http_request('GET', suffix)

    def create_folder(self, user_id: str, new_folder_name: str, parent_folder_id: str = None) -> dict:
        """Create folder under specified folder with given display name

        Args:
            user_id (str): User id or mailbox address
            new_folder_name (str): Created folder display name
            parent_folder_id (str): Parent folder id under where created new folder

        Returns:
            dict: Created folder data
        """

        suffix = f'/users/{user_id}/mailFolders'
        if parent_folder_id:
            suffix += f'/{parent_folder_id}/childFolders'

        json_data = {'displayName': new_folder_name}
        return self.ms_client.http_request('POST', suffix, json_data=json_data)

    def update_folder(self, user_id: str, folder_id: str, new_display_name: str) -> dict:
        """Update folder under specified folder with new display name

        Args:
            user_id (str): User id or mailbox address
            folder_id (str): Folder id to update
            new_display_name (str): New display name of updated folder

        Returns:
            dict: Updated folder data
        """

        suffix = f'/users/{user_id}/mailFolders/{folder_id}'
        json_data = {'displayName': new_display_name}
        return self.ms_client.http_request('PATCH', suffix, json_data=json_data)

    def delete_folder(self, user_id: str, folder_id: str):
        """Deletes folder under specified folder

        Args:
            user_id (str): User id or mailbox address
            folder_id (str): Folder id to delete
        """

        suffix = f'/users/{user_id}/mailFolders/{folder_id}'
        return self.ms_client.http_request('DELETE', suffix, resp_type="")

    def move_email(self, user_id: str, message_id: str, destination_folder_id: str) -> dict:
        """Moves email to destination folder

        Args:
            user_id (str): User id or mailbox address
            message_id (str): The message id to move
            destination_folder_id (str): Destination folder id

        Returns:
            dict: Moved email data
        """

        suffix = f'/users/{user_id}/messages/{message_id}/move'
        json_data = {'destinationId': destination_folder_id}
        return self.ms_client.http_request('POST', suffix, json_data=json_data)

    def get_email_as_eml(self, user_id: str, message_id: str) -> str:
        """Returns MIME content of specified message

        Args:
            user_id (str): User id or mailbox address
            message_id (str): The message id of the email

        Returns:
            str: MIME content of the email
        """

        suffix = f'/users/{user_id}/messages/{message_id}/$value'
        return self.ms_client.http_request('GET', suffix, resp_type='text')

    @staticmethod
    def _build_recipient_input(recipients):
        """
        Builds legal recipients list.

        :type recipients: ``list``
        :param recipients: List of recipients

        :return: List of email addresses recipients
        :rtype: ``list``
        """
        return [{'emailAddress': {'address': r}} for r in recipients] if recipients else []

    @staticmethod
    def _build_body_input(body, body_type):
        """
        Builds message body input.

        :type body: ``str``
        :param body: The body of the message

        :type body_type: The body type of the message, html or text.
        :param body_type:

        :return: The message body
        :rtype ``dict``
        """
        return {
            "content": body,
            "contentType": body_type
        }

    @staticmethod
    def _build_flag_input(flag):
        """
        Builds flag status of the message.

        :type flag: ``str``
        :param flag: The flag of the message

        :return: The flag status of the message
        :rtype ``dict``
        """
        return {'flagStatus': flag}

    @classmethod
    def _build_attachments_input(cls, ids, attach_names=None, is_inline=False):
        """
        Builds valid attachment input of the message. Is used for both in-line and regular attachments.

        :type ids: ``list``
        :param ids: List of uploaded to War Room files ids

        :type attach_names: ``list``
        :param attach_names: List of attachment name, not required.

        :type is_inline: ``bool``
        :param is_inline: Indicates whether the attachment is inline or not

        :return: List of valid attachments of message
        :rtype: ``list``
        """
        provided_names = bool(attach_names)

        if provided_names and len(ids) != len(attach_names):
            raise Exception("Invalid input, attach_ids and attach_names lists should be the same length.")

        file_attachments_result = []
        # in case that no attach names where provided, ids are zipped together and the attach_name value is ignored
        attachments = zip(ids, attach_names) if provided_names else zip(ids, ids)

        for attach_id, attach_name in attachments:
            file_data, file_size, uploaded_file_name = read_file(attach_id)
            file_name = attach_name if provided_names or not uploaded_file_name else uploaded_file_name
            if file_size < cls.MAX_ATTACHMENT_SIZE:  # if file is less than 3MB
                file_attachments_result.append(
                    {
                        '@odata.type': cls.FILE_ATTACHMENT,
                        'contentBytes': base64.b64encode(file_data).decode('utf-8'),
                        'isInline': is_inline,
                        'name': file_name,
                        'size': file_size
                    }
                )
            else:
                file_attachments_result.append(
                    {
                        'size': file_size,
                        'data': file_data,
                        'name': file_name,
                        'isInline': is_inline,
                        'requires_upload': True
                    }
                )

        return file_attachments_result

    @staticmethod
    def _build_file_attachments_input(attach_ids, attach_names, attach_cids, manual_attachments):
        """
        Builds both inline and regular attachments.

        :type attach_ids: ``list``
        :param attach_ids: List of uploaded to War Room regular attachments to send

        :type attach_names: ``list``
        :param attach_names: List of regular attachments names to send

        :type attach_cids: ``list``
        :param attach_cids: List of uploaded to War Room inline attachments to send

        :type manual_attachments: ``list``
        :param manual_attachments: List of manual attachments reports to send

        :return: List of both inline and regular attachments of the message
        :rtype: ``list``
        """
        regular_attachments = MsGraphClient._build_attachments_input(ids=attach_ids, attach_names=attach_names)
        inline_attachments = MsGraphClient._build_attachments_input(ids=attach_cids, is_inline=True)
        # collecting manual attachments info
        manual_att_ids = [os.path.basename(att['RealFileName']) for att in manual_attachments if 'RealFileName' in att]
        manual_att_names = [att['FileName'] for att in manual_attachments if 'FileName' in att]
        manual_report_attachments = MsGraphClient._build_attachments_input(ids=manual_att_ids,
                                                                           attach_names=manual_att_names)

        return regular_attachments + inline_attachments + manual_report_attachments

    @staticmethod
    def _get_recipient_address(email_address):
        """
        Receives dict of form  "emailAddress":{"name":"_", "address":"_"} and return the address

        :type email_address: ``dict``
        :param email_address: Recipient address

        :return: The address of recipient
        :rtype: ``str``
        """
        return email_address.get('emailAddress', {}).get('address', '')

    @staticmethod
    def _build_headers_input(internet_message_headers):
        """
        Builds valid headers input.

        :type internet_message_headers: ``list``
        :param internet_message_headers: List of headers to build.

        :return: List of transformed headers
        :rtype: ``list``
        """
        return [{'name': kv[0], 'value': kv[1]} for kv in (h.split(':') for h in internet_message_headers)]

    @staticmethod
    def build_message(to_recipients, cc_recipients, bcc_recipients, subject, body, body_type, flag, importance,
                      internet_message_headers, attach_ids, attach_names, attach_cids, manual_attachments, reply_to):
        """
        Builds valid message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        message = {
            'toRecipients': MsGraphClient._build_recipient_input(to_recipients),
            'ccRecipients': MsGraphClient._build_recipient_input(cc_recipients),
            'bccRecipients': MsGraphClient._build_recipient_input(bcc_recipients),
            'replyTo': MsGraphClient._build_recipient_input(reply_to),
            'subject': subject,
            'body': MsGraphClient._build_body_input(body=body, body_type=body_type),
            'bodyPreview': body[:255],
            'importance': importance,
            'flag': MsGraphClient._build_flag_input(flag),
            'attachments': MsGraphClient._build_file_attachments_input(attach_ids, attach_names, attach_cids,
                                                                       manual_attachments)
        }

        if internet_message_headers:
            message['internetMessageHeaders'] = MsGraphClient._build_headers_input(internet_message_headers)

        return message

    @staticmethod
    def build_message_to_reply(to_recipients, cc_recipients, bcc_recipients, subject, email_body, attach_ids,
                               attach_names, attach_cids, reply_to):
        """
        Builds a valid reply message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        return {
            'toRecipients': MsGraphClient._build_recipient_input(to_recipients),
            'ccRecipients': MsGraphClient._build_recipient_input(cc_recipients),
            'bccRecipients': MsGraphClient._build_recipient_input(bcc_recipients),
            'replyTo': MsGraphClient._build_recipient_input(reply_to),
            'subject': subject,
            'bodyPreview': email_body[:255],
            'attachments': MsGraphClient._build_file_attachments_input(attach_ids, attach_names, attach_cids, [])
        }

    @staticmethod
    def parse_item_as_dict(email):
        """
        Parses basic data of email.

        Additional info https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0

        :type email: ``dict``
        :param email: Email to parse

        :return: Parsed email
        :rtype: ``dict``
        """
        parsed_email = {EMAIL_DATA_MAPPING[k]: v for (k, v) in email.items() if k in EMAIL_DATA_MAPPING}
        parsed_email['Headers'] = email.get('internetMessageHeaders', [])

        email_body = email.get('body', {}) or email.get('uniqueBody', {})
        parsed_email['Body'] = email_body.get('content', '')
        parsed_email['BodyType'] = email_body.get('contentType', '')

        parsed_email['Sender'] = MsGraphClient._get_recipient_address(email.get('sender', {}))
        parsed_email['From'] = MsGraphClient._get_recipient_address(email.get('from', {}))
        parsed_email['To'] = list(map(MsGraphClient._get_recipient_address, email.get('toRecipients', [])))
        parsed_email['Cc'] = list(map(MsGraphClient._get_recipient_address, email.get('ccRecipients', [])))
        parsed_email['Bcc'] = list(map(MsGraphClient._get_recipient_address, email.get('bccRecipients', [])))

        return parsed_email

    @staticmethod
    def build_reply(to_recipients, comment, attach_ids, attach_names, attach_cids):
        """
        Builds the reply message that includes recipients to reply and reply message.

        :type to_recipients: ``list``
        :param to_recipients: The recipients list to reply

        :type comment: ``str``
        :param comment: The message to reply.

        :type attach_ids: ``list``
        :param attach_ids: List of uploaded to War Room regular attachments to send

        :type attach_names: ``list``
        :param attach_names: List of regular attachments names to send

        :type attach_cids: ``list``
        :param attach_cids: List of uploaded to War Room inline attachments to send

        :return: Returns legal reply message.
        :rtype: ``dict``
        """
        return {
            'message': {
                'toRecipients': MsGraphClient._build_recipient_input(to_recipients),
                'attachments': MsGraphClient._build_file_attachments_input(attach_ids, attach_names, attach_cids, [])
            },
            'comment': comment
        }

    def _get_folder_children(self, user_id, folder_id, overwrite_rate_limit_retry=False):
        """
        Get the folder collection under the specified folder.

        :type user_id ``str``
        :param user_id: Mailbox address

        :type folder_id: ``str``
        :param folder_id: Folder id

        :return: List of folders that contain basic folder information
        :rtype: ``list``
        """
        suffix_endpoint = f'/users/{user_id}/mailFolders/{folder_id}/childFolders?$top=250'
        folder_children = self.ms_client.http_request('GET', suffix_endpoint,
                                                      overwrite_rate_limit_retry=overwrite_rate_limit_retry).get(
            'value', [])
        return folder_children

    def _get_folder_info(self, user_id, folder_id, overwrite_rate_limit_retry=False):
        """
        Returns folder information.

        :type user_id: ``str``
        :param user_id: Mailbox address

        :type folder_id: ``str``
        :param folder_id: Folder id

        :raises: ``Exception``: No info found for folder {folder id}

        :return: Folder information if found
        :rtype: ``dict``
        """

        suffix_endpoint = f'/users/{user_id}/mailFolders/{folder_id}'
        folder_info = self.ms_client.http_request('GET', suffix_endpoint,
                                                  overwrite_rate_limit_retry=overwrite_rate_limit_retry)
        if not folder_info:
            raise Exception(f'No info found for folder {folder_id}')
        return folder_info

    def _get_root_folder_children(self, user_id, overwrite_rate_limit_retry=False):
        """
        Get the root folder (Top Of Information Store) children collection.

        :type user_id: ``str``
        :param user_id: Mailbox address

        :raises: ``Exception``: No folders found under Top Of Information Store folder

        :return: List of root folder children
        rtype: ``list``
        """
        suffix_endpoint = f'/users/{user_id}/mailFolders/msgfolderroot/childFolders?$top=250'
        root_folder_children = self.ms_client.http_request('GET', suffix_endpoint,
                                                           overwrite_rate_limit_retry=overwrite_rate_limit_retry)\
            .get('value', None)
        if not root_folder_children:
            raise Exception("No folders found under Top Of Information Store folder")

        return root_folder_children

    def _get_folder_by_path(self, user_id, folder_path, overwrite_rate_limit_retry=False):
        """
        Searches and returns basic folder information.

        Receives mailbox address and folder path (e.g Inbox/Phishing) and iteratively retrieves folders info until
        reaches the last folder of a path. In case that such folder exist, basic information that includes folder id,
        display name, parent folder id, child folders count, unread items count and total items count will be returned.

        :type user_id: ``str``
        :param user_id: Mailbox address

        :type folder_path: ``str``
        :param folder_path: Folder path of searched folder

        :raises: ``Exception``: No such folder exist: {folder path}

        :return: Folder information if found
        :rtype: ``dict``
        """
        folders_names = folder_path.replace('\\', '/').split('/')  # replaced backslash in original folder path

        # Optimization step in order to improve performance before iterating the folder path in order to skip API call
        # for getting Top of Information Store children collection if possible.
        if folders_names[0].lower() in WELL_KNOWN_FOLDERS:
            # check if first folder in the path is known folder in order to skip not necessary api call
            folder_id = WELL_KNOWN_FOLDERS[folders_names[0].lower()]  # get folder shortcut instead of using folder id
            if len(folders_names) == 1:  # in such case the folder path consist only from one well known folder
                return self._get_folder_info(user_id, folder_id, overwrite_rate_limit_retry)
            else:
                current_directory_level_folders = self._get_folder_children(user_id, folder_id,
                                                                            overwrite_rate_limit_retry)
                folders_names.pop(0)  # remove the first folder name from the path before iterating
        else:  # in such case the optimization step is skipped
            # current_directory_level_folders will be set to folders that are under Top Of Information Store (root)
            current_directory_level_folders = self._get_root_folder_children(user_id, overwrite_rate_limit_retry)

        for index, folder_name in enumerate(folders_names):
            # searching for folder in current_directory_level_folders list by display name or id
            found_folder = [f for f in current_directory_level_folders if
                            f.get('displayName', '').lower() == folder_name.lower() or f.get('id', '') == folder_name]

            if not found_folder:  # no folder found, return error
                raise Exception(f'No such folder exist: {folder_path}')
            found_folder = found_folder[0]  # found_folder will be list with only one element in such case

            if index == len(folders_names) - 1:  # reached the final folder in the path
                # skip get folder children step in such case
                return found_folder
            # didn't reach the end of the loop, set the current_directory_level_folders to folder children
            current_directory_level_folders = self._get_folder_children(user_id, found_folder.get('id', ''),
                                                                        overwrite_rate_limit_retry=overwrite_rate_limit_retry)

    def get_emails(self, exclude_ids, last_fetch, folder_id, overwrite_rate_limit_retry=False):

        suffix_endpoint = f"/users/{self._mailbox_to_fetch}/mailFolders/{folder_id}/messages"
        # If you add to the select filter the $ sign, The 'internetMessageHeaders' field not contained within the
        # API response, (looks like a bug in graph API).
        params = {
            "$filter": f"receivedDateTime ge {last_fetch}",
            "$orderby": "receivedDateTime asc",
            "select": "*",
            "$top": len(exclude_ids) + self._emails_fetch_limit  # fetch extra incidents
        }

        emails_as_html = self.ms_client.http_request('GET', suffix_endpoint, params=params,
                                                     overwrite_rate_limit_retry=overwrite_rate_limit_retry)\
                             .get('value') or []

        headers = {
            "Prefer": "outlook.body-content-type='text'"
        }

        emails_as_text = self.ms_client.http_request(
            'GET', suffix_endpoint, params=params, overwrite_rate_limit_retry=overwrite_rate_limit_retry, headers=headers
        ).get('value') or []

        return self.get_emails_as_text_and_html(emails_as_html=emails_as_html, emails_as_text=emails_as_text)

    @staticmethod
    def get_emails_as_text_and_html(emails_as_html, emails_as_text):

        text_emails_ids = {email.get('id'): email for email in emails_as_text}
        emails_as_html_and_text = []

        for email_as_html in emails_as_html:
            html_email_id = email_as_html.get('id')
            text_email_data = text_emails_ids.get(html_email_id) or {}
            if not text_email_data:
                demisto.info(f'There is no matching text email to html email-ID {html_email_id}')

            body_as_text = text_email_data.get('body')
            if body_as_html := email_as_html.get('body'):
                email_as_html['body'] = (body_as_html, body_as_text)

            unique_body_as_text = text_email_data.get('uniqueBody')
            if unique_body_as_html := email_as_html.get('uniqueBody'):
                email_as_html['uniqueBody'] = (unique_body_as_html, unique_body_as_text)

            emails_as_html_and_text.append(email_as_html)

        return emails_as_html_and_text

    def _fetch_last_emails(self, folder_id, last_fetch, exclude_ids):
        """
        Fetches emails from given folder that were modified after specific datetime (last_fetch).
        All fields are fetched for given email using select=* clause,
        for more information https://docs.microsoft.com/en-us/graph/query-parameters.
        The email will be excluded from returned results if it's id is presented in exclude_ids.
        Number of fetched emails is limited by _emails_fetch_limit parameter.
        The filtering and ordering is done based on modified time.
        :type folder_id: ``str``
        :param folder_id: Folder id
        :type last_fetch: ``str``
        :param last_fetch: Previous fetch date
        :type exclude_ids: ``list``
        :param exclude_ids: List of previous fetch email ids to exclude in current run
        :return: Fetched emails and exclude ids list that contains the new ids of fetched emails
        :rtype: ``list`` and ``list``
        """
        demisto.debug(f'fetching emails since {last_fetch}')
        fetched_emails = self.get_emails(exclude_ids=exclude_ids, last_fetch=last_fetch,
                                         folder_id=folder_id, overwrite_rate_limit_retry=True)

        fetched_emails_ids = {email.get('id') for email in fetched_emails}
        exclude_ids_set = set(exclude_ids)
        if not fetched_emails or not (filtered_new_email_ids := fetched_emails_ids - exclude_ids_set):
            # no new emails
            demisto.debug(f'No new emails: {fetched_emails_ids=}. {exclude_ids_set=}')
            return [], exclude_ids
        new_emails = [mail for mail in fetched_emails
                      if mail.get('id') in filtered_new_email_ids][:self._emails_fetch_limit]
        last_email_time = new_emails[-1].get('receivedDateTime')
        if last_email_time == last_fetch:
            # next fetch will need to skip existing exclude_ids
            excluded_ids_for_nextrun = exclude_ids + [email.get('id') for email in new_emails]
        else:
            # next fetch will need to skip messages the same time as last_email
            excluded_ids_for_nextrun = [email.get('id') for email in new_emails if
                                        email.get('receivedDateTime') == last_email_time]

        return new_emails, excluded_ids_for_nextrun

    @staticmethod
    def get_email_content_as_text_and_html(email):
        email_body = email.get('body') or tuple()  # email body including replyTo emails.
        email_unique_body = email.get('uniqueBody') or tuple()  # email-body without replyTo emails.

        # there are situations where the 'body' key won't be returned from the api response, hence taking the uniqueBody
        # in those cases for both html/text formats.
        try:
            email_content_as_html, email_content_as_text = email_body or email_unique_body
        except ValueError:
            demisto.info(f'email body content is missing from email {email}')
            return '', ''

        return email_content_as_html.get('content'), email_content_as_text.get('content')

    def _parse_item_as_dict(self, email):
        """
        Parses basic data of email.

        Additional info https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0

        :type email: ``dict``
        :param email: Email to parse

        :return: Parsed email
        :rtype: ``dict``
        """
        parsed_email = {EMAIL_DATA_MAPPING[k]: v for (k, v) in email.items() if k in EMAIL_DATA_MAPPING}
        parsed_email['Headers'] = email.get('internetMessageHeaders', [])

        # there are situations where the 'body' key won't be returned from the api response, hence taking the uniqueBody
        # in those cases for both html/text formats.
        email_content_as_html, email_content_as_text = self.get_email_content_as_text_and_html(email)

        parsed_email['Body'] = email_content_as_html
        parsed_email['Text'] = email_content_as_text
        parsed_email['BodyType'] = 'html'

        parsed_email['Sender'] = MsGraphClient._get_recipient_address(email.get('sender', {}))
        parsed_email['From'] = MsGraphClient._get_recipient_address(email.get('from', {}))
        parsed_email['To'] = list(map(MsGraphClient._get_recipient_address, email.get('toRecipients', [])))
        parsed_email['Cc'] = list(map(MsGraphClient._get_recipient_address, email.get('ccRecipients', [])))
        parsed_email['Bcc'] = list(map(MsGraphClient._get_recipient_address, email.get('bccRecipients', [])))

        return parsed_email

    def _get_attachment_mime(self, message_id, attachment_id):
        """
        Gets attachment mime.

        :type attachment_id: ``str``
        :param attachment_id: Attachment id to get MIME

        :return: The MIME of the attachment
        :rtype: ``str``
        """
        suffix_endpoint = f'/users/{self._mailbox_to_fetch}/messages/{message_id}/attachments/{attachment_id}/$value'
        mime_content = self.ms_client.http_request('GET', suffix_endpoint, resp_type='text')

        return mime_content

    def _get_email_attachments(self, message_id):
        """
        Get email attachments  and upload to War Room.

        :type message_id: ``str``
        :param message_id: The email id to get attachments

        :return: List of uploaded to War Room data, uploaded file path and name
        :rtype: ``list``
        """

        attachment_results = []  # type: ignore
        suffix_endpoint = f'/users/{self._mailbox_to_fetch}/messages/{message_id}/attachments'
        attachments = self.ms_client.http_request('Get', suffix_endpoint).get('value', [])

        for attachment in attachments:
            attachment_type = attachment.get('@odata.type', '')
            attachment_name = attachment.get('name', 'untitled_attachment')
            if attachment_type == self.FILE_ATTACHMENT:
                try:
                    attachment_content = base64.b64decode(attachment.get('contentBytes', ''))
                except Exception as e:  # skip the uploading file step
                    demisto.info(f"MS-Graph-Listener: failed in decoding base64 file attachment with error {str(e)}")
                    continue
            elif attachment_type == self.ITEM_ATTACHMENT:
                attachment_id = attachment.get('id', '')
                attachment_content = self._get_attachment_mime(message_id, attachment_id)
                attachment_name = f'{attachment_name}.eml'
            else:
                # skip attachments that are not of the previous types (type referenceAttachment)
                continue
            # upload the item/file attachment to War Room
            upload_file(attachment_name, attachment_content, attachment_results)

        return attachment_results

    @staticmethod
    def _parse_email_as_labels(parsed_email):
        """
        Parses the email as incident labels.

        :type parsed_email: ``dict``
        :param parsed_email: The parsed email from which create incidents labels.

        :return: Incident labels
        :rtype: ``list``
        """
        labels = []

        for (key, value) in parsed_email.items():
            if key == 'Headers':
                headers_labels = [
                    {'type': 'Email/Header/{}'.format(header.get('name', '')), 'value': header.get('value', '')}
                    for header in value]
                labels.extend(headers_labels)
            elif key in ['To', 'Cc', 'Bcc']:
                recipients_labels = [{'type': f'Email/{key}', 'value': recipient} for recipient in value]
                labels.extend(recipients_labels)
            else:
                labels.append({'type': f'Email/{key}', 'value': f'{value}'})

        return labels

    def _parse_email_as_incident(self, email):
        """
        Parses fetched emails as incidents.

        :type email: ``dict``
        :param email: Fetched email to parse

        :return: Parsed email
        :rtype: ``dict``
        """
        parsed_email = self._parse_item_as_dict(email)

        # handling attachments of fetched email
        attachments = self._get_email_attachments(message_id=email.get('id', ''))
        if attachments:
            parsed_email['Attachments'] = attachments

        parsed_email['Mailbox'] = self._mailbox_to_fetch

        body = email.get('bodyPreview', '')
        if not body or self.display_full_email_body:
            _, body = self.get_email_content_as_text_and_html(email)

        incident = {
            'name': parsed_email.get('Subject'),
            'details': body,
            'labels': MsGraphClient._parse_email_as_labels(parsed_email),
            'occurred': parsed_email.get('ModifiedTime'),
            'attachment': parsed_email.get('Attachments', []),
            'rawJSON': json.dumps(parsed_email),
            'ID': parsed_email.get('ID')  # only used for look-back to identify the email in a unique way
        }

        return incident

    @logger
    def fetch_incidents(self, last_run):
        """
        Fetches emails from office 365 mailbox and creates incidents of parsed emails.
        :type last_run: ``dict``
        :param last_run:
            Previous fetch run data that holds the fetch time in utc Y-m-dTH:M:SZ format,
            ids of fetched emails, id and path of folder to fetch incidents from
        :return: Next run data and parsed fetched incidents
        :rtype: ``dict`` and ``list``
        """
        if 'time' not in last_run and (last_run_time := last_run.get('LAST_RUN_TIME')):
            last_run['time'] = last_run_time.replace('Z', '')

        if 'time' in last_run:
            last_run['time'] = last_run['time'].replace('Z', '')

        start_fetch_time, end_fetch_time = get_fetch_run_time_range(
            last_run=last_run,
            first_fetch=self._first_fetch_interval,
            look_back=self.look_back,
            date_format=API_DATE_FORMAT
        )

        demisto.debug(f'{start_fetch_time=}, {end_fetch_time=}')

        exclude_ids = list(set(last_run.get('LAST_RUN_IDS', [])))  # remove any possible duplicates

        last_run_folder_path = last_run.get('LAST_RUN_FOLDER_PATH')
        folder_path_changed = (last_run_folder_path != self._folder_to_fetch)
        last_run_account = last_run.get('LAST_RUN_ACCOUNT')
        mailbox_to_fetch_changed = last_run_account != self._mailbox_to_fetch

        if folder_path_changed or mailbox_to_fetch_changed:
            # detected folder path change, get new folder id
            folder_id = self._get_folder_by_path(self._mailbox_to_fetch, self._folder_to_fetch,
                                                 overwrite_rate_limit_retry=True).get('id')
            demisto.info("MS-Graph-Listener: detected file path change, ignored LAST_RUN_FOLDER_ID from last run.")
        else:
            # LAST_RUN_FOLDER_ID is stored in order to avoid calling _get_folder_by_path method in each fetch
            folder_id = last_run.get('LAST_RUN_FOLDER_ID')

        fetched_emails, exclude_ids = self._fetch_last_emails(
            folder_id=folder_id, last_fetch=start_fetch_time, exclude_ids=exclude_ids)

        demisto.debug(
            f'fetched email IDs before removing duplications - {[email.get("id") for email in fetched_emails]}'
        )

        # remove duplicate incidents which were already fetched
        incidents = filter_incidents_by_duplicates_and_limit(
            incidents_res=list(map(self._parse_email_as_incident, fetched_emails)),
            last_run=last_run,
            fetch_limit=self._emails_fetch_limit,
            id_field='ID'
        )

        demisto.debug(
            f'fetched email IDs after removing duplications - {[email.get("ID") for email in incidents]}'
        )

        next_run = update_last_run_object(
            last_run=last_run,
            incidents=incidents,
            fetch_limit=self._emails_fetch_limit,
            start_fetch_time=start_fetch_time,
            end_fetch_time=end_fetch_time,
            look_back=self.look_back,
            created_time_field='occurred',
            id_field='ID',
            date_format=API_DATE_FORMAT,
            increase_last_run_time=True
        )

        next_run.update(
            {
                'LAST_RUN_IDS': exclude_ids,
                'LAST_RUN_FOLDER_ID': folder_id,
                'LAST_RUN_FOLDER_PATH': self._folder_to_fetch,
                'LAST_RUN_ACCOUNT': self._mailbox_to_fetch,
            }
        )

        for incident in incidents:  # remove the ID from the incidents, they are used only for look-back.
            incident.pop('ID', None)

        demisto.info(f"MS-Graph-Listener: fetched {len(incidents)} incidents")
        demisto.debug(f"{next_run=}")

        return next_run, incidents

    def add_attachments_via_upload_session(self, email, draft_id, attachments):
        """
        Add attachments using an upload session by dividing the file bytes into chunks and sent each chunk each time.
        more info here - https://docs.microsoft.com/en-us/graph/outlook-large-attachments?tabs=http

        Args:
            email (str): email to create the upload session.
            draft_id (str): draft ID to add the attachments to.
            attachments (list[dict]) : attachments to add to the draft message.
        """
        for attachment in attachments:
            self.add_attachment_with_upload_session(
                email=email,
                draft_id=draft_id,
                attachment_data=attachment.get('data'),
                attachment_name=attachment.get('name'),
                is_inline=attachment.get('isInline')
            )

    def get_upload_session(self, email, draft_id, attachment_name, attachment_size, is_inline):
        """
        Create an upload session for a specific draft ID.

        Args:
            email (str): email to create the upload session.
            draft_id (str): draft ID to add the attachments to.
            attachment_size (int) : attachment size (in bytes).
            attachment_name (str): attachment name.
            is_inline (bool): is the attachment inline, True if yes, False if not.
        """
        return self.ms_client.http_request(
            'POST',
            f'/users/{email}/messages/{draft_id}/attachments/createUploadSession',
            json_data={
                'attachmentItem': {
                    'attachmentType': 'file',
                    'name': attachment_name,
                    'size': attachment_size,
                    'isInline': is_inline
                }
            }
        )

    @staticmethod
    def upload_attachment(
            upload_url, start_chunk_idx, end_chunk_idx, chunk_data, attachment_size
    ):
        """
        Upload an attachment to the upload URL.

        Args:
            upload_url (str): upload URL provided when running 'get_upload_session'
            start_chunk_idx (int): the start of the chunk file data.
            end_chunk_idx (int): the end of the chunk file data.
            chunk_data (bytes): the chunk data in bytes from start_chunk_idx to end_chunk_idx
            attachment_size (int): the entire attachment size in bytes.

        Returns:
            Response: response indicating whether the operation succeeded. 200 if a chunk was added successfully,
                201 (created) if the file was uploaded completely. 400 in case of errors.
        """
        chunk_size = len(chunk_data)
        headers = {
            "Content-Length": f'{chunk_size}',
            "Content-Range": f"bytes {start_chunk_idx}-{end_chunk_idx - 1}/{attachment_size}",
            "Content-Type": "application/octet-stream"
        }
        demisto.debug(f'uploading session headers: {headers}')
        return requests.put(url=upload_url, data=chunk_data, headers=headers)

    def add_attachment_with_upload_session(self, email, draft_id, attachment_data, attachment_name, is_inline=False):
        """
        Add an attachment using an upload session by dividing the file bytes into chunks and sent each chunk each time.
        more info here - https://docs.microsoft.com/en-us/graph/outlook-large-attachments?tabs=http

        Args:
            email (str): email to create the upload session.
            draft_id (str): draft ID to add the attachments to.
            attachment_data (bytes) : attachment data in bytes.
            attachment_name (str): attachment name.
            is_inline (bool): is the attachment inline, True if yes, False if not.
        """

        attachment_size = len(attachment_data)
        try:
            upload_session = self.get_upload_session(
                email=email,
                draft_id=draft_id,
                attachment_name=attachment_name,
                attachment_size=attachment_size,
                is_inline=is_inline
            )
            upload_url = upload_session.get('uploadUrl')
            if not upload_url:
                raise Exception(f'Cannot get upload URL for attachment {attachment_name}')

            start_chunk_index = 0
            end_chunk_index = self.MAX_ATTACHMENT_SIZE

            chunk_data = attachment_data[start_chunk_index: end_chunk_index]

            response = self.upload_attachment(
                upload_url=upload_url,
                start_chunk_idx=start_chunk_index,
                end_chunk_idx=end_chunk_index,
                chunk_data=chunk_data,
                attachment_size=attachment_size
            )
            while response.status_code != 201:  # the api returns 201 when the file is created at the draft message
                start_chunk_index = end_chunk_index
                next_chunk = end_chunk_index + self.MAX_ATTACHMENT_SIZE
                end_chunk_index = next_chunk if next_chunk < attachment_size else attachment_size

                chunk_data = attachment_data[start_chunk_index: end_chunk_index]

                response = self.upload_attachment(
                    upload_url=upload_url,
                    start_chunk_idx=start_chunk_index,
                    end_chunk_idx=end_chunk_index,
                    chunk_data=chunk_data,
                    attachment_size=attachment_size
                )

                if response.status_code not in (201, 200):
                    raise Exception(f'{response.json()}')

        except Exception as e:
            demisto.error(f'{e}')
            raise e

    def create_draft(self, email, json_data, reply_message_id=None):
        """
        Create a draft message for either a new message or as a reply to an existing message.

        Args:
            email (str): email to create the draft from.
            json_data (dict): data to create the message with.
            reply_message_id (str): message ID in case creating a draft to an existing message.

        Returns:
            dict: api response information about the draft.
        """
        if reply_message_id:
            suffix = f'/users/{email}/messages/{reply_message_id}/createReply'  # create draft for a reply to an existing message
        else:
            suffix = f'/users/{email}/messages'  # create draft for a new message
        return self.ms_client.http_request('POST', suffix, json_data=json_data)

    def send_draft(self, email, draft_id):
        """
        Sends a draft message.

        Args:
            email (str): email to send the draft from.
            draft_id (str): the ID of the draft to send.
        """
        self.ms_client.http_request('POST', f'/users/{email}/messages/{draft_id}/send', resp_type='text')

    def send_mail(self, email, json_data):
        """
        Sends an email.

        Args:
            email (str): email to send the the message from.
            json_data (dict): message data.
        """
        self.ms_client.http_request(
            'POST', f'/users/{email}/sendMail', json_data={'message': json_data}, resp_type="text"
        )

    def send_reply(self, email_from, json_data, message_id):
        """
        Sends a reply email.

        Args:
            email_from (str): email to send the reply from.
            message_id (str): a message ID to reply to.
            message (dict): message body request.
            comment (str): email's body.
        """
        self.ms_client.http_request(
            'POST',
            f'/users/{email_from}/messages/{message_id}/reply',
            json_data=json_data,
            resp_type="text"
        )

    def send_mail_with_upload_session_flow(self, email, json_data, attachments_more_than_3mb, reply_message_id=None):
        """
        Sends an email with the upload session flow, this is used only when there is one attachment that is larger
        than 3 MB.

        1) creates a draft message
        2) upload the attachment using an upload session which uploads file chunks by chunks.
        3) send the draft message

        Args:
            email (str): email to send from.
            json_data (dict): data to send the message with.
            attachments_more_than_3mb (list[dict]): data information about the large attachments.
            reply_message_id (str): message ID in case sending a reply to an existing message.
        """
        # create the draft email
        created_draft = self.create_draft(email=email, json_data=json_data, reply_message_id=reply_message_id)
        draft_id = created_draft.get('id')
        self.add_attachments_via_upload_session(  # add attachments via upload session.
            email=email, draft_id=draft_id, attachments=attachments_more_than_3mb
        )
        self.send_draft(email=email, draft_id=draft_id)  # send the draft email


''' HELPER FUNCTIONS '''


def upload_file(filename, content, attachments_list):
    """
    Uploads file to War room.

    :type filename: ``str``
    :param filename: file name to upload

    :type content: ``str``
    :param content: Content of file to upload

    :type attachments_list: ``list``
    :param attachments_list: List of uploaded file data to War Room
    """
    file_result = fileResult(filename, content)

    if is_error(file_result):
        demisto.error(file_result['Contents'])
        raise Exception(file_result['Contents'])

    attachments_list.append({
        'path': file_result['FileID'],
        'name': file_result['File']
    })


def get_now_utc():
    """
    Creates UTC current time of format Y-m-dTH:M:SZ (e.g. 2019-11-06T09:06:39Z)

    :return: String format of current UTC time
    :rtype: ``str``
    """
    return datetime.utcnow().strftime(API_DATE_FORMAT)


def read_file(attach_id):
    """
    Reads file that was uploaded to War Room.

    :type attach_id: ``str``
    :param attach_id: The id of uploaded file to War Room

    :return: file data, size of the file in bytes and uploaded file name.
    :rtype: ``bytes``, ``int``, ``str``
    """
    try:
        file_info = demisto.getFilePath(attach_id)
        with open(file_info['path'], 'rb') as file_data:
            file_data = file_data.read()  # type: ignore[assignment]
            file_size = os.path.getsize(file_info['path'])
            return file_data, file_size, file_info['name']
    except Exception as e:
        raise Exception(f'Unable to read and decode in base 64 file with id {attach_id}', e)


def assert_pages(pages: Union[str, int]) -> int:
    """

    Args:
        pages (str or int): pages need to pull in int or str

    Returns:
        int: default 1

    """
    if isinstance(pages, str) and pages.isdigit():
        return int(pages)
    elif isinstance(pages, int):
        return pages
    return 1


def build_folders_path(folder_string: str) -> Optional[str]:
    """

    Args:
        folder_string (str): string with `,` delimiter. first one is mailFolders all other are child

    Returns:
        str or None:  string with path to the folder and child folders
    """
    if isinstance(folder_string, str):
        path = 'mailFolders/'
        folders_list = argToList(folder_string, ',')
        first = True
        for folder in folders_list:
            if first:
                path += folder
                first = False
            else:
                path += f'/childFolders/{folder}'
        return path
    return None


def build_mail_object(raw_response: Union[dict, list], user_id: str, get_body: bool = False) -> Union[dict, list]:
    """Building mail entry context
    Getting a list from build_mail_object

    Args:
        user_id (str): user id of the mail
        get_body (bool): should get body
        raw_response (dict or list): list of pages

    Returns:
        dict or list: output context
    """

    def build_mail(given_mail: dict) -> dict:
        """

        Args:
            given_mail (dict):

        Returns:
            dict:
        """
        # Dicts
        mail_properties = {
            'ID': 'id',
            'Created': 'createdDateTime',
            'LastModifiedTime': 'lastModifiedDateTime',
            'ReceivedTime': 'receivedDateTime',
            'SendTime': 'sentDateTime',
            'Categories': 'categories',
            'HasAttachments': 'hasAttachments',
            'Subject': 'subject',
            'IsDraft': 'isDraft',
            'Headers': 'internetMessageHeaders',
            'Flag': 'flag',
            'Importance': 'importance',
            'InternetMessageID': 'internetMessageId',
            'ConversationID': 'conversationId',
        }

        contact_properties = {
            'Sender': 'sender',
            'From': 'from',
            'Recipients': 'toRecipients',
            'CCRecipients': 'ccRecipients',
            'BCCRecipients': 'bccRecipients',
            'ReplyTo': 'replyTo'
        }

        # Create entry properties
        entry = {k: given_mail.get(v) for k, v in mail_properties.items()}

        # Create contacts properties
        entry.update(
            {k: build_contact(given_mail.get(v)) for k, v in contact_properties.items()}  # type: ignore
        )

        if get_body:
            entry['Body'] = given_mail.get('body', {}).get('content')
        entry['UserID'] = user_id
        return entry

    def build_contact(contacts: Union[dict, list, str]) -> object:
        """Building contact object

        Args:
            contacts (list or dict or str):

        Returns:
            dict or list[dict] or str or None: describing contact
        """
        if contacts:
            if isinstance(contacts, list):
                return [build_contact(contact) for contact in contacts]
            elif isinstance(contacts, dict):
                email = contacts.get('emailAddress')
                if email and isinstance(email, dict):
                    return {
                        'Name': email.get('name'),
                        'Address': email.get('address')
                    }
        return None

    mails_list = list()
    if isinstance(raw_response, list):  # response from list_emails_command
        for page in raw_response:
            # raw_response is a list containing multiple pages or one page
            # if value is not empty, there are emails in the page
            value = page.get('value')
            if value:
                for mail in value:
                    mails_list.append(build_mail(mail))
    elif isinstance(raw_response, dict):  # response from get_message_command
        return build_mail(raw_response)
    return mails_list


def file_result_creator(raw_response: dict) -> dict:
    """

    Args:
        raw_response (dict):

    Returns:
        dict:

    """
    name = raw_response.get('name')
    data = raw_response.get('contentBytes')
    try:
        data = base64.b64decode(data)  # type: ignore
        return fileResult(name, data)
    except binascii.Error:
        return_error('Attachment could not be decoded')
        return {}  # return_error will exit


def parse_folders_list(folders_list):
    if isinstance(folders_list, dict):
        folders_list = [folders_list]

    return [{FOLDER_MAPPING[k]: v for (k, v) in f.items() if k in FOLDER_MAPPING} for f in folders_list]


def get_text_from_html(html):
    # parse HTML into plain-text
    soup = BeautifulSoup(html, features="html.parser")

    # kill all script and style elements
    for script in soup(["script", "style"]):
        script.extract()  # rip it out
    # get text
    text = soup.get_text()
    # break into lines and remove leading and trailing space on each line
    lines = (line.strip() for line in text.splitlines())
    # break multi-headlines into a line each
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    # drop blank lines
    return '\n'.join(chunk for chunk in chunks if chunk)


''' COMMANDS '''


def list_mails_command(client: MsGraphClient, args):
    search = args.get('search')
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    odata = args.get('odata')

    raw_response = client.list_mails(user_id, folder_id=folder_id, search=search, odata=odata)
    last_page_response = raw_response[len(raw_response) - 1]
    metadata = ''
    next_page = last_page_response.get('@odata.nextLink')
    if next_page:
        metadata = '\nPay attention there are more results than shown. For more data please ' \
                   'increase "pages_to_pull" argument'

    mail_context = build_mail_object(raw_response, user_id)
    entry_context = {}
    if mail_context:
        entry_context = {'MSGraphMail(val.ID === obj.ID)': mail_context}
        if next_page:
            # .NextPage.indexOf(\'http\')>=0 : will make sure the NextPage token will always be updated because it's a url
            entry_context['MSGraphMail(val.NextPage.indexOf(\'http\')>=0)'] = {'NextPage': next_page}

        # human_readable builder
        human_readable_header = f'{len(mail_context)} mails received {metadata}' if metadata \
            else f'Total of {len(mail_context)} mails received'
        human_readable = tableToMarkdown(
            human_readable_header,
            mail_context,
            headers=['Subject', 'From', 'Recipients', 'SendTime', 'ID', 'InternetMessageID']
        )
    else:
        human_readable = '### No mails were found'
    return_outputs(human_readable, entry_context, raw_response)


def delete_mail_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    message_id = args.get('message_id')
    client.delete_mail(user_id, message_id, folder_id)

    human_readable = tableToMarkdown(
        'Message has been deleted successfully',
        {
            'Message ID': message_id,
            'User ID': user_id,
            'Folder ID': folder_id
        },
        headers=['Message ID', 'User ID', 'Folder ID'],
        removeNull=True
    )

    entry_context = {}  # type: ignore

    return_outputs(human_readable, entry_context)


def item_result_creator(raw_response, user_id) -> CommandResults:
    item = raw_response.get('item', {})
    item_type = item.get('@odata.type', '')
    if 'message' in item_type:
        message_id = raw_response.get('id')
        item['id'] = message_id
        mail_context = build_mail_object(item, user_id=user_id, get_body=True)
        human_readable = tableToMarkdown(
            f'Attachment ID {message_id} \n **message details:**',
            mail_context,
            headers=['ID', 'Subject', 'SendTime', 'Sender', 'From', 'HasAttachments', 'Body']
        )
        return CommandResults(outputs_prefix='MSGraphMail',
                              outputs_key_field='ID',
                              outputs=mail_context,
                              readable_output=human_readable,
                              raw_response=raw_response)
    else:
        human_readable = f'Integration does not support attachments from type {item_type}'
        return CommandResults(readable_output=human_readable, raw_response=raw_response)


def create_attachment(raw_response, user_id) -> Union[CommandResults, dict]:
    attachment_type = raw_response.get('@odata.type', '')
    # Documentation about the different attachment types
    # https://docs.microsoft.com/en-us/graph/api/attachment-get?view=graph-rest-1.0&tabs=http
    if 'itemAttachment' in attachment_type:
        return item_result_creator(raw_response, user_id)
    elif 'fileAttachment' in attachment_type:
        return file_result_creator(raw_response)
    else:
        demisto.debug(f"Unsupported attachment type: {attachment_type}. Attachment was not added to incident")
        return {}


def get_attachment_command(client: MsGraphClient, args):
    message_id = args.get('message_id')
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    attachment_id = args.get('attachment_id')
    raw_response = client.get_attachment(message_id, user_id, folder_id=folder_id, attachment_id=attachment_id)
    attachment = create_attachment(raw_response, user_id)
    return_results(attachment)


def get_message_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    message_id = args.get('message_id')
    get_body = args.get('get_body') == 'true'
    odata = args.get('odata')
    raw_response = client.get_message(user_id, message_id, folder_id, odata=odata)
    mail_context = build_mail_object(raw_response, user_id=user_id, get_body=get_body)
    entry_context = {'MSGraphMail(val.ID === obj.ID)': mail_context}
    human_readable = tableToMarkdown(
        f'Results for message ID {message_id}',
        mail_context,
        headers=['ID', 'Subject', 'SendTime', 'Sender', 'From', 'Recipients', 'HasAttachments', 'Body']
    )
    return_outputs(
        human_readable,
        entry_context,
        raw_response=raw_response
    )


def list_attachments_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    message_id = args.get('message_id')
    folder_id = args.get('folder_id')
    raw_response = client.list_attachments(user_id, message_id, folder_id)
    attachments = raw_response.get('value')
    if attachments:
        attachment_list = [{
            'ID': attachment.get('id'),
            'Name': attachment.get('name') or attachment.get('id'),
            'Type': attachment.get('contentType')
        } for attachment in attachments]
        attachment_entry = {'ID': message_id, 'Attachment': attachment_list, 'UserID': user_id}
        entry_context = {'MSGraphMailAttachment(val.ID === obj.ID)': attachment_entry}

        # Build human readable
        file_names = [attachment.get('Name') for attachment in attachment_list if isinstance(
            attachment, dict) and attachment.get('Name')]
        human_readable = tableToMarkdown(
            f'Total of {len(attachment_list)} attachments found in message {message_id} from user {user_id}',
            {'File names': file_names}
        )
        return_outputs(human_readable, entry_context, raw_response)
    else:
        human_readable = f'### No attachments found in message {message_id}'
        return_outputs(human_readable, dict(), raw_response)


def list_folders_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    limit = args.get('limit', '20')

    raw_response = client.list_folders(user_id, limit)
    parsed_folder_result = parse_folders_list(raw_response.get('value', []))
    human_readable = tableToMarkdown(f'Mail Folder collection under root folder for user {user_id}',
                                     parsed_folder_result)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_folder_result}

    return_outputs(human_readable, entry_context, raw_response)


def list_child_folders_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    parent_folder_id = args.get('parent_folder_id')
    limit = args.get('limit', '20')

    raw_response = client.list_child_folders(user_id, parent_folder_id, limit)
    parsed_child_folders_result = parse_folders_list(raw_response.get('value', []))  # type: ignore
    human_readable = tableToMarkdown(f'Mail Folder collection under {parent_folder_id} folder for user {user_id}',
                                     parsed_child_folders_result)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_child_folders_result}

    return_outputs(human_readable, entry_context, raw_response)


def create_folder_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    new_folder_name = args.get('new_folder_name')
    parent_folder_id = args.get('parent_folder_id')

    raw_response = client.create_folder(user_id, new_folder_name, parent_folder_id)
    parsed_created_folder = parse_folders_list(raw_response)
    human_readable = tableToMarkdown(
        f'Mail folder was created with display name: {new_folder_name}',
        parsed_created_folder)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_created_folder}

    return_outputs(human_readable, entry_context, raw_response)


def update_folder_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    new_display_name = args.get('new_display_name')

    raw_response = client.update_folder(user_id, folder_id, new_display_name)
    parsed_updated_folder = parse_folders_list(raw_response)
    human_readable = tableToMarkdown(f'Mail folder {folder_id} was updated with display name: {new_display_name}',
                                     parsed_updated_folder)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_updated_folder}

    return_outputs(human_readable, entry_context, raw_response)


def delete_folder_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')

    client.delete_folder(user_id, folder_id)
    return_outputs(f'The folder {folder_id} was deleted successfully')


def move_email_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    message_id = args.get('message_id')
    destination_folder_id = args.get('destination_folder_id')

    raw_response = client.move_email(user_id, message_id, destination_folder_id)
    new_message_id = raw_response.get('id')
    moved_email_info = {
        'ID': new_message_id,
        'DestinationFolderID': destination_folder_id,
        'UserID': user_id
    }
    human_readable = tableToMarkdown('The email was moved successfully. Updated email data:', moved_email_info)
    entry_context = {CONTEXT_COPIED_EMAIL: moved_email_info}

    return_outputs(human_readable, entry_context, raw_response)


def get_email_as_eml_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    message_id = args.get('message_id')

    eml_content = client.get_email_as_eml(user_id, message_id)
    file_result = fileResult(f'{message_id}.eml', eml_content)

    if is_error(file_result):
        raise Exception(file_result['Contents'])

    demisto.results(file_result)


def prepare_args(command, args):
    """
    Receives command and prepares the arguments for future usage.

    :type command: ``str``
    :param command: Command to execute

    :type args: ``dict``
    :param args: Demisto args

    :return: Prepared args
    :rtype: ``dict``
    """
    if command in ['create-draft', 'send-mail']:
        if args.get('htmlBody', None):
            email_body = args.get('htmlBody')
        else:
            email_body = args.get('body', '')
        return {
            'to_recipients': argToList(args.get('to')),
            'cc_recipients': argToList(args.get('cc')),
            'bcc_recipients': argToList(args.get('bcc')),
            'reply_to': argToList(args.get('replyTo')),
            'subject': args.get('subject', ''),
            'body': email_body,
            'body_type': args.get('bodyType', 'html'),
            'flag': args.get('flag', 'notFlagged'),
            'importance': args.get('importance', 'Low'),
            'internet_message_headers': argToList(args.get('headers')),
            'attach_ids': argToList(args.get('attachIDs')),
            'attach_names': argToList(args.get('attachNames')),
            'attach_cids': argToList((args.get('attachCIDs'))),
            'manual_attachments': args.get('manualAttachObj', [])
        }

    elif command == 'reply-to':
        return {
            'to_recipients': argToList(args.get('to')),
            'message_id': args.get('ID', ''),
            'comment': args.get('body'),
            'attach_ids': argToList(args.get('attachIDs')),
            'attach_names': argToList(args.get('attachNames')),
            'attach_cids': argToList((args.get('attachCIDs')))
        }

    return args


def divide_attachments_according_to_size(attachments):
    """
    Divide attachments to those are larger than 3mb and those who are less than 3mb.

    Returns:
        tuple[list, list]: less than 3mb attachments and more than 3mb attachments.
    """
    less_than_3mb_attachments, more_than_3mb_attachments = [], []

    for attachment in attachments:
        if attachment.pop('requires_upload', None):  # if the attachment is bigger than 3mb, it requires upload session.
            more_than_3mb_attachments.append(attachment)
        else:
            less_than_3mb_attachments.append(attachment)
    return less_than_3mb_attachments, more_than_3mb_attachments


def create_draft_command(client: MsGraphClient, args):
    """
    Creates draft message in user's mailbox, in draft folder.
    """
    prepared_args = prepare_args('create-draft', args)
    email = args.get('from')
    draft = client.build_message(**prepared_args)
    less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
        attachments=draft.get('attachments')
    )

    draft['attachments'] = less_than_3mb_attachments
    created_draft = client.create_draft(email=email, json_data=draft)

    if more_than_3mb_attachments:  # we have at least one attachment that should be uploaded using upload session
        client.add_attachments_via_upload_session(
            email=email, draft_id=created_draft.get('id'), attachments=more_than_3mb_attachments
        )

    parsed_draft = client.parse_item_as_dict(created_draft)
    headers = ['ID', 'From', 'Sender', 'To', 'Subject', 'Body', 'BodyType', 'Cc', 'Bcc', 'Headers', 'Importance',
               'MessageID', 'ConversationID', 'CreatedTime', 'SentTime', 'ReceivedTime', 'ModifiedTime', 'IsDraft',
               'IsRead']
    human_readable = tableToMarkdown(f'Created draft with id: {parsed_draft.get("ID", "")}',
                                     parsed_draft, headers=headers)
    entry_context = {CONTEXT_DRAFT_PATH: parsed_draft}

    return_outputs(human_readable, entry_context, created_draft)


def build_recipients_human_readable(message_content):
    to_recipients = []
    cc_recipients = []
    bcc_recipients = []
    reply_to_recipients = []

    for recipients_dict in message_content.get('toRecipients', {}):
        to_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('ccRecipients', {}):
        cc_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('bccRecipients', {}):
        bcc_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('replyTo', {}):
        reply_to_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    return to_recipients, cc_recipients, bcc_recipients, reply_to_recipients


def send_email_command(client: MsGraphClient, args):
    """
    Sends email from user's mailbox, the sent message will appear in Sent Items folder.

    Sending email process:
    1) If there are attachments larger than 3MB, create a draft mail, upload > 3MB attachments via upload session,
        and send the draft mail.

    2) if there aren't any attachments larger than 3MB, just send the email as usual.
    """
    prepared_args = prepare_args('send-mail', args)
    message_content = MsGraphClient.build_message(**prepared_args)
    email = args.get('from', client._mailbox_to_fetch)

    less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
        attachments=message_content.get('attachments')
    )

    if more_than_3mb_attachments:  # go through process 1 (in docstring)
        message_content['attachments'] = less_than_3mb_attachments
        client.send_mail_with_upload_session_flow(
            email=email, json_data=message_content, attachments_more_than_3mb=more_than_3mb_attachments
        )
    else:  # go through process 2 (in docstring)
        client.send_mail(email=email, json_data=message_content)

    message_content.pop('attachments', None)
    message_content.pop('internet_message_headers', None)

    to_recipients, cc_recipients, bcc_recipients, reply_to_recipients = build_recipients_human_readable(message_content)
    message_content['toRecipients'] = to_recipients
    message_content['ccRecipients'] = cc_recipients
    message_content['bccRecipients'] = bcc_recipients
    message_content['replyTo'] = reply_to_recipients

    message_content = assign_params(**message_content)
    human_readable = tableToMarkdown('Email was sent successfully.', message_content)
    ec = {CONTEXT_SENT_EMAIL_PATH: message_content}

    return_outputs(human_readable, ec)


def prepare_outputs_for_reply_mail_command(reply, email_to, message_id):
    reply.pop('attachments', None)
    to_recipients, cc_recipients, bcc_recipients, reply_to_recipients = build_recipients_human_readable(reply)
    reply['toRecipients'] = to_recipients
    reply['ccRecipients'] = cc_recipients
    reply['bccRecipients'] = bcc_recipients
    reply['replyTo'] = reply_to_recipients
    reply['ID'] = message_id

    message_content = assign_params(**reply)
    human_readable = tableToMarkdown(f'Replied message was successfully sent to {", ".join(email_to)} .',
                                     message_content)

    return CommandResults(
        outputs_prefix="MicrosoftGraph",
        readable_output=human_readable,
        outputs_key_field="SentMail",
        outputs=message_content,
    )


def reply_email_command(client: MsGraphClient, args):
    """
    Reply to an email from user's mailbox, the sent message will appear in Sent Items folder
    """
    email_to = argToList(args.get('to'))
    email_from = args.get('from', client._mailbox_to_fetch)
    message_id = args.get('inReplyTo')
    reply_to = argToList(args.get('replyTo'))
    email_body = args.get('body', "")
    email_subject = args.get('subject', "")
    email_subject = f'Re: {email_subject}'
    attach_ids = argToList(args.get('attachIDs'))
    email_cc = argToList(args.get('cc'))
    email_bcc = argToList(args.get('bcc'))
    html_body = args.get('htmlBody')
    attach_names = argToList(args.get('attachNames'))
    attach_cids = argToList(args.get('attachCIDs'))
    message_body = html_body or email_body

    reply = client.build_message_to_reply(email_to, email_cc, email_bcc, email_subject, message_body, attach_ids,
                                          attach_names, attach_cids, reply_to)

    less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
        attachments=reply.get('attachments')
    )

    if more_than_3mb_attachments:
        reply['attachments'] = less_than_3mb_attachments
        client.send_mail_with_upload_session_flow(
            email=email_from,
            json_data={'message': reply, 'comment': message_body},
            attachments_more_than_3mb=more_than_3mb_attachments,
            reply_message_id=message_id
        )
    else:
        client.send_reply(
            email_from=email_from, message_id=message_id, json_data={'message': reply, 'comment': message_body}
        )

    return prepare_outputs_for_reply_mail_command(reply, email_to, message_id)


def reply_to_command(client: MsGraphClient, args):
    prepared_args = prepare_args('reply-to', args)

    to_recipients = prepared_args.get('to_recipients')
    message_id = prepared_args.get('message_id')
    comment = prepared_args.get('comment')
    attach_ids = prepared_args.get('attach_ids')
    attach_names = prepared_args.get('attach_names')
    attach_cids = prepared_args.get('attach_cids')
    email = args.get('from')

    reply = client.build_reply(to_recipients, comment, attach_ids, attach_names, attach_cids)

    less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
        attachments=reply.get('message').get('attachments')
    )

    if more_than_3mb_attachments:
        reply['message']['attachments'] = less_than_3mb_attachments
        client.send_mail_with_upload_session_flow(
            email=email,
            json_data=reply,
            attachments_more_than_3mb=more_than_3mb_attachments,
            reply_message_id=message_id
        )
    else:
        client.send_reply(email_from=email, message_id=message_id, json_data=reply)

    return_outputs(f'### Replied to: {", ".join(to_recipients)} with comment: {comment}')


def send_draft_command(client: MsGraphClient, args):
    email = args.get('from')
    draft_id = args.get('draft_id')
    client.send_draft(email=email, draft_id=draft_id)

    return_outputs(f'### Draft with: {draft_id} id was sent successfully.')


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    args: dict = demisto.args()
    params: dict = demisto.params()
    self_deployed: bool = params.get('self_deployed', False)
    # There're several options for tenant_id & auth_and_token_url due to the recent credentials set supoort enhancment.
    tenant_id: str = params.get('tenant_id', '') or params.get('_tenant_id', '') or (params.get('creds_tenant_id')
                                                                                     or {}).get('password', '')
    auth_and_token_url: str = params.get('auth_id', '') or params.get('_auth_id', '') or (params.get('creds_auth_id')
                                                                                          or {}).get('password', '')
    enc_key: str = params.get('enc_key', '') or (params.get('credentials') or {}).get('password', '')
    server = params.get('url', '')
    base_url: str = urljoin(server, '/v1.0')
    endpoint = GRAPH_BASE_ENDPOINTS.get(server, 'com')
    app_name: str = 'ms-graph-mail'
    ok_codes: tuple = (200, 201, 202, 204)
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    certificate_thumbprint: str = params.get('certificate_thumbprint', '')
    private_key: str = params.get('private_key', '')

    if not self_deployed and not enc_key:
        raise DemistoException('Key must be provided. For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
    elif not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')
    if not auth_and_token_url:
        raise Exception('ID must be provided.')
    if not tenant_id:
        raise Exception('Token must be provided.')

    # params related to mailbox to fetch incidents
    mailbox_to_fetch = params.get('mailbox_to_fetch', '')
    folder_to_fetch = params.get('folder_to_fetch', 'Inbox')
    first_fetch_interval = params.get('first_fetch', '15 minutes')
    emails_fetch_limit = int(params.get('fetch_limit', '50'))
    timeout = arg_to_number(params.get('timeout', '10') or '10')
    display_full_email_body = argToBoolean(params.get("display_full_email_body", False))
    look_back = arg_to_number(params.get('look_back', 0))

    client: MsGraphClient = MsGraphClient(self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url,
                                          use_ssl, proxy, ok_codes, mailbox_to_fetch, folder_to_fetch,
                                          first_fetch_interval, emails_fetch_limit, timeout, endpoint,
                                          certificate_thumbprint=certificate_thumbprint,
                                          private_key=private_key,
                                          display_full_email_body=display_full_email_body,
                                          look_back=look_back
                                          )

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            client.ms_client.get_access_token()
            demisto.results('ok')
        if command == 'fetch-incidents':
            next_run, incidents = client.fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in ('msgraph-mail-list-emails', 'msgraph-mail-search-email'):
            list_mails_command(client, args)
        elif command == 'msgraph-mail-get-email':
            get_message_command(client, args)
        elif command == 'msgraph-mail-delete-email':
            delete_mail_command(client, args)
        elif command == 'msgraph-mail-list-attachments':
            list_attachments_command(client, args)
        elif command == 'msgraph-mail-get-attachment':
            get_attachment_command(client, args)
        elif command == 'msgraph-mail-list-folders':
            list_folders_command(client, args)
        elif command == 'msgraph-mail-list-child-folders':
            list_child_folders_command(client, args)
        elif command == 'msgraph-mail-create-folder':
            create_folder_command(client, args)
        elif command == 'msgraph-mail-update-folder':
            update_folder_command(client, args)
        elif command == 'msgraph-mail-delete-folder':
            delete_folder_command(client, args)
        elif command == 'msgraph-mail-move-email':
            move_email_command(client, args)
        elif command == 'msgraph-mail-get-email-as-eml':
            get_email_as_eml_command(client, args)
        elif command == 'msgraph-mail-create-draft':
            create_draft_command(client, args)
        elif command == 'msgraph-mail-reply-to':
            reply_to_command(client, args)  # pylint: disable=E1123
        elif command == 'msgraph-mail-send-draft':
            send_draft_command(client, args)  # pylint: disable=E1123
        elif command == 'send-mail':
            send_email_command(client, args)
        elif command == 'reply-mail':
            return_results(reply_email_command(client, args))
    # Log exceptions
    except Exception as e:
        return_error(str(e))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
