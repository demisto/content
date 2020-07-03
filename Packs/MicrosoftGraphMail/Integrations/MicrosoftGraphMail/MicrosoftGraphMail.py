import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Union, Optional

''' IMPORTS '''
import requests
import base64
import binascii

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

CONTEXT_FOLDER_PATH = 'MSGraphMail.Folders(val.ID && val.ID === obj.ID)'
CONTEXT_COPIED_EMAIL = 'MSGraphMail.MovedEmails(val.ID && val.ID === obj.ID)'
CONTEXT_DRAFT_PATH = 'MicrosoftGraph.Draft(val.ID && val.ID == obj.ID)'
CONTEXT_SENT_EMAIL_PATH = 'MicrosoftGraph.Email'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

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

    def __init__(self, self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url, use_ssl, proxy,
                 ok_codes, mailbox_to_fetch, folder_to_fetch, first_fetch_interval, emails_fetch_limit):

        self.ms_client = MicrosoftClient(self_deployed=self_deployed, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                         enc_key=enc_key, app_name=app_name, base_url=base_url, verify=use_ssl,
                                         proxy=proxy, ok_codes=ok_codes)

        self._mailbox_to_fetch = mailbox_to_fetch
        self._folder_to_fetch = folder_to_fetch
        self._first_fetch_interval = first_fetch_interval
        self._emails_fetch_limit = emails_fetch_limit

    def pages_puller(self, response: dict, page_count: int) -> list:
        """ Gets first response from API and returns all pages

        Args:
            response (dict):
            page_count (int):

        Returns:
            list: list of all pages
        """
        responses = [response]
        i = page_count
        while i != 0:
            next_link = response.get('@odata.nextLink')
            if next_link:
                responses.append(
                    self.ms_client.http_request('GET', full_url=next_link, url_suffix=None)
                )

            else:
                return responses
            i -= 1
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
        no_folder = f'/users/{user_id}/messages/'
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages/'
        pages_to_pull = demisto.args().get('pages_to_pull', 1)

        if search:
            odata = f'?{odata}$search={search}' if odata else f'?$search={search}'
        suffix = with_folder if folder_id else no_folder
        if odata:
            suffix += odata
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
        no_folder = f'/users/{user_id}/messages/{message_id}/attachments/{attachment_id}'
        with_folder = (f'/users/{user_id}/{build_folders_path(folder_id)}/'  # type: ignore
                       f'messages/{message_id}/attachments/{attachment_id}')
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
            suffix += odata
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
            b64_encoded_data, file_size, uploaded_file_name = read_file_and_encode64(attach_id)
            attachment = {
                '@odata.type': cls.FILE_ATTACHMENT,
                'contentBytes': b64_encoded_data.decode('utf-8'),
                'isInline': is_inline,
                'name': attach_name if provided_names else uploaded_file_name,
                'size': file_size
            }
            file_attachments_result.append(attachment)

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
                      internet_message_headers, attach_ids, attach_names, attach_cids, manual_attachments):
        """
        Builds valid message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        message = {
            'toRecipients': MsGraphClient._build_recipient_input(to_recipients),
            'ccRecipients': MsGraphClient._build_recipient_input(cc_recipients),
            'bccRecipients': MsGraphClient._build_recipient_input(bcc_recipients),
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
    def build_reply(to_recipients, comment):
        """
        Builds the reply message that includes recipients to reply and reply message.

        :type to_recipients: ``list``
        :param to_recipients: The recipients list to reply

        :type comment: ``str``
        :param comment: The message to reply.

        :return: Returns legal reply message.
        :rtype: ``dict``
        """
        return {
            'message': {
                'toRecipients': MsGraphClient._build_recipient_input(to_recipients)
            },
            'comment': comment
        }

    def _get_folder_children(self, user_id, folder_id):
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
        folder_children = self.ms_client.http_request('GET', suffix_endpoint).get('value', [])
        return folder_children

    def _get_folder_info(self, user_id, folder_id):
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
        folder_info = self.ms_client.http_request('GET', suffix_endpoint)
        if not folder_info:
            raise Exception(f'No info found for folder {folder_id}')
        return folder_info

    def _get_root_folder_children(self, user_id):
        """
        Get the root folder (Top Of Information Store) children collection.

        :type user_id: ``str``
        :param user_id: Mailbox address

        :raises: ``Exception``: No folders found under Top Of Information Store folder

        :return: List of root folder children
        rtype: ``list``
        """
        suffix_endpoint = f'/users/{user_id}/mailFolders/msgfolderroot/childFolders?$top=250'
        root_folder_children = self.ms_client.http_request('GET', suffix_endpoint).get('value', None)
        if not root_folder_children:
            raise Exception("No folders found under Top Of Information Store folder")

        return root_folder_children

    def _get_folder_by_path(self, user_id, folder_path):
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
                return self._get_folder_info(user_id, folder_id)
            else:
                current_directory_level_folders = self._get_folder_children(user_id, folder_id)
                folders_names.pop(0)  # remove the first folder name from the path before iterating
        else:  # in such case the optimization step is skipped
            # current_directory_level_folders will be set to folders that are under Top Of Information Store (root)
            current_directory_level_folders = self._get_root_folder_children(user_id)

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
            current_directory_level_folders = self._get_folder_children(user_id, found_folder.get('id', ''))

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
        target_modified_time = add_second_to_str_date(last_fetch)  # workaround to Graph API bug
        suffix_endpoint = (f"/users/{self._mailbox_to_fetch}/mailFolders/{folder_id}/messages"
                           f"?$filter=lastModifiedDateTime ge {target_modified_time}"
                           f"&$orderby=lastModifiedDateTime &$top={self._emails_fetch_limit}&select=*")
        fetched_emails = self.ms_client.http_request('GET', suffix_endpoint).get('value', [])[:self._emails_fetch_limit]

        if exclude_ids:  # removing emails in order to prevent duplicate incidents
            fetched_emails = [email for email in fetched_emails if email.get('id') not in exclude_ids]

        fetched_emails_ids = [email.get('id') for email in fetched_emails]
        return fetched_emails, fetched_emails_ids

    @staticmethod
    def _parse_item_as_dict(email):
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
        parsed_email = MsGraphClient._parse_item_as_dict(email)

        if email.get('hasAttachments', False):  # handling attachments of fetched email
            parsed_email['Attachments'] = self._get_email_attachments(message_id=email.get('id', ''))

        incident = {
            'name': parsed_email['Subject'],
            'details': email.get('bodyPreview', '') or parsed_email['Body'],
            'labels': MsGraphClient._parse_email_as_labels(parsed_email),
            'occurred': parsed_email['ModifiedTime'],
            'attachment': parsed_email.get('Attachments', []),
            'rawJSON': json.dumps(parsed_email)
        }

        return incident

    @staticmethod
    def _get_next_run_time(fetched_emails, start_time):
        """
        Returns modified time of last email if exist, else utc time that was passed as start_time.

        The elements in fetched emails are ordered by modified time in ascending order,
        meaning the last element has the latest modified time.

        :type fetched_emails: ``list``
        :param fetched_emails: List of fetched emails

        :type start_time: ``str``
        :param start_time: utc string of format Y-m-dTH:M:SZ

        :return: Returns str date of format Y-m-dTH:M:SZ
        :rtype: `str`
        """
        next_run_time = fetched_emails[-1].get('lastModifiedDateTime') if fetched_emails else start_time

        return next_run_time

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
        start_time = get_now_utc()
        last_fetch = last_run.get('LAST_RUN_TIME')
        exclude_ids = last_run.get('LAST_RUN_IDS', [])
        last_run_folder_path = last_run.get('LAST_RUN_FOLDER_PATH')
        folder_path_changed = (last_run_folder_path != self._folder_to_fetch)

        if folder_path_changed:
            # detected folder path change, get new folder id
            folder_id = self._get_folder_by_path(self._mailbox_to_fetch, self._folder_to_fetch).get('id')
            demisto.info("MS-Graph-Listener: detected file path change, ignored last run.")
        else:
            # LAST_RUN_FOLDER_ID is stored in order to avoid calling _get_folder_by_path method in each fetch
            folder_id = last_run.get('LAST_RUN_FOLDER_ID')

        if not last_fetch or folder_path_changed:  # initialized fetch
            last_fetch, _ = parse_date_range(self._first_fetch_interval, date_format=DATE_FORMAT, utc=True)
            demisto.info(f"MS-Graph-Listener: initialize fetch and pull emails from date :{last_fetch}")

        fetched_emails, fetched_emails_ids = self._fetch_last_emails(folder_id=folder_id, last_fetch=last_fetch,
                                                                     exclude_ids=exclude_ids)
        incidents = list(map(self._parse_email_as_incident, fetched_emails))
        next_run_time = MsGraphClient._get_next_run_time(fetched_emails, start_time)
        next_run = {
            'LAST_RUN_TIME': next_run_time,
            'LAST_RUN_IDS': fetched_emails_ids,
            'LAST_RUN_FOLDER_ID': folder_id,
            'LAST_RUN_FOLDER_PATH': self._folder_to_fetch
        }
        demisto.info(f"MS-Graph-Listener: fetched {len(incidents)} incidents")

        return next_run, incidents


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


def add_second_to_str_date(date_string, seconds=1):
    """
    Add seconds to date string.

    Is used as workaround to Graph API bug, for more information go to:
    https://stackoverflow.com/questions/35729273/office-365-graph-api-greater-than-filter-on-received-date

    :type date_string: ``str``
    :param date_string: Date string to add seconds

    :type seconds: int
    :param seconds: Seconds to add to date, by default is set to 1

    :return: Date time string appended seconds
    :rtype: ``str``
    """
    added_result = datetime.strptime(date_string, DATE_FORMAT) + timedelta(seconds=seconds)
    return datetime.strftime(added_result, DATE_FORMAT)


def get_now_utc():
    """
    Creates UTC current time of format Y-m-dTH:M:SZ (e.g. 2019-11-06T09:06:39Z)

    :return: String format of current UTC time
    :rtype: ``str``
    """
    return datetime.utcnow().strftime(DATE_FORMAT)


def read_file_and_encode64(attach_id):
    """
    Reads file that was uploaded to War Room and encodes it's content to base 64.

    :type attach_id: ``str``
    :param attach_id: The id of uploaded file to War Room

    :return: Base 64 encoded data, size of the encoded data in bytes and uploaded file name.
    :rtype: ``bytes``, ``int``, ``str``
    """
    try:
        file_info = demisto.getFilePath(attach_id)
        with open(file_info['path'], 'rb') as file_data:
            b64_encoded_data = base64.b64encode(file_data.read())
            file_size = os.path.getsize(file_info['path'])
            return b64_encoded_data, file_size, file_info['name']
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
        }

        contact_properties = {
            'Sender': 'sender',
            'From': 'from',
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
    if isinstance(raw_response, list):
        for page in raw_response:
            # raw_response can be a list containing multiple pages or one response
            # if value in page, we got
            value = page.get('value')
            if value:
                for mail in value:
                    mails_list.append(build_mail(mail))
            else:
                mails_list.append(build_mail(page))
    elif isinstance(raw_response, dict):
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


''' COMMANDS '''


def list_mails_command(client: MsGraphClient, args):
    search = args.get('search')
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    odata = args.get('odata')

    raw_response = client.list_mails(user_id, folder_id=folder_id, search=search, odata=odata)
    mail_context = build_mail_object(raw_response, user_id)
    entry_context = {'MSGraphMail(val.ID === obj.ID)': mail_context}

    # human_readable builder
    human_readable = tableToMarkdown(
        f'### Total of {len(mail_context)} of mails received',
        mail_context,
        headers=['Subject', 'From', 'SendTime']
    )
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


def get_attachment_command(client: MsGraphClient, args):
    message_id = args.get('message_id')
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    attachment_id = args.get('attachment_id')
    raw_response = client.get_attachment(message_id, user_id, folder_id=folder_id, attachment_id=attachment_id)
    entry_context = file_result_creator(raw_response)
    demisto.results(entry_context)


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
        headers=['ID', 'Subject', 'SendTime', 'Sender', 'From', 'HasAttachments', 'Body']
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
            'Name': attachment.get('name'),
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
        return {
            'to_recipients': argToList(args.get('to')),
            'cc_recipients': argToList(args.get('cc')),
            'bcc_recipients': argToList(args.get('bcc')),
            'subject': args.get('subject', ''),
            'body': args.get('body', ''),
            'body_type': args.get('bodyType', 'text'),
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
            'comment': args.get('body')
        }

    return args


def create_draft_command(client: MsGraphClient, args):
    """
    Creates draft message in user's mailbox, in draft folder.
    """
    prepared_args = prepare_args('create-draft', args)
    email = args.get('from')
    suffix_endpoint = f'/users/{email}/messages'
    draft = client.build_message(**prepared_args)

    created_draft = client.ms_client.http_request('POST', suffix_endpoint, json_data=draft)

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

    for recipients_dict in message_content.get('toRecipients', {}):
        to_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('ccRecipients', {}):
        cc_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('bccRecipients', {}):
        bcc_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    return to_recipients, cc_recipients, bcc_recipients


def send_email_command(client: MsGraphClient, args):
    """
    Sends email from user's mailbox, the sent message will appear in Sent Items folder
    """
    prepared_args = prepare_args('send-mail', args)
    email = args.get('from', client._mailbox_to_fetch)
    suffix_endpoint = f'/users/{email}/sendMail'
    message_content = MsGraphClient.build_message(**prepared_args)
    client.ms_client.http_request('POST', suffix_endpoint, json_data={'message': message_content}, resp_type="text")

    message_content.pop('attachments', None)
    message_content.pop('internet_message_headers', None)

    to_recipients, cc_recipients, bcc_recipients = build_recipients_human_readable(message_content)
    message_content['toRecipients'] = to_recipients
    message_content['ccRecipients'] = cc_recipients
    message_content['bccRecipients'] = bcc_recipients

    message_content = assign_params(**message_content)
    human_readable = tableToMarkdown('Email was sent successfully.', message_content)
    ec = {CONTEXT_SENT_EMAIL_PATH: message_content}

    return_outputs(human_readable, ec)


def reply_to_command(client: MsGraphClient, args):
    prepared_args = prepare_args('reply-to', args)

    to_recipients = prepared_args.get('to_recipients')
    message_id = prepared_args.get('message_id')
    comment = prepared_args.get('comment')
    email = args.get('from')

    suffix_endpoint = f'/users/{email}/messages/{message_id}/reply'
    reply = client.build_reply(to_recipients, comment)
    client.ms_client.http_request('POST', suffix_endpoint, json_data=reply, resp_type="text")

    return_outputs(f'### Replied to: {", ".join(to_recipients)} with comment: {comment}')


def send_draft_command(client: MsGraphClient, args):
    email = args.get('from')
    draft_id = args.get('draft_id')
    suffix_endpoint = f'/users/{email}/messages/{draft_id}/send'
    client.ms_client.http_request('POST', suffix_endpoint, resp_type="text")

    return_outputs(f'### Draft with: {draft_id} id was sent successfully.')


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    args: dict = demisto.args()
    params: dict = demisto.params()
    self_deployed: bool = params.get('self_deployed', False)
    tenant_id: str = params.get('tenant_id', '')
    auth_and_token_url: str = params.get('auth_id', '')
    enc_key: str = params.get('enc_key', '')
    base_url: str = urljoin(params.get('url', ''), '/v1.0')
    app_name: str = 'ms-graph-mail'
    ok_codes: tuple = (200, 201, 202, 204)
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    # params related to mailbox to fetch incidents
    mailbox_to_fetch = params.get('mailbox_to_fetch', '')
    folder_to_fetch = params.get('folder_to_fetch', 'Inbox')
    first_fetch_interval = params.get('first_fetch', '15 minutes')
    emails_fetch_limit = int(params.get('fetch_limit', '50'))

    client: MsGraphClient = MsGraphClient(self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url,
                                          use_ssl, proxy, ok_codes, mailbox_to_fetch, folder_to_fetch,
                                          first_fetch_interval, emails_fetch_limit)

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
    # Log exceptions
    except Exception as e:
        return_error(str(e))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
