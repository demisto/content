import binascii
import uuid
from urllib.parse import quote

from MicrosoftApiModule import *  # noqa: E402

API_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class MsGraphMailBaseClient(MicrosoftClient):
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """
    ITEM_ATTACHMENT = '#microsoft.graph.itemAttachment'
    FILE_ATTACHMENT = '#microsoft.graph.fileAttachment'
    # maximum attachment size to be sent through the api, files larger must be uploaded via upload session
    MAX_ATTACHMENT_SIZE = 3145728  # 3mb = 3145728 bytes
    MAX_FOLDERS_SIZE = 250
    DEFAULT_PAGE_SIZE = 20
    DEFAULT_PAGES_TO_PULL_NUM = 1

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

    def __init__(self, mailbox_to_fetch, folder_to_fetch, first_fetch_interval, emails_fetch_limit,
                 display_full_email_body: bool = False,
                 mark_fetched_read: bool = False,
                 look_back: int | None = 0,
                 fetch_html_formatting=True,
                 legacy_name=False,
                 **kwargs):
        super().__init__(retry_on_rate_limit=True, managed_identities_resource_uri=Resources.graph,
                         command_prefix="msgraph-mail",
                         **kwargs)
        self._mailbox_to_fetch = mailbox_to_fetch
        self._folder_to_fetch = folder_to_fetch
        self._first_fetch_interval = first_fetch_interval
        self._emails_fetch_limit = emails_fetch_limit
        self._display_full_email_body = display_full_email_body
        self._mark_fetched_read = mark_fetched_read
        self._look_back = look_back
        self.fetch_html_formatting = fetch_html_formatting
        self.legacy_name = legacy_name

    @classmethod
    def _build_inline_layout_attachments_input(cls, inline_from_layout_attachments):
        # Added requires_upload for handling the attachment in upload session
        file_attachments_result = []
        for attachment in inline_from_layout_attachments:
            file_attachments_result.append(
                {
                    'data': attachment.get('data'),
                    'isInline': True,
                    'name': attachment.get('name'),
                    'contentId': attachment.get('cid'),
                    'requires_upload': True,
                    'size': len(attachment.get('data')),
                })
        return file_attachments_result

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
            file_data, file_size, uploaded_file_name = GraphMailUtils.read_file(attach_id)
            file_name = attach_name if provided_names or not uploaded_file_name else uploaded_file_name
            if file_size < cls.MAX_ATTACHMENT_SIZE:  # if file is less than 3MB
                file_attachments_result.append(
                    {
                        '@odata.type': cls.FILE_ATTACHMENT,
                        'contentBytes': base64.b64encode(file_data).decode('utf-8'),
                        'isInline': is_inline,
                        'name': file_name,
                        'size': file_size,
                        'contentId': attach_id,
                    }
                )
            else:
                file_attachments_result.append(
                    {
                        'size': file_size,
                        'data': file_data,
                        'name': file_name,
                        'isInline': is_inline,
                        'requires_upload': True,
                        'contentId': attach_id
                    }
                )
        return file_attachments_result

    @staticmethod
    def upload_attachment(
        upload_url: str, start_chunk_idx: int, end_chunk_idx: int, chunk_data: bytes, attachment_size: int
    ) -> requests.Response:
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

    def _get_root_folder_children(self, user_id, overwrite_rate_limit_retry=False):
        """
        Get the root folder (Top Of Information Store) children collection.

        :type user_id: ``str``
        :param user_id: Mailbox address

        :raises: ``Exception``: No folders found under Top Of Information Store folder

        :return: List of root folder children
        rtype: ``list``
        """
        root_folder_id = 'msgfolderroot'
        if children := self._get_folder_children(user_id, root_folder_id, overwrite_rate_limit_retry):
            return children

        raise DemistoException("No folders found under Top Of Information Store folder")

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
        return self.http_request('GET',
                                 f'users/{user_id}/mailFolders/{folder_id}/childFolders?$top={self.MAX_FOLDERS_SIZE}',
                                 overwrite_rate_limit_retry=overwrite_rate_limit_retry).get('value', [])

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

        if folder_info := self.http_request('GET',
                                            f'users/{user_id}/mailFolders/{folder_id}',
                                            overwrite_rate_limit_retry=overwrite_rate_limit_retry):
            return folder_info

        raise DemistoException(f'No info found for folder {folder_id}')

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
        if folders_names[0].lower() in self.WELL_KNOWN_FOLDERS:
            # check if first folder in the path is known folder in order to skip not necessary api call
            folder_id = self.WELL_KNOWN_FOLDERS[folders_names[0].lower()]  # get folder shortcut instead of using folder id
            if len(folders_names) == 1:  # in such case the folder path consist only from one well known folder
                return self._get_folder_info(user_id, folder_id, overwrite_rate_limit_retry)

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
                raise DemistoException(f'No such folder exist: {folder_path}')
            found_folder = found_folder[0]  # found_folder will be list with only one element in such case

            if index == len(folders_names) - 1:  # reached the final folder in the path
                # skip get folder children step in such case
                return found_folder
            # didn't reach the end of the loop, set the current_directory_level_folders to folder children
            current_directory_level_folders = self._get_folder_children(user_id, found_folder.get('id', ''),
                                                                        overwrite_rate_limit_retry=overwrite_rate_limit_retry)
        return None

    def _get_email_attachments(self, message_id, user_id=None, overwrite_rate_limit_retry=False) -> list:
        """
        Get email attachments  and upload to War Room.

        :type message_id: ``str``
        :param message_id: The email id to get attachments

        :type user_id: ``str``
        :param user_id: The user id to get attachments from, if not provided - the mailbox_to_fetch will be used.

        :return: List of uploaded to War Room data, uploaded file path and name
        :rtype: ``list``
        """
        user_id = user_id or self._mailbox_to_fetch
        attachment_results: list = []
        attachments = self.http_request('Get',
                                        f'users/{user_id}/messages/{message_id}/attachments',
                                        overwrite_rate_limit_retry=overwrite_rate_limit_retry).get('value', [])

        for attachment in attachments:

            attachment_type = attachment.get('@odata.type', '')
            attachment_content_id = attachment.get('contentId')
            attachment_is_inline = attachment.get('isInline')
            attachment_name = attachment.get('name', 'untitled_attachment')
            if attachment_is_inline and not self.legacy_name and attachment_content_id and attachment_content_id != "None":
                attachment_name = f"{attachment_content_id}-attachmentName-{attachment_name}"
            if not attachment_name.isascii():
                try:
                    demisto.debug(f"Trying to decode the attachment file name: {attachment_name}")
                    attachment_name = b64_decode(attachment_name)  # type: ignore
                except Exception as e:
                    demisto.debug(f"Could not decode the {attachment_name=}: error: {e}")

            if attachment_type == self.FILE_ATTACHMENT:
                try:
                    attachment_content = b64_decode(attachment.get('contentBytes', ''))
                except Exception as e:  # skip the uploading file step
                    demisto.info(f"failed in decoding base64 file attachment with error {str(e)}")
                    continue
            elif attachment_type == self.ITEM_ATTACHMENT:
                attachment_id = attachment.get('id', '')
                attachment_content = self._get_attachment_mime(message_id, attachment_id, user_id, overwrite_rate_limit_retry)
                attachment_name = f'{attachment_name}.eml'
            else:
                # skip attachments that are not of the previous types (type referenceAttachment)
                continue
            # upload the item/file attachment to War Room
            demisto.debug(f"Uploading attachment file: {attachment_name=}, {attachment_content=}")
            GraphMailUtils.upload_file(attachment_name, attachment_content, attachment_results)

        demisto.debug(f"Final attachment results = {attachment_results}")
        return attachment_results

    def _get_attachment_mime(self, message_id, attachment_id, user_id=None, overwrite_rate_limit_retry=False):
        """
        Gets attachment mime.


        :type message_id: ``str``
        :param message_id: The email id to get attachments

        :type attachment_id: ``str``
        :param attachment_id: Attachment id to get MIME

        :type user_id: ``str``
        :param user_id: The user id to get attachments from, if not provided - the mailbox_to_fetch will be used.

        :return: The MIME of the attachment
        :rtype: ``str``
        """
        user_id = user_id or self._mailbox_to_fetch
        suffix_endpoint = f'users/{user_id}/messages/{message_id}/attachments/{attachment_id}/$value'
        return self.http_request('GET',
                                 suffix_endpoint,
                                 resp_type='text',
                                 overwrite_rate_limit_retry=overwrite_rate_limit_retry)

    def list_mails(self, user_id: str, folder_id: str = '', search: str = None, odata: str = None) -> dict | list:
        """Returning all mails from given user

        Args:
            user_id (str): the user id,
            folder_id (str): the folder id
            search (str):   plaintext search query
            odata (str):    odata-formatted query

        Returns:
            dict or list:   list of mails or dictionary when single item is returned
        """
        user_id = user_id or self._mailbox_to_fetch
        pages_to_pull = demisto.args().get('pages_to_pull', self.DEFAULT_PAGES_TO_PULL_NUM)
        page_size = demisto.args().get('page_size', self.DEFAULT_PAGE_SIZE)
        odata = f'{odata}&$top={page_size}' if odata else f'$top={page_size}'
        if search:
            # Data is being handled as a JSON so in cases the search phrase contains double quote ",
            # we should escape it.
            search = search.replace('"', '\\"')
            odata = f'{odata}&$search="{quote(search)}"'

        folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''
        suffix = f'/users/{user_id}{folder_path}/messages?{odata}'
        demisto.debug(f"URL suffix is {suffix}")
        response = self.http_request('GET', suffix)
        return self.pages_puller(response, GraphMailUtils.assert_pages(pages_to_pull))

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
        user_id = user_id or self._mailbox_to_fetch
        folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''
        suffix = f'/users/{user_id}{folder_path}/messages/{message_id}'

        if odata:
            suffix += f'?{odata}'
        response = self.http_request('GET', suffix)

        # Add user ID
        response['userId'] = user_id
        return response

    def delete_mail(self, user_id: str, message_id: str, folder_id: str = None) -> bool:
        """

        Args:
            user_id (str):
            message_id (str):
            folder_id (str):

        Returns:
            bool
        """
        user_id = user_id or self._mailbox_to_fetch
        folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''
        suffix = f'/users/{user_id}{folder_path}/messages/{message_id}'
        self.http_request('DELETE', suffix, resp_type="")
        return True

    def create_draft(self, from_email: str, json_data, reply_message_id: str = None) -> dict:
        """
        Create a draft message for either a new message or as a reply to an existing message.
        Args:
            from_email (str): email to create the draft from.
            json_data (dict): data to create the message with.
            reply_message_id (str): message ID in case creating a draft to an existing message.
        Returns:
            dict: api response information about the draft.
        """
        from_email = from_email or self._mailbox_to_fetch
        suffix = f'/users/{from_email}/messages'  # create draft for a new message
        if reply_message_id:
            suffix = f'{suffix}/{reply_message_id}/createReply'  # create draft for a reply to an existing message
        demisto.debug(f'{suffix=}')
        return self.http_request('POST', suffix, json_data=json_data)

    def send_mail(self, email, json_data):
        """
        Sends an email.
        Args:
            email (str): email to send the message from, if not provided - the mailbox_to_fetch will be used.
            json_data (dict): message data.
        """
        email = email or self._mailbox_to_fetch
        self.http_request(
            'POST', f'/users/{email}/sendMail', json_data={'message': json_data}, resp_type="text"
        )

    def send_reply(self, email_from, json_data, message_id):
        """
        Sends a reply email.
        Args:
            email_from (str): email to send the reply from.
            message_id (str): a message ID to reply to.
            json_data (dict): message body request.
        """
        email_from = email_from or self._mailbox_to_fetch
        self.http_request(
            'POST',
            f'/users/{email_from}/messages/{message_id}/reply',
            json_data=json_data,
            resp_type="text"
        )

    def send_draft(self, email: str, draft_id: str):
        """
        Sends a draft message.
        Args:
            email (str): email to send the draft from, if not provided - the mailbox_to_fetch will be used.
            draft_id (str): the ID of the draft to send.
        """
        email = email or self._mailbox_to_fetch
        self.http_request('POST', f'/users/{email}/messages/{draft_id}/send', resp_type='text')

    def list_attachments(self, user_id: str, message_id: str, folder_id: str | None = None) -> dict:
        """Listing all the attachments

        Args:
            user_id (str):      ID of a user to pull attachments from
            message_id (str):   ID of a message to pull attachments from
            folder_id (str):    ID of a folder to pull attachments from

        Returns:
            dict:
        """
        user_id = user_id or self._mailbox_to_fetch
        folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''
        suffix = f'/users/{user_id}{folder_path}/messages/{message_id}/attachments/'
        return self.http_request('GET', suffix)

    def get_attachment(self, message_id: str, user_id: str = None, attachment_id: str = None, folder_id: str = None) -> list:
        """Get the attachment represented by the attachment_id from the API
        In case not supplied, the command will return all the attachments.

        Args:
            message_id (str): The message ID to get attachments from
            user_id (str, optional): The User ID, if not provided - the mailbox_to_fetch will be used
            attachment_id (str, optional): The attachment id. Defaults to None.
            folder_id (str, optional): The folder ID. Defaults to None.

        Returns:
            list: List contained the attachment represented by the attachment_id from the API
            or all the attachments if not attachment_id was provided.
        """
        user_id = user_id or self._mailbox_to_fetch
        folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''
        attachment_id_path = f'/{attachment_id}/?$expand=microsoft.graph.itemattachment/item' if attachment_id else ''
        suffix = f'/users/{user_id}{folder_path}/messages/{message_id}/attachments{attachment_id_path}'

        demisto.debug(f'Getting attachment with suffix: {suffix}')

        response = self.http_request('GET', suffix)
        return [response] if attachment_id else response.get('value', [])

    def create_folder(self, user_id: str, new_folder_name: str, parent_folder_id: str = None) -> dict:
        """Create folder under specified folder with given display name

        Args:
            user_id (str): The User ID, if not provided - the mailbox_to_fetch will be used
            new_folder_name (str): Created folder display name
            parent_folder_id (str): Parent folder id under where created new folder

        Returns:
            dict: Created folder data
        """
        user_id = user_id or self._mailbox_to_fetch
        suffix = f'/users/{user_id}/mailFolders'
        if parent_folder_id:
            suffix += f'/{parent_folder_id}/childFolders'

        json_data = {'displayName': new_folder_name}
        return self.http_request('POST', suffix, json_data=json_data)

    def update_folder(self, user_id: str, folder_id: str, new_display_name: str) -> dict:
        """Update folder under specified folder with new display name

        Args:
            user_id (str): The User ID, if not provided - the mailbox_to_fetch will be used
            folder_id (str): Folder id to update
            new_display_name (str): New display name of updated folder

        Returns:
            dict: Updated folder data
        """

        suffix = f'/users/{user_id}/mailFolders/{folder_id}'
        json_data = {'displayName': new_display_name}
        return self.http_request('PATCH', suffix, json_data=json_data)

    def list_folders(self, user_id: str, limit: str = '20') -> dict:
        """List folder under root folder (Top of information store)

        Args:
            user_id (str): User id or mailbox address, if not provided - the mailbox_to_fetch will be used
            limit (str): Limit number of returned folder collection

        Returns:
            dict: Collection of folders under root folder
        """
        user_id = user_id or self._mailbox_to_fetch
        suffix = f'/users/{user_id}/mailFolders?$top={limit}'
        return self.http_request('GET', suffix)

    def list_child_folders(self, user_id: str, parent_folder_id: str, limit: str = '20') -> list:
        """List child folder under specified folder.

        Args:
            user_id (str): User id or mailbox address, if not provided - the mailbox_to_fetch will be used
            parent_folder_id (str): Parent folder id
            limit (str): Limit number of returned folder collection

        Returns:
            list: Collection of folders under specified folder
        """
        # for additional info regarding OData query https://docs.microsoft.com/en-us/graph/query-parameters
        user_id = user_id or self._mailbox_to_fetch
        suffix = f'/users/{user_id}/mailFolders/{parent_folder_id}/childFolders?$top={limit}'
        return self.http_request('GET', suffix)

    def delete_folder(self, user_id: str, folder_id: str):
        """Deletes folder under specified folder

        Args:
            user_id (str): User id or mailbox address
            folder_id (str): Folder id to delete
        """

        suffix = f'/users/{user_id}/mailFolders/{folder_id}'
        return self.http_request('DELETE', suffix, resp_type="")

    def move_email(self, user_id: str, message_id: str, destination_folder_id: str) -> dict:
        """Moves email to destination folder

        Args:
            user_id (str): User id or mailbox address, if not provided - the mailbox_to_fetch will be used
            message_id (str): The message id to move
            destination_folder_id (str): Destination folder id

        Returns:
            dict: Moved email data
        """
        user_id = user_id or self._mailbox_to_fetch
        suffix = f'/users/{user_id}/messages/{message_id}/move'
        json_data = {'destinationId': destination_folder_id}
        return self.http_request('POST', suffix, json_data=json_data)

    def get_email_as_eml(self, user_id: str, message_id: str) -> str:
        """Returns MIME content of specified message

        Args:
            user_id (str): User id or mailbox address, if not provided - the mailbox_to_fetch will be used
            message_id (str): The message id of the email

        Returns:
            str: MIME content of the email
        """
        user_id = user_id or self._mailbox_to_fetch
        suffix = f'/users/{user_id}/messages/{message_id}/$value'
        return self.http_request('GET', suffix, resp_type='text')

    def update_email_read_status(self, user_id: str, message_id: str, read: bool,
                                 folder_id: str | None = None) -> dict:
        """
        Update the status of an email to read / unread.

        Args:
            user_id (str): User id or mailbox address, if not provided - the mailbox_to_fetch will be used
            message_id (str): Message id to mark as read/unread
            folder_id (str): Folder id to update
            read (bool): Whether to mark the email as read or unread. True for read, False for unread.

        Returns:
            dict: API response
        """
        user_id = user_id or self._mailbox_to_fetch
        folder_path = f'/{GraphMailUtils.build_folders_path(folder_id)}' if folder_id else ''

        return self.http_request(
            method='PATCH',
            url_suffix=f'/users/{user_id}{folder_path}/messages/{message_id}',
            json_data={'isRead': read},
        )

    def pages_puller(self, response: dict, page_count: int) -> list:
        """ Gets first response from API and returns all pages

        Args:
            response (dict):        raw http response data
            page_count (int):       amount of pages

        Returns:
            list: list of all pages
        """
        responses = [response]
        for _i in range(page_count - 1):
            next_link = response.get('@odata.nextLink')
            if next_link:
                response = self.http_request('GET', full_url=next_link, url_suffix=None)
                responses.append(response)
            else:
                return responses
        return responses

    def test_connection(self):
        if self._mailbox_to_fetch:
            self.http_request('GET', f'/users/{self._mailbox_to_fetch}/messages?$top=1')
        else:
            self.get_access_token()
        return 'ok'

    def add_attachments_via_upload_session(self, email: str, draft_id: str, attachments: list[dict]):
        """
        Add attachments using an upload session by dividing the file bytes into chunks and sent each chunk each time.
        more info here - https://docs.microsoft.com/en-us/graph/outlook-large-attachments?tabs=http
        Args:
            email (str): email to create the upload session.
            draft_id (str): draft ID to add the attachments to.
            attachments (list[dict]) : attachments to add to the draft message.
        """
        email = email or self._mailbox_to_fetch
        for attachment in attachments:
            self.add_attachment_with_upload_session(
                email=email,
                draft_id=draft_id,
                attachment_data=attachment.get('data', ''),
                attachment_name=attachment.get('name', ''),
                is_inline=attachment.get('isInline', False),
                content_id=attachment.get('contentId', None)
            )

    def get_upload_session(self, email: str, draft_id: str, attachment_name: str, attachment_size: int, is_inline: bool,
                           content_id=None) -> dict:
        """
        Create an upload session for a specific draft ID.
        Args:
            email (str): email to create the upload session.
            draft_id (str): draft ID to add the attachments to.
            attachment_size (int) : attachment size (in bytes).
            attachment_name (str): attachment name.
            is_inline (bool): is the attachment inline, True if yes, False if not.
        """
        json_data = {
            'attachmentItem': {
                'attachmentType': 'file',
                'name': attachment_name,
                'size': attachment_size,
                'isInline': is_inline
            }
        }
        if content_id:
            json_data['attachmentItem']['contentId'] = content_id
        return self.http_request(
            'POST',
            f'/users/{email}/messages/{draft_id}/attachments/createUploadSession',
            json_data=json_data
        )

    def add_attachment_with_upload_session(self, email: str, draft_id: str, attachment_data: bytes,
                                           attachment_name: str, is_inline: bool = False, content_id=None):
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
        upload_session = self.get_upload_session(
            email=email,
            draft_id=draft_id,
            attachment_name=attachment_name,
            attachment_size=attachment_size,
            is_inline=is_inline,
            content_id=content_id
        )
        upload_url = upload_session.get('uploadUrl')
        if not upload_url:
            raise Exception(f'Cannot get upload URL for attachment {attachment_name}')

        start_chunk_index = 0
        # The if is for adding functionality of inline attachment sending from layout
        end_chunk_index = attachment_size if attachment_size < self.MAX_ATTACHMENT_SIZE else self.MAX_ATTACHMENT_SIZE

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

    def send_mail_with_upload_session_flow(self, email: str, json_data: dict,
                                           attachments_more_than_3mb: list[dict], reply_message_id: str = None):
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
        email = email or self._mailbox_to_fetch
        created_draft = self.create_draft(from_email=email, json_data=json_data, reply_message_id=reply_message_id)
        draft_id = created_draft.get('id', '')
        self.add_attachments_via_upload_session(  # add attachments via upload session.
            email=email, draft_id=draft_id, attachments=attachments_more_than_3mb
        )
        self.send_draft(email=email, draft_id=draft_id)  # send the draft email

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
        demisto.debug(f'Fetching emails since {last_fetch}')
        fetched_emails = self.get_emails(exclude_ids=exclude_ids, last_fetch=last_fetch,
                                         folder_id=folder_id, overwrite_rate_limit_retry=True,
                                         mark_emails_as_read=self._mark_fetched_read)

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

    def get_emails_from_api(self, folder_id: str, last_fetch: str, limit: int,
                            body_as_text: bool = True,
                            overwrite_rate_limit_retry: bool = False):
        headers = {"Prefer": "outlook.body-content-type='text'"} if body_as_text else None
        # Adding the "$" sign to the select filter results in the 'internetMessageHeaders' field not being contained
        # within the response, (looks like a bug in graph API).
        return self.http_request(
            method='GET',
            url_suffix=f'/users/{self._mailbox_to_fetch}/mailFolders/{folder_id}/messages',
            params={
                '$filter': f'receivedDateTime ge {GraphMailUtils.add_second_to_str_date(last_fetch)}',
                '$orderby': 'receivedDateTime asc',
                'select': '*',
                '$top': limit
            },
            headers=headers,
            overwrite_rate_limit_retry=overwrite_rate_limit_retry,
        ).get('value', [])

    def get_emails(self, exclude_ids, last_fetch, folder_id, overwrite_rate_limit_retry=False,
                   mark_emails_as_read: bool = False) -> list:

        emails_as_html = self.get_emails_from_api(folder_id,
                                                  last_fetch,
                                                  body_as_text=False,
                                                  limit=len(exclude_ids) + self._emails_fetch_limit,  # fetch extra incidents
                                                  overwrite_rate_limit_retry=overwrite_rate_limit_retry)

        emails_as_text = self.get_emails_from_api(folder_id,
                                                  last_fetch,
                                                  limit=len(exclude_ids) + self._emails_fetch_limit,  # fetch extra incidents
                                                  overwrite_rate_limit_retry=overwrite_rate_limit_retry)

        if mark_emails_as_read:
            for email in emails_as_html:
                if email.get('id'):
                    self.update_email_read_status(
                        user_id=self._mailbox_to_fetch,
                        message_id=email["id"],
                        read=True,
                        folder_id=folder_id)

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
                email_as_html['body'] = [body_as_html, body_as_text]

            unique_body_as_text = text_email_data.get('uniqueBody')
            if unique_body_as_html := email_as_html.get('uniqueBody'):
                email_as_html['uniqueBody'] = [unique_body_as_html, unique_body_as_text]

            emails_as_html_and_text.append(email_as_html)

        return emails_as_html_and_text

    @staticmethod
    def get_email_content_as_text_and_html(email):
        email_body: tuple = email.get('body') or ()  # email body including replyTo emails.
        email_unique_body: tuple = email.get('uniqueBody') or ()  # email-body without replyTo emails.

        # there are situations where the 'body' key won't be returned from the api response, hence taking the uniqueBody
        # in those cases for both html/text formats.
        try:
            email_content_as_html, email_content_as_text = email_body or email_unique_body
        except ValueError:
            demisto.info(f'email body content is missing from email {email}')
            return '', ''

        return email_content_as_html.get('content'), email_content_as_text.get('content')

    def _parse_email_as_incident(self, email, overwrite_rate_limit_retry=False):
        """
        Parses fetched emails as incidents.

        :type email: ``dict``
        :param email: Fetched email to parse

        :return: Parsed email
        :rtype: ``dict``
        """
        # there are situations where the 'body' key won't be returned from the api response, hence taking the uniqueBody
        # in those cases for both html/text formats.

        def body_extractor(email, parsed_email):
            email_content_as_html, email_content_as_text = self.get_email_content_as_text_and_html(email)
            parsed_email['Body'] = email_content_as_html if self.fetch_html_formatting else email_content_as_text
            parsed_email['Text'] = email_content_as_text
            parsed_email['BodyType'] = 'html' if self.fetch_html_formatting else 'text'

        parsed_email = GraphMailUtils.parse_item_as_dict(email, body_extractor)

        # handling attachments of fetched email
        attachments = self._get_email_attachments(
            message_id=email.get('id', ''),
            overwrite_rate_limit_retry=overwrite_rate_limit_retry
        )
        if attachments:
            parsed_email['Attachments'] = attachments

        parsed_email['Mailbox'] = self._mailbox_to_fetch

        body = email.get('bodyPreview', '')
        if not body or self._display_full_email_body:
            _, body = self.get_email_content_as_text_and_html(email)

        incident = {
            'name': parsed_email.get('Subject'),
            'details': body,
            'labels': GraphMailUtils.parse_email_as_labels(parsed_email),
            'occurred': parsed_email.get('ReceivedTime'),
            'attachment': parsed_email.get('Attachments', []),
            'rawJSON': json.dumps(parsed_email),
            'ID': parsed_email.get('ID')  # only used for look-back to identify the email in a unique way
        }

        return incident

    def message_rules_action(self, action, user_id=None, rule_id=None, limit=50):
        """
        get/delete message rule action
        """
        if action != "DELETE":
            return_empty_response = False
            params = {'$top': limit}
        else:
            return_empty_response = True
            params = {}
            if rule_id is None:
                raise ValueError("rule_id is required in order to delete the rule")

        url = f"{f'/users/{user_id}' if user_id else '/me'}/mailFolders/inbox/messageRules{f'/{rule_id}' if rule_id else ''}"
        return self.http_request(action.upper(), url, return_empty_response=return_empty_response, params=params)


# HELPER FUNCTIONS
class GraphMailUtils:

    FOLDER_MAPPING = {
        'id': 'ID',
        'displayName': 'DisplayName',
        'parentFolderId': 'ParentFolderID',
        'childFolderCount': 'ChildFolderCount',
        'unreadItemCount': 'UnreadItemCount',
        'totalItemCount': 'TotalItemCount'
    }

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
        'internetMessageId': 'MessageID',
        'categories': 'Categories',
    }

    @staticmethod
    def read_file(attach_id: str) -> tuple[bytes, int, str]:
        """
        Reads file that was uploaded to War Room.

        :type attach_id: ``str``
        :param attach_id: The id of uploaded file to War Room

        :return: data, size of the file in bytes and uploaded file name.
        :rtype: ``bytes``, ``int``, ``str``
        """
        try:
            file_info = demisto.getFilePath(attach_id)
            with open(file_info['path'], 'rb') as file_data:
                data = file_data.read()
                file_size = os.path.getsize(file_info['path'])
                return data, file_size, file_info['name']
        except Exception as e:
            raise Exception(f'Unable to read file with id {attach_id}', e)

    @staticmethod
    def build_folders_path(folder_string: str) -> str | None:
        """

        Args:
            folder_string (str): string with `,` delimiter. first one is mailFolders all other are child

        Returns:
            str or None:  string with path to the folder and child folders
        """
        if not folder_string:
            return None
        folders_list = argToList(folder_string, ',')
        path = f'mailFolders/{folders_list[0]}'
        for folder in folders_list[1:]:
            path += f'/childFolders/{folder}'
        return path

    @staticmethod
    def build_mail_object(raw_response: dict | list, get_body: bool = False, user_id: str = None) -> dict | list:
        """Building mail entry context
        Getting a list from GraphMailUtils.build_mail_object

        Args:
            raw_response (dict or list): list of pages
            get_body (bool): should get body
            user_id (str): user id of the mail

        Returns:
            dict or list: output context
        """

        def build_mail(given_mail: dict) -> dict:
            """

            Args:
                given_mail (dict):  Mail Data

            Returns:
                dict: Transformed mail data
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
            if user_id:
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

        mails_list = []
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

    @staticmethod
    def handle_html(htmlBody):
        """
        Extract all data-url content from within the html and return as separate attachments.
        Due to security implications, we support only images here
        We might not have Beautiful Soup so just do regex search
        """
        attachments = []
        cleanBody = ''
        if htmlBody:
            lastIndex = 0
            for i, m in enumerate(
                re.finditer(  # pylint: disable=E1101
                    r'<img.+?src=\"(data:(image\/.+?);base64,([a-zA-Z0-9+/=\r\n]+?))\"',
                    htmlBody,
                    re.I | re.S  # pylint: disable=E1101
                )
            ):
                maintype, subtype = m.group(2).split('/', 1)
                name = f"image{i}.{subtype}"
                att = {
                    'maintype': maintype,
                    'subtype': subtype,
                    'data': b64_decode(m.group(3)),
                    'name': name,
                    'cid': f'{name}@{str(uuid.uuid4())[:8]}_{str(uuid.uuid4())[:8]}',
                }
                attachments.append(att)
                cleanBody += htmlBody[lastIndex:m.start(1)] + 'cid:' + att['cid']
                lastIndex = m.end() - 1

            cleanBody += htmlBody[lastIndex:]
        return cleanBody, attachments

    @staticmethod
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
            email_body, inline_attachments = GraphMailUtils.handle_html(
                args.get('htmlBody')) if args.get('htmlBody', None) else (args.get('body', ''), [])
            processed_args = {
                'to_recipients': argToList(args.get('to')),
                'cc_recipients': argToList(args.get('cc')),
                'bcc_recipients': argToList(args.get('bcc')),
                'reply_to': argToList(args.get('replyTo') or args.get('reply_to')),
                'subject': args.get('subject', ''),
                'body': email_body,
                'body_type': args.get('bodyType') or args.get('body_type') or 'html',
                'flag': args.get('flag', 'notFlagged'),
                'importance': args.get('importance', 'Low'),
                'internet_message_headers': argToList(args.get('headers')),
                'attach_ids': argToList(args.get('attachIDs') or args.get('attach_ids')),
                'attach_names': argToList(args.get('attachNames') or args.get('attach_names')),
                'attach_cids': argToList(args.get('attachCIDs') or args.get('attach_cids')),
                'manual_attachments': args.get('manualAttachObj', []),
                'inline_attachments': inline_attachments or []
            }
            if command == 'send-mail':
                processed_args['renderBody'] = argToBoolean(args.get('renderBody') or False)
            return processed_args

        elif command == 'reply-to':
            return {
                'to_recipients': argToList(args.get('to')),
                'message_id': GraphMailUtils.handle_message_id(args.get('ID') or args.get('message_id') or ''),
                'comment': args.get('body') or args.get('comment'),
                'attach_ids': argToList(args.get('attachIDs') or args.get('attach_ids')),
                'attach_names': argToList(args.get('attachNames') or args.get('attach_names')),
                'attach_cids': argToList(args.get('attachCIDs') or args.get('attach_cids'))
            }

        elif command == 'get-message':
            return {
                'user_id': args.get('user_id'),
                'folder_id': args.get('folder_id'),
                'message_id': GraphMailUtils.handle_message_id(args.get('message_id', '')),
                'odata': args.get('odata')
            }

        return args

    @staticmethod
    def divide_attachments_according_to_size(attachments=[]):
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

    @staticmethod
    def assert_pages(pages: str | int) -> int:
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

    @staticmethod
    def item_result_creator(raw_attachment, user_id, args, client) -> dict[str, Any] | CommandResults:
        """
        Create a result object for an attachment item.
        This method processes raw attachment data and returns either an XSOAR file result or a command result
        based on the attachment type and provided arguments.

        Args:
            raw_attachment (dict): The raw attachment data from the API response.
            user_id (str): The ID of the user associated with the attachment.
            args (dict): Additional arguments for processing the attachment.
            client (MsGraphMailBaseClient, optional): The client instance for making additional API calls.

        Returns:
            dict[str, Any] | CommandResults:
                - If the attachment is a message and should be downloaded, returns a dict containing file result.
                - If the attachment is a message but should not be downloaded, returns a CommandResults with message details.
                - If the attachment is of an unsupported type, returns a CommandResults with an error message.

        Note:
            - The method handles different types of attachments, particularly focusing on message attachments.
              It can either return the attachment as a downloadable file or as structured data in the command results.
            - 'client' function argument is only relevant when 'should_download_message_attachment' command argument is True.
        """
        item = raw_attachment.get('item', {})
        item_type = item.get('@odata.type', '')
        if 'message' in item_type:
            return_message_attachment_as_downloadable_file: bool = client and argToBoolean(
                args.get('should_download_message_attachment', False))
            if return_message_attachment_as_downloadable_file:
                # return the message attachment as a file result
                attachment_content = client._get_attachment_mime(
                    GraphMailUtils.handle_message_id(args.get('message_id', '')),
                    args.get('attachment_id'),
                    user_id, False)
                attachment_name: str = (item.get("name") or item.get('subject')
                                        or "untitled_attachment").replace(' ', '_') + '.eml'
                demisto.debug(f'Email attachment of type "microsoft.graph.message" acquired successfully, {attachment_name=}')
                return fileResult(attachment_name, attachment_content)
            else:
                # return the message attachment as a command result
                message_id = raw_attachment.get('id')
                item['id'] = message_id
                mail_context = GraphMailUtils.build_mail_object(item, user_id=user_id, get_body=True)
                human_readable = tableToMarkdown(
                    f'Attachment ID {message_id} \n **message details:**',
                    mail_context,
                    headers=['ID', 'Subject', 'SendTime', 'Sender', 'From', 'HasAttachments', 'Body']
                )

                return CommandResults(outputs_prefix='MSGraphMail',
                                      outputs_key_field='ID',
                                      outputs=mail_context,
                                      readable_output=human_readable,
                                      raw_response=raw_attachment)
        else:
            human_readable = f'Integration does not support attachments from type {item_type}'
            return CommandResults(readable_output=human_readable, raw_response=raw_attachment)

    @staticmethod
    def file_result_creator(raw_attachment: dict, legacy_name=False) -> dict:
        """Create FileResult from the attachment

        Args:
            raw_attachment (dict): The attachments from the API

        Raises:
            DemistoException: if the decoded fail, raise DemistoException

        Returns:
            dict: FileResult with the b64decode of the attachment content
        """
        name = raw_attachment.get('name', '')
        content_id = raw_attachment.get('contentId')
        is_inline = raw_attachment.get('isInline')
        if is_inline and content_id and content_id != "None" and not legacy_name:
            name = f"{content_id}-attachmentName-{name}"
        data = raw_attachment.get('contentBytes')
        try:
            data = b64_decode(data)  # type: ignore
            return fileResult(name, data)
        except binascii.Error:
            raise DemistoException('Attachment could not be decoded')

    @staticmethod
    def create_attachment(raw_attachment, user_id, args, client, legacy_name=False) -> CommandResults | dict:
        attachment_type = raw_attachment.get('@odata.type', '')
        # Documentation about the different attachment types
        # https://docs.microsoft.com/en-us/graph/api/attachment-get?view=graph-rest-1.0&tabs=http
        if 'itemAttachment' in attachment_type:
            return GraphMailUtils.item_result_creator(raw_attachment, user_id, args, client)
        elif 'fileAttachment' in attachment_type:
            return GraphMailUtils.file_result_creator(raw_attachment, legacy_name)
        else:
            human_readable = f'Integration does not support attachments from type {attachment_type}'
            return CommandResults(readable_output=human_readable, raw_response=raw_attachment)

    @staticmethod
    def parse_folders_list(folders_list):
        if isinstance(folders_list, dict):
            folders_list = [folders_list]

        return [
            {parsed_key: f.get(response_key) for (response_key, parsed_key) in GraphMailUtils.FOLDER_MAPPING.items()}
            for f in folders_list
        ]

    @staticmethod
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

    @staticmethod
    def prepare_outputs_for_reply_mail_command(reply, email_to, message_id):
        reply.pop('attachments', None)
        to_recipients, cc_recipients, bcc_recipients, reply_to_recipients = GraphMailUtils.build_recipients_human_readable(reply)
        reply['toRecipients'] = to_recipients
        reply['ccRecipients'] = cc_recipients
        reply['bccRecipients'] = bcc_recipients
        reply['replyTo'] = reply_to_recipients
        reply['ID'] = message_id

        message_content = assign_params(**reply)
        human_readable = tableToMarkdown(f'Replied message was successfully sent to {", ".join(email_to)} .',
                                         message_content)

        return CommandResults(
            outputs_prefix="MicrosoftGraph.SentMail",
            readable_output=human_readable,
            outputs_key_field="ID",
            outputs=message_content,
        )

    @staticmethod
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
        added_result = datetime.strptime(date_string, API_DATE_FORMAT) + timedelta(seconds=seconds)
        return datetime.strftime(added_result, API_DATE_FORMAT)

    @staticmethod
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
            raise DemistoException(file_result['Contents'])

        attachments_list.append({
            'path': file_result['FileID'],
            'name': file_result['File']
        })

    @staticmethod
    def parse_item_as_dict(email, body_extractor=None):
        """
        Parses basic data of email.

        Additional info https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0

        :type email: ``dict``
        :param email: Email to parse

        :type body_extractor: ``function``
        :param body_extractor: Optional function to parse the body in different way

        :return: Parsed email
        :rtype: ``dict``
        """
        parsed_email = {
            parsed_key: email.get(orig_key)
            for (orig_key, parsed_key) in GraphMailUtils.EMAIL_DATA_MAPPING.items()
        }
        parsed_email['Headers'] = email.get('internetMessageHeaders', [])
        parsed_email['Sender'] = GraphMailUtils.get_recipient_address(email.get('sender', {}))
        parsed_email['From'] = GraphMailUtils.get_recipient_address(email.get('from', {}))
        parsed_email['To'] = list(map(GraphMailUtils.get_recipient_address, email.get('toRecipients', [])))
        parsed_email['Cc'] = list(map(GraphMailUtils.get_recipient_address, email.get('ccRecipients', [])))
        parsed_email['Bcc'] = list(map(GraphMailUtils.get_recipient_address, email.get('bccRecipients', [])))

        if body_extractor:
            body_extractor(email, parsed_email)
        else:
            email_body = email.get('body', {}) or email.get('uniqueBody', {})
            parsed_email['Body'] = email_body.get('content', '')
            parsed_email['BodyType'] = email_body.get('contentType', '')

        return parsed_email

    @staticmethod
    def parse_email_as_labels(parsed_email):
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
                    {'type': f"Email/Header/{header.get('name', '')}", 'value': header.get('value', '')}
                    for header in value]
                labels.extend(headers_labels)
            elif key in ['To', 'Cc', 'Bcc']:
                recipients_labels = [{'type': f'Email/{key}', 'value': recipient} for recipient in value]
                labels.extend(recipients_labels)
            else:
                labels.append({'type': f'Email/{key}', 'value': f'{value}'})

        return labels

    @staticmethod
    def get_recipient_address(email_address):
        """
        Receives dict of form  "emailAddress":{"name":"_", "address":"_"} and return the address

        :type email_address: ``dict``
        :param email_address: Recipient address

        :return: The address of recipient
        :rtype: ``str``
        """
        return email_address.get('emailAddress', {}).get('address', '')

    @staticmethod
    def build_recipient_input(recipients):
        """
        Builds legal recipients list.

        :type recipients: ``list``
        :param recipients: List of recipients

        :return: List of email addresses recipients
        :rtype: ``list``
        """
        return [{'emailAddress': {'address': r}} for r in recipients] if recipients else []

    @staticmethod
    def build_body_input(body, body_type):
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
    def build_flag_input(flag):
        """
        Builds flag status of the message.

        :type flag: ``str``
        :param flag: The flag of the message

        :return: The flag status of the message
        :rtype ``dict``
        """
        return {'flagStatus': flag}

    @staticmethod
    def build_file_attachments_input(attach_ids,
                                     attach_names,
                                     attach_cids,
                                     manual_attachments,
                                     inline_attachments_from_layout=[]):
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
        regular_attachments = MsGraphMailBaseClient._build_attachments_input(ids=attach_ids, attach_names=attach_names)
        inline_attachments = MsGraphMailBaseClient._build_attachments_input(ids=attach_cids, is_inline=True)
        # collecting manual attachments info
        manual_att_ids = [os.path.basename(att['RealFileName']) for att in manual_attachments if 'RealFileName' in att]
        manual_att_names = [att['FileName'] for att in manual_attachments if 'FileName' in att]
        manual_report_attachments = MsGraphMailBaseClient._build_attachments_input(ids=manual_att_ids,
                                                                                   attach_names=manual_att_names)
        inline_from_layout_attachments = MsGraphMailBaseClient._build_inline_layout_attachments_input(
            inline_attachments_from_layout)

        return regular_attachments + inline_attachments + manual_report_attachments + inline_from_layout_attachments

    @staticmethod
    def build_headers_input(internet_message_headers):
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
                      internet_message_headers, attach_ids, attach_names, attach_cids, manual_attachments, reply_to,
                      inline_attachments=[]):
        """
        Builds valid message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        message = {
            'toRecipients': GraphMailUtils.build_recipient_input(to_recipients),
            'ccRecipients': GraphMailUtils.build_recipient_input(cc_recipients),
            'bccRecipients': GraphMailUtils.build_recipient_input(bcc_recipients),
            'replyTo': GraphMailUtils.build_recipient_input(reply_to),
            'subject': subject,
            'body': GraphMailUtils.build_body_input(body=body, body_type=body_type),
            'bodyPreview': body[:255],
            'importance': importance,
            'flag': GraphMailUtils.build_flag_input(flag),
            'attachments': GraphMailUtils.build_file_attachments_input(attach_ids, attach_names, attach_cids,
                                                                       manual_attachments, inline_attachments)
        }

        if internet_message_headers:
            message['internetMessageHeaders'] = GraphMailUtils.build_headers_input(internet_message_headers)

        return message

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
                'toRecipients': GraphMailUtils.build_recipient_input(to_recipients),
                'attachments': GraphMailUtils.build_file_attachments_input(attach_ids, attach_names, attach_cids, [])
            },
            'comment': comment
        }

    @staticmethod
    def build_message_to_reply(to_recipients, cc_recipients, bcc_recipients, subject, email_body, attach_ids,
                               attach_names, attach_cids, reply_to):
        """
        Builds a valid reply message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        return {
            'toRecipients': GraphMailUtils.build_recipient_input(to_recipients),
            'ccRecipients': GraphMailUtils.build_recipient_input(cc_recipients),
            'bccRecipients': GraphMailUtils.build_recipient_input(bcc_recipients),
            'replyTo': GraphMailUtils.build_recipient_input(reply_to),
            'subject': subject,
            'bodyPreview': email_body[:255],
            'attachments': GraphMailUtils.build_file_attachments_input(attach_ids, attach_names, attach_cids, [])
        }

    @staticmethod
    def handle_message_id(message_id: str) -> str:
        """
        Handle a Microsoft Graph API message ID by replacing forward slashes with hyphens.
        """
        if '/' in message_id:
            message_id = message_id.replace('/', '-')
            demisto.debug(f'Handling message_id: {message_id}')
        return message_id


# COMMANDS
def list_mails_command(client: MsGraphMailBaseClient, args) -> CommandResults | dict:
    kwargs = {arg_key: args.get(arg_key) for arg_key in ['search', 'odata', 'folder_id', 'user_id']}
    demisto.debug(f'{kwargs=}')
    raw_response = client.list_mails(**kwargs)

    next_page = raw_response[-1].get('@odata.nextLink')

    if not (mail_context := GraphMailUtils.build_mail_object(raw_response, user_id=args.get('user_id'))):
        return CommandResults(readable_output='### No mails were found')

    partial_result_title = ''
    if next_page:
        partial_result_title = f'{len(mail_context)} mails received' \
            '\nPay attention there are more results than shown. ' \
            'For more data please increase "pages_to_pull" argument'
    human_readable = tableToMarkdown(
        partial_result_title or f'Total of {len(mail_context)} mails received',
        mail_context,
        headers=['Subject', 'From', 'Recipients', 'SendTime', 'ID', 'InternetMessageID']
    )

    result_entry = CommandResults(
        outputs_prefix='MSGraphMail',
        outputs_key_field='ID',
        outputs=mail_context,
        readable_output=human_readable,
        raw_response=raw_response
    ).to_context()
    if next_page:
        result_entry['EntryContext'].update({'MSGraphMail(val.NextPage.indexOf(\'http\')>=0)': {'NextPage': next_page}})
    return result_entry


def create_draft_command(client: MsGraphMailBaseClient, args) -> CommandResults:
    """
    Creates draft message in user's mailbox, in draft folder.
    """
    # prepare the draft data
    kwargs = GraphMailUtils.prepare_args('create-draft', args)
    draft = GraphMailUtils.build_message(**kwargs)
    less_than_3mb_attachments, more_than_3mb_attachments = GraphMailUtils.divide_attachments_according_to_size(
        attachments=draft.get('attachments')
    )
    draft['attachments'] = less_than_3mb_attachments

    # create the draft via API
    from_email = args.get('from')
    created_draft = client.create_draft(from_email=from_email, json_data=draft)

    # upload attachment that should be uploaded using upload session
    if more_than_3mb_attachments:
        client.add_attachments_via_upload_session(email=from_email,
                                                  draft_id=created_draft.get('id', ''),
                                                  attachments=more_than_3mb_attachments)

    # prepare the command result
    parsed_draft = GraphMailUtils.parse_item_as_dict(created_draft)
    human_readable = tableToMarkdown(f'Created draft with id: {parsed_draft.get("ID", "")}', parsed_draft)
    return CommandResults(
        outputs_prefix='MicrosoftGraph.Draft',
        outputs_key_field='ID',
        outputs=parsed_draft,
        readable_output=human_readable,
        raw_response=created_draft
    )


def reply_to_command(client: MsGraphMailBaseClient, args) -> CommandResults:

    prepared_args = GraphMailUtils.prepare_args('reply-to', args)
    email = args.get('from')
    message_id = prepared_args.pop('message_id')

    reply = GraphMailUtils.build_reply(**prepared_args)  # pylint: disable=unexpected-keyword-arg

    less_than_3mb_attachments, more_than_3mb_attachments = GraphMailUtils.divide_attachments_according_to_size(
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

    to_recipients = prepared_args.get('to_recipients')
    comment = prepared_args.get('comment')
    return CommandResults(readable_output=f'### Replied to: {", ".join(to_recipients)} with comment: {comment}')


def get_message_command(client: MsGraphMailBaseClient, args) -> CommandResults:
    prepared_args = GraphMailUtils.prepare_args('get-message', args)
    get_body = args.get('get_body') == 'true'
    user_id = args.get('user_id')

    raw_response = client.get_message(**prepared_args)
    message = GraphMailUtils.build_mail_object(raw_response, user_id=user_id, get_body=get_body)
    human_readable = tableToMarkdown(
        f'Results for message ID {prepared_args["message_id"]}',
        message,
        headers=['ID', 'Subject', 'SendTime', 'Sender', 'From', 'Recipients', 'HasAttachments', 'Body']
    )
    return CommandResults(
        outputs_prefix='MSGraphMail',
        outputs_key_field='ID',
        outputs=message,
        readable_output=human_readable,
        raw_response=raw_response
    )


def delete_mail_command(client: MsGraphMailBaseClient, args) -> CommandResults:
    delete_mail_args = {
        'user_id': args.get('user_id'),
        'message_id': GraphMailUtils.handle_message_id(args.get('message_id', '')),
        'folder_id': args.get('folder_id')
    }
    client.delete_mail(**delete_mail_args)

    human_readable = tableToMarkdown('Message has been deleted successfully', delete_mail_args, removeNull=True)

    return CommandResults(readable_output=human_readable)


def list_attachments_command(client: MsGraphMailBaseClient, args) -> CommandResults:
    user_id = args.get('user_id')
    message_id = GraphMailUtils.handle_message_id(args.get('message_id', ''))
    folder_id = args.get('folder_id')
    raw_response = client.list_attachments(user_id, message_id, folder_id)
    if not (attachments := raw_response.get('value')):
        readable_output = f'### No attachments found in message {message_id}'
        return CommandResults(readable_output=readable_output)

    attachment_list = [{
        'ID': attachment.get('id'),
        'Name': attachment.get('name') or attachment.get('id'),
        'Type': attachment.get('contentType')
    } for attachment in attachments]

    # Build human readable
    readable_output = tableToMarkdown(
        f'Total of {len(attachment_list)} attachments found in message {message_id}',
        {'File names': [attachment.get('Name') for attachment in attachment_list]},
        removeNull=True
    )

    return CommandResults(
        outputs_prefix='MSGraphMailAttachment',
        outputs_key_field='ID',
        outputs={'ID': message_id, 'Attachment': attachment_list, 'UserID': user_id},
        readable_output=readable_output,
        raw_response=raw_response
    )


def get_attachment_command(client: MsGraphMailBaseClient, args) -> list[CommandResults | dict]:
    kwargs = {
        'message_id': GraphMailUtils.handle_message_id(args.get('message_id', '')),
        'user_id': args.get('user_id', client._mailbox_to_fetch),
        'folder_id': args.get('folder_id'),
        'attachment_id': args.get('attachment_id'),
    }
    raw_response = client.get_attachment(**kwargs)
    return [GraphMailUtils.create_attachment(raw_attachment=attachment, user_id=kwargs['user_id'], args=args, client=client,
                                             legacy_name=client.legacy_name) for attachment in raw_response]


def create_folder_command(client: MsGraphMailBaseClient, args) -> CommandResults:
    user_id = args.get('user_id')
    new_folder_name = args.get('new_folder_name')
    parent_folder_id = args.get('parent_folder_id')

    raw_response = client.create_folder(user_id, new_folder_name, parent_folder_id)
    parsed_folder = GraphMailUtils.parse_folders_list(raw_response)

    return CommandResults(
        outputs_prefix='MSGraphMail.Folders',
        outputs_key_field='ID',
        outputs=parsed_folder,
        readable_output=tableToMarkdown(f'The Mail folder {new_folder_name} was created', parsed_folder),
        raw_response=raw_response
    )


def list_folders_command(client: MsGraphMailBaseClient, args):
    user_id = args.get('user_id')
    limit = args.get('limit', '20')

    raw_response = client.list_folders(user_id, limit)
    parsed_folders = GraphMailUtils.parse_folders_list(raw_response.get('value', []))
    return CommandResults(
        outputs_prefix='MSGraphMail.Folders',
        outputs_key_field='ID',
        outputs=parsed_folders,
        raw_response=raw_response,
        readable_output=tableToMarkdown(f'Mail Folder collection under root folder for user {user_id}',
                                        parsed_folders),
    )


def list_child_folders_command(client: MsGraphMailBaseClient, args):
    user_id = args.get('user_id')
    parent_folder_id = args.get('parent_folder_id')
    limit = args.get('limit', '20')

    raw_response = client.list_child_folders(user_id, parent_folder_id, limit)
    child_folders = GraphMailUtils.parse_folders_list(raw_response.get('value', []))  # type: ignore

    return CommandResults(
        outputs_prefix='MSGraphMail.Folders',
        outputs_key_field='ID',
        outputs=child_folders,
        raw_response=raw_response,
        readable_output=tableToMarkdown(f'Mail Folder collection under {parent_folder_id} folder for user {user_id}',
                                        child_folders)
    )


def update_folder_command(client: MsGraphMailBaseClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    new_display_name = args.get('new_display_name')

    raw_response = client.update_folder(user_id, folder_id, new_display_name)
    parsed_folder = GraphMailUtils.parse_folders_list(raw_response)

    return CommandResults(
        outputs_prefix='MSGraphMail.Folders',
        outputs_key_field='ID',
        outputs=parsed_folder,
        raw_response=raw_response,
        readable_output=tableToMarkdown(f'Mail folder {folder_id} was updated with display name: {new_display_name}',
                                        parsed_folder)
    )


def delete_folder_command(client: MsGraphMailBaseClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')

    client.delete_folder(user_id, folder_id)

    return CommandResults(readable_output=f'The folder {folder_id} was deleted successfully')


def move_email_command(client: MsGraphMailBaseClient, args):
    user_id = args.get('user_id')
    message_id = GraphMailUtils.handle_message_id(args.get('message_id', ''))
    destination_folder_id = args.get('destination_folder_id')

    raw_response = client.move_email(user_id, message_id, destination_folder_id)
    new_message_id = raw_response.get('id')
    moved_email_info = {
        'ID': new_message_id,
        'DestinationFolderID': destination_folder_id,
        'UserID': user_id
    }

    readable_output = tableToMarkdown('The email was moved successfully. Updated email data:', moved_email_info)
    return CommandResults(
        outputs_prefix='MSGraphMail.MovedEmails',
        outputs_key_field='ID',
        outputs=moved_email_info,
        readable_output=readable_output,
        raw_response=raw_response
    )


def get_email_as_eml_command(client: MsGraphMailBaseClient, args):
    user_id = args.get('user_id')
    message_id = GraphMailUtils.handle_message_id(args.get('message_id', ''))

    eml_content = client.get_email_as_eml(user_id, message_id)
    file_result = fileResult(f'{message_id}.eml', eml_content)

    if is_error(file_result):
        raise DemistoException(file_result['Contents'])

    return file_result


def send_draft_command(client: MsGraphMailBaseClient, args):
    email = args.get('from')
    draft_id = args.get('draft_id')

    client.send_draft(email=email, draft_id=draft_id)

    return CommandResults(readable_output=f'### Draft with: {draft_id} id was sent successfully.')


def update_email_status_command(client: MsGraphMailBaseClient, args) -> CommandResults:
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    message_ids = argToList(args['message_ids'], transform=GraphMailUtils.handle_message_id)
    status: str = args['status']
    mark_as_read = (status.lower() == 'read')

    raw_responses = []

    for message_id in message_ids:
        raw_responses.append(
            client.update_email_read_status(user_id=user_id, message_id=message_id,
                                            folder_id=folder_id, read=mark_as_read)
        )

    return CommandResults(
        readable_output=f'Emails status has been updated to {status}.',
        raw_response=raw_responses[0] if len(raw_responses) == 1 else raw_responses
    )


def reply_email_command(client: MsGraphMailBaseClient, args):
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

    reply = GraphMailUtils.build_message_to_reply(email_to, email_cc, email_bcc, email_subject, message_body, attach_ids,
                                                  attach_names, attach_cids, reply_to)

    less_than_3mb_attachments, more_than_3mb_attachments = GraphMailUtils.divide_attachments_according_to_size(
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

    return GraphMailUtils.prepare_outputs_for_reply_mail_command(reply, email_to, message_id)


def send_email_command(client: MsGraphMailBaseClient, args):
    """
    Sends email from user's mailbox, the sent message will appear in Sent Items folder.

    Sending email process:
    1) If there are attachments larger than 3MB, create a draft mail, upload > 3MB attachments via upload session,
        and send the draft mail.

    2) if there aren't any attachments larger than 3MB, just send the email as usual.
    """
    prepared_args = GraphMailUtils.prepare_args('send-mail', args)
    render_body = prepared_args.pop('renderBody', False)
    message_content = GraphMailUtils.build_message(**prepared_args)
    email = args.get('from', client._mailbox_to_fetch)

    less_than_3mb_attachments, more_than_3mb_attachments = GraphMailUtils.divide_attachments_according_to_size(
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

    to_recipients, cc_recipients, bcc_recipients, reply_to_recipients = \
        GraphMailUtils.build_recipients_human_readable(message_content)
    message_content['toRecipients'] = to_recipients
    message_content['ccRecipients'] = cc_recipients
    message_content['bccRecipients'] = bcc_recipients
    message_content['replyTo'] = reply_to_recipients

    message_content = assign_params(**message_content)
    results = [
        CommandResults(
            outputs_prefix='MicrosoftGraph.Email',
            outputs=message_content,
            readable_output=tableToMarkdown('Email was sent successfully.', message_content)
        )
    ]
    if render_body:
        results.append(CommandResults(
            entry_type=EntryType.NOTE,
            content_format=EntryFormat.HTML,
            raw_response=prepared_args['body'],
        ))
    return results


def list_rule_action_command(client: MsGraphMailBaseClient, args) -> CommandResults | dict:
    rule_id = args.get('rule_id')
    user_id = args.get('user_id')
    limit = args.get('limit', 50)
    hr_headers = ['id', 'displayName', 'isEnabled']
    hr_title_parts = [f'!{demisto.command()}', user_id if user_id else '', f'for {rule_id=}' if rule_id else 'rules']
    if rule_id:
        hr_headers.extend(['conditions', 'actions'])
    result = client.message_rules_action('GET', user_id=user_id, rule_id=rule_id, limit=limit)
    result.pop('@odata.context', None)
    outputs = [result] if rule_id else result.get('value', [])

    return CommandResults(
        outputs_prefix='MSGraphMail.Rule', outputs=outputs,
        readable_output=tableToMarkdown(' '.join(hr_title_parts), outputs, headers=hr_headers,
                                        headerTransform=pascalToSpace)
    )


def delete_rule_command(client: MsGraphMailBaseClient, args) -> str:
    rule_id = args.get('rule_id')
    user_id = args.get('user_id')
    client.message_rules_action('DELETE', user_id=user_id, rule_id=rule_id)
    return f"Rule {rule_id} deleted{f' for user {user_id}' if user_id else ''}."
