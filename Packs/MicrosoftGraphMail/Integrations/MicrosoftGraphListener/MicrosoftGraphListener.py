import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' IMPORTS '''
import base64
import os
import json
import urllib3
from urllib.parse import quote


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

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

''' HELPER FUNCTIONS '''


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
    if command in ['msgraph-mail-create-draft', 'send-mail']:
        if args.get('htmlBody', None):
            email_body = args.get('htmlBody')
        else:
            email_body = args.get('body', '')
        return {
            'to_recipients': argToList(args.get('to')),
            'cc_recipients': argToList(args.get('cc')),
            'bcc_recipients': argToList(args.get('bcc')),
            'replyTo': argToList(args.get('replyTo')),
            'subject': args.get('subject', ''),
            'body': email_body,
            'body_type': args.get('body_type', 'html'),
            'flag': args.get('flag', 'notFlagged'),
            'importance': args.get('importance', 'Low'),
            'internet_message_headers': argToList(args.get('headers')),
            'attach_ids': argToList(args.get('attach_ids')),
            'attach_names': argToList(args.get('attach_names')),
            'attach_cids': argToList((args.get('attach_cids'))),
            'manual_attachments': args.get('manualAttachObj', [])
        }

    elif command == 'msgraph-mail-reply-to':
        return {
            'to_recipients': argToList(args.get('to')),
            'message_id': args.get('message_id', ''),
            'comment': args.get('comment'),
            'attach_ids': argToList(args.get('attach_ids')),
            'attach_names': argToList(args.get('attach_names')),
            'attach_cids': argToList((args.get('attach_cids')))
        }

    return args


def prepare_outputs_for_reply_mail_command(reply, email_to: str, message_id: str) -> CommandResults:
    reply.pop('attachments', None)
    to_recipients, cc_recipients, bcc_recipients = build_recipients_human_readable(reply)
    reply['toRecipients'] = to_recipients
    reply['ccRecipients'] = cc_recipients
    reply['bccRecipients'] = bcc_recipients
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


# -*- coding: utf-8 -*-
def is_only_ascii(s: str) -> bool:
    """
    Check whether the string can be encoded only with ASCII characters
    (which are Latin alphabet + some other characters).
    If it can not be encoded, then it has the characters from some other alphabet.

    Args:
        s: str to check

    Returns: True when s contains only Latin alphabet + some other characters, otherwise False.

    """
    try:
        s.encode(encoding='utf-8').decode('ascii')
        return True

    except UnicodeDecodeError:
        return False


''' MICROSOFT GRAPH MAIL CLIENT '''


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """
    ITEM_ATTACHMENT = '#microsoft.graph.itemAttachment'
    FILE_ATTACHMENT = '#microsoft.graph.fileAttachment'
    CONTEXT_DRAFT_PATH = 'MicrosoftGraph.Draft(val.ID && val.ID == obj.ID)'
    CONTEXT_SENT_EMAIL_PATH = 'MicrosoftGraph.Email'
    MAX_ATTACHMENT_SIZE = 3145728  # 3mb = 3145728 bytes

    def __init__(self, self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url, use_ssl, proxy,
                 ok_codes, refresh_token, mailbox_to_fetch, folder_to_fetch, first_fetch_interval, emails_fetch_limit,
                 auth_code, redirect_uri,
                 certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None,
                 display_full_email_body: bool = False,
                 fetch_mail_body_as_text: bool = True,
                 refresh_token_param: Optional[str] = '',
                 mark_fetched_read: bool = False,
                 managed_identities_client_id: Optional[str] = None):
        self.ms_client = MicrosoftClient(self_deployed=self_deployed, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                         enc_key=enc_key, app_name=app_name, base_url=base_url, verify=use_ssl,
                                         proxy=proxy, ok_codes=ok_codes, refresh_token=refresh_token,
                                         refresh_token_param=refresh_token_param,
                                         auth_code=auth_code, redirect_uri=redirect_uri,
                                         grant_type=AUTHORIZATION_CODE, certificate_thumbprint=certificate_thumbprint,
                                         private_key=private_key, retry_on_rate_limit=True,
                                         managed_identities_client_id=managed_identities_client_id,
                                         managed_identities_resource_uri=Resources.graph)
        self._mailbox_to_fetch = mailbox_to_fetch
        self._folder_to_fetch = folder_to_fetch
        self._first_fetch_interval = first_fetch_interval
        self._emails_fetch_limit = emails_fetch_limit
        self._display_full_email_body = display_full_email_body
        self._fetch_mail_body_as_text = fetch_mail_body_as_text
        self._mark_fetched_read = mark_fetched_read

    def _get_root_folder_children(self, user_id, overwrite_rate_limit_retry=False):
        """
        Get the root folder (Top Of Information Store) children collection.

        :type user_id: ``str``
        :param user_id: Mailbox address

        :raises: ``Exception``: No folders found under Top Of Information Store folder

        :return: List of root folder children
        rtype: ``list``
        """
        suffix_endpoint = f'users/{user_id}/mailFolders/msgfolderroot/childFolders?$top=250'
        root_folder_children = self.ms_client.http_request('GET', suffix_endpoint,
                                                           overwrite_rate_limit_retry=overwrite_rate_limit_retry) \
            .get('value', None)
        if not root_folder_children:
            raise Exception("No folders found under Top Of Information Store folder")

        return root_folder_children

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
        suffix_endpoint = f'users/{user_id}/mailFolders/{folder_id}/childFolders?$top=250'
        folder_children = self.ms_client.http_request('GET', suffix_endpoint,
                                                      overwrite_rate_limit_retry=overwrite_rate_limit_retry).get('value', [])
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

        suffix_endpoint = f'users/{user_id}/mailFolders/{folder_id}'
        folder_info = self.ms_client.http_request('GET', suffix_endpoint,
                                                  overwrite_rate_limit_retry=overwrite_rate_limit_retry)
        if not folder_info:
            raise Exception(f'No info found for folder {folder_id}')
        return folder_info

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

        :type last_fetch: ``dict``
        :param last_fetch: Previous fetch data

        :type exclude_ids: ``list``
        :param exclude_ids: List of previous fetch email ids to exclude in current run

        :return: Fetched emails and exclude ids list that contains the new ids of fetched emails
        :rtype: ``list`` and ``list``
        """
        demisto.debug(f'Fetching Emails starting from {last_fetch}')
        fetched_emails = self.get_emails(exclude_ids=exclude_ids, last_fetch=last_fetch,
                                         folder_id=folder_id, overwrite_rate_limit_retry=True,
                                         fetch_mail_body_as_text=self._fetch_mail_body_as_text,
                                         mark_emails_as_read=self._mark_fetched_read)

        fetched_emails = fetched_emails[:self._emails_fetch_limit]

        if exclude_ids:  # removing emails in order to prevent duplicate incidents
            fetched_emails = [email for email in fetched_emails if email.get('id') not in exclude_ids]

        fetched_emails_ids = [email.get('id') for email in fetched_emails]
        return fetched_emails, fetched_emails_ids

    @staticmethod
    def _get_next_run_time(fetched_emails, start_time):
        """
        Returns received time of last email if exist, else utc time that was passed as start_time.

        The elements in fetched emails are ordered by modified time in ascending order,
        meaning the last element has the latest received time.

        :type fetched_emails: ``list``
        :param fetched_emails: List of fetched emails

        :type start_time: ``str``
        :param start_time: utc string of format Y-m-dTH:M:SZ

        :return: Returns str date of format Y-m-dTH:M:SZ
        :rtype: `str`
        """
        next_run_time = fetched_emails[-1].get('receivedDateTime') if fetched_emails else start_time

        return next_run_time

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
    def _build_message(to_recipients, cc_recipients, bcc_recipients, subject, body, body_type, flag, importance,
                       internet_message_headers, attach_ids, attach_names, attach_cids, manual_attachments, replyTo):
        """
        Builds valid message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        message = {
            'toRecipients': MsGraphClient._build_recipient_input(to_recipients),
            'ccRecipients': MsGraphClient._build_recipient_input(cc_recipients),
            'bccRecipients': MsGraphClient._build_recipient_input(bcc_recipients),
            'replyTo': MsGraphClient._build_recipient_input(replyTo),
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
    def _build_reply(to_recipients, comment, attach_ids, attach_names, attach_cids):
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

    def _get_attachment_mime(self, message_id, attachment_id, overwrite_rate_limit_retry=False):
        """
        Gets attachment mime.

        :type attachment_id: ``str``
        :param attachment_id: Attachment id to get MIME

        :return: The MIME of the attachment
        :rtype: ``str``
        """
        suffix_endpoint = f'users/{self._mailbox_to_fetch}/messages/{message_id}/attachments/{attachment_id}/$value'
        mime_content = self.ms_client.http_request('GET', suffix_endpoint, resp_type='text',
                                                   overwrite_rate_limit_retry=overwrite_rate_limit_retry)

        return mime_content

    def _get_email_attachments(self, message_id, user_id=None, overwrite_rate_limit_retry=False):
        """
        Get email attachments  and upload to War Room.

        :type message_id: ``str``
        :param message_id: The email id to get attachments

        :return: List of uploaded to War Room data, uploaded file path and name
        :rtype: ``list``
        """
        if not user_id:
            user_id = self._mailbox_to_fetch
        attachment_results = []  # type: ignore
        suffix_endpoint = f'users/{user_id}/messages/{message_id}/attachments'
        attachments = self.ms_client.http_request('Get', suffix_endpoint,
                                                  overwrite_rate_limit_retry=overwrite_rate_limit_retry).get('value', [])

        for attachment in attachments:

            attachment_type = attachment.get('@odata.type', '')
            attachment_name = attachment.get('name', 'untitled_attachment')

            if not is_only_ascii(attachment_name):
                try:
                    demisto.debug(f"Trying to decode the attachment file name: {attachment_name}")
                    attachment_name = base64.b64decode(attachment_name)
                except Exception as e:
                    demisto.debug(f"Could not decode the {attachment_name=}: error: {e}")

            if attachment_type == self.FILE_ATTACHMENT:
                try:
                    attachment_content = base64.b64decode(attachment.get('contentBytes', ''))
                except Exception as e:  # skip the uploading file step
                    demisto.info(f"MS-Graph-Listener: failed in decoding base64 file attachment with error {str(e)}")
                    continue
            elif attachment_type == self.ITEM_ATTACHMENT:
                attachment_id = attachment.get('id', '')
                attachment_content = self._get_attachment_mime(message_id, attachment_id, overwrite_rate_limit_retry)
                attachment_name = f'{attachment_name}.eml'
            else:
                # skip attachments that are not of the previous types (type referenceAttachment)
                continue
            # upload the item/file attachment to War Room
            demisto.debug(f"Uploading attachment file: {attachment_name=}, {attachment_content=}")
            upload_file(attachment_name, attachment_content, attachment_results)

        demisto.debug(f"Final attachment results = {attachment_results}")
        return attachment_results

    def _parse_email_as_incident(self, email, overwrite_rate_limit_retry=False):
        """
        Parses fetched emails as incidents.

        :type email: ``dict``
        :param email: Fetched email to parse

        :return: Parsed email
        :rtype: ``dict``
        """
        parsed_email = MsGraphClient._parse_item_as_dict(email)

        # handling attachments of fetched email
        attachments = self._get_email_attachments(message_id=email.get('id', ''),
                                                  overwrite_rate_limit_retry=overwrite_rate_limit_retry)
        if attachments:
            parsed_email['Attachments'] = attachments

        parsed_email['Mailbox'] = self._mailbox_to_fetch

        if self._display_full_email_body:
            body = email.get('body', {}).get('content', '')

        else:
            body = email.get('bodyPreview', '')

        incident = {
            'name': parsed_email['Subject'],
            'details': body,
            'labels': MsGraphClient._parse_email_as_labels(parsed_email),
            'occurred': parsed_email['ModifiedTime'],
            'attachment': parsed_email.get('Attachments', []),
            'rawJSON': json.dumps(parsed_email)
        }

        return incident

    def get_emails(self, exclude_ids, last_fetch, folder_id, overwrite_rate_limit_retry=False,
                   fetch_mail_body_as_text: bool | None = False, mark_emails_as_read: bool = False) -> list:
        if fetch_mail_body_as_text is None:
            fetch_mail_body_as_text = self._fetch_mail_body_as_text

        # Add headers to request body as text if `mail_body_as_text` is True
        headers = {"Prefer": "outlook.body-content-type='text'"} if fetch_mail_body_as_text else None

        # Adding the "$" sign to the select filter results in the 'internetMessageHeaders' field not being contained
        # within the response, (looks like a bug in graph API).
        results = self.ms_client.http_request(
            method='GET',
            url_suffix=f'/users/{self._mailbox_to_fetch}/mailFolders/{folder_id}/messages',
            params={
                '$filter': f'receivedDateTime ge {add_second_to_str_date(last_fetch)}',  # workaround to Graph API bug
                '$orderby': 'receivedDateTime asc',
                'select': '*',
                '$top': len(exclude_ids) + self._emails_fetch_limit,  # fetch extra incidents
            },
            headers=headers,
            overwrite_rate_limit_retry=overwrite_rate_limit_retry,
        ).get('value', [])

        if mark_emails_as_read:
            for email in results:
                if email.get('id'):
                    self.update_email_read_status(message_id=email["id"],
                                                  read=True,
                                                  folder_id=folder_id)

        return results

    def update_email_read_status(self, message_id: str, read: bool, folder_id: str | None = None) -> dict:
        """
        Update the status of an email to read / unread.

        Args:
            message_id (str): Message id to mark as read/unread
            folder_id (str): Folder id to update
            read (bool): Whether to mark the email as read or unread. True for read, False for unread.

        Returns:
            dict: API response
        """
        if folder_id:
            suffix = f'/users/{self._mailbox_to_fetch}/{build_folders_path(folder_id)}/messages/{message_id}'

        else:
            suffix = f'/users/{self._mailbox_to_fetch}/messages/{message_id}'

        return self.ms_client.http_request(
            method='PATCH',
            url_suffix=suffix,
            json_data={'isRead': read},
        )

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
        last_fetch = last_run.get('LAST_RUN_TIME')
        exclude_ids = last_run.get('LAST_RUN_IDS', [])
        last_run_folder_path = last_run.get('LAST_RUN_FOLDER_PATH')
        folder_path_changed = (last_run_folder_path != self._folder_to_fetch)

        if folder_path_changed:
            # detected folder path change, get new folder id
            folder_id = self._get_folder_by_path(self._mailbox_to_fetch, self._folder_to_fetch,
                                                 overwrite_rate_limit_retry=True).get('id')
            demisto.info("MS-Graph-Listener: detected file path change, ignored last run.")
        else:
            # LAST_RUN_FOLDER_ID is stored in order to avoid calling _get_folder_by_path method in each fetch
            folder_id = last_run.get('LAST_RUN_FOLDER_ID')

        if not last_fetch or folder_path_changed:  # initialized fetch
            last_fetch, _ = parse_date_range(self._first_fetch_interval, date_format=DATE_FORMAT, utc=True)
            demisto.info(f"MS-Graph-Listener: initialize fetch and pull emails from date :{last_fetch}")

        fetched_emails, fetched_emails_ids = self._fetch_last_emails(folder_id=folder_id, last_fetch=last_fetch,
                                                                     exclude_ids=exclude_ids)
        incidents = list(map(lambda email: self._parse_email_as_incident(email, True), fetched_emails))
        next_run_time = MsGraphClient._get_next_run_time(fetched_emails, last_fetch)
        next_run = {
            'LAST_RUN_TIME': next_run_time,
            'LAST_RUN_IDS': fetched_emails_ids,
            'LAST_RUN_FOLDER_ID': folder_id,
            'LAST_RUN_FOLDER_PATH': self._folder_to_fetch
        }
        demisto.info(f"MS-Graph-Listener: fetched {len(incidents)} incidents")

        return next_run, incidents

    def create_draft(self, email: str, json_data, reply_message_id: str = None) -> dict:
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

    def create_draft_command(self, **kwargs) -> tuple[str, dict, dict]:
        """
        Creates draft message in user's mailbox, in draft folder.
        """
        draft = MsGraphClient._build_message(**kwargs)
        less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
            attachments=draft.get('attachments')
        )

        draft['attachments'] = less_than_3mb_attachments
        created_draft = self.create_draft(email=self._mailbox_to_fetch, json_data=draft)
        if more_than_3mb_attachments:  # we have at least one attachment that should be uploaded using upload session
            self.add_attachments_via_upload_session(
                email=self._mailbox_to_fetch, draft_id=created_draft.get('id', ''), attachments=more_than_3mb_attachments
            )
        parsed_draft = MsGraphClient._parse_item_as_dict(created_draft)
        human_readable = tableToMarkdown(f'Created draft with id: {parsed_draft.get("ID", "")}', parsed_draft)
        ec = {self.CONTEXT_DRAFT_PATH: parsed_draft}

        return human_readable, ec, created_draft

    def send_email_command(self, **kwargs) -> tuple[str, dict]:
        """
        Sends email from user's mailbox, the sent message will appear in Sent Items folder.
        Sending email process:
        1) If there are attachments larger than 3MB, create a draft mail, upload > 3MB attachments via upload session,
            and send the draft mail.
        2) if there aren't any attachments larger than 3MB, just send the email as usual.
        """
        message_content = self._build_message(**kwargs)
        email = kwargs.get('from', self._mailbox_to_fetch)

        less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
            attachments=message_content.get('attachments')
        )

        if more_than_3mb_attachments:  # go through process 1 (in docstring)
            message_content['attachments'] = less_than_3mb_attachments
            self.send_mail_with_upload_session_flow(
                email=email, json_data=message_content, attachments_more_than_3mb=more_than_3mb_attachments
            )
        else:  # go through process 2 (in docstring)
            self.send_mail(email=email, json_data=message_content)

        message_content.pop('attachments', None)
        message_content.pop('internet_message_headers', None)
        human_readable = tableToMarkdown('Email was sent successfully.', message_content)
        ec = {self.CONTEXT_SENT_EMAIL_PATH: message_content}

        return human_readable, ec

    def send_mail(self, email, json_data):
        """
        Sends an email.
        Args:
            email (str): email to send the message from.
            json_data (dict): message data.
        """
        self.ms_client.http_request(
            'POST', f'/users/{email}/sendMail', json_data={'message': json_data}, resp_type="text"
        )

    def mail_reply_to_command(self, to_recipients: list, comment: str, message_id: str,
                              attach_ids: list, attach_names: list, attach_cids: str) -> str:
        """
        Sends reply message to recipients.

        :type to_recipients: ``list``
        :param to_recipients: List of recipients to reply.

        :type comment: ``str``
        :param comment: The comment to send as a reply

        :type message_id: ``str``
        :param message_id: The message id to reply.

        :type attach_ids: ``list``
        :param attach_ids: List of uploaded to War Room regular attachments to send

        :type attach_names: ``list``
        :param attach_names: List of regular attachments names to send

        :type attach_cids: ``list``
        :param attach_cids: List of uploaded to War Room inline attachments to send

        :return: String representation of markdown message regarding successful message submission.
        rtype: ``str``
        """
        reply = MsGraphClient._build_reply(to_recipients, comment, attach_ids, attach_names, attach_cids)
        less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
            attachments=reply.get('message').get('attachments')
        )
        if more_than_3mb_attachments:
            reply['message']['attachments'] = less_than_3mb_attachments
            self.send_mail_with_upload_session_flow(
                email=self._mailbox_to_fetch,
                json_data=reply,
                attachments_more_than_3mb=more_than_3mb_attachments,
                reply_message_id=message_id
            )
        else:
            self.send_reply(email_from=self._mailbox_to_fetch, message_id=message_id, json_data=reply)

        return f'### Replied to: {", ".join(to_recipients)} with comment: {comment}'

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

    def reply_mail_command(self, args: dict) -> CommandResults:
        email_to = argToList(args.get('to'))
        email_from = args.get('from', self._mailbox_to_fetch)
        message_id = args.get('inReplyTo', '')
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

        reply = self.build_message_to_reply(email_to, email_cc, email_bcc, email_subject, message_body,
                                            attach_ids,
                                            attach_names, attach_cids)

        less_than_3mb_attachments, more_than_3mb_attachments = divide_attachments_according_to_size(
            attachments=reply.get('attachments')
        )

        if more_than_3mb_attachments:
            reply['attachments'] = less_than_3mb_attachments
            self.send_mail_with_upload_session_flow(
                email=email_from,
                json_data={'message': reply, 'comment': message_body},
                attachments_more_than_3mb=more_than_3mb_attachments,
                reply_message_id=message_id
            )
        else:
            self.send_reply(
                email_from=email_from, message_id=message_id, json_data={'message': reply, 'comment': message_body}
            )

        return prepare_outputs_for_reply_mail_command(reply, email_to, message_id)

    def send_draft(self, email: str, draft_id: str):
        """
        Sends a draft message.
        Args:
            email (str): email to send the draft from.
            draft_id (str): the ID of the draft to send.
        """
        self.ms_client.http_request('POST', f'/users/{email}/messages/{draft_id}/send', resp_type='text')

    def send_draft_command(self, draft_id: str) -> str:
        """
        Send draft message.

        :type draft_id: ``str``
        :param draft_id: Draft id to send.

        :return: String representation of markdown message regarding successful message submission.
        :rtype: ``str``
        """
        self.send_draft(email=self._mailbox_to_fetch, draft_id=draft_id)
        return f'### Draft with: {draft_id} id was sent successfully.'

    @staticmethod
    def build_message_to_reply(to_recipients, cc_recipients, bcc_recipients, subject, email_body, attach_ids,
                               attach_names, attach_cids):
        """
        Builds a valid reply message dict.
        For more information https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        """
        return {
            'toRecipients': MsGraphClient._build_recipient_input(to_recipients),
            'ccRecipients': MsGraphClient._build_recipient_input(cc_recipients),
            'bccRecipients': MsGraphClient._build_recipient_input(bcc_recipients),
            'subject': subject,
            'bodyPreview': email_body[:255],
            'attachments': MsGraphClient._build_file_attachments_input(attach_ids, attach_names, attach_cids, [])
        }

    def list_mails(self, search: str = None, odata: str = None) -> Union[dict, list]:
        """Returning all mails from given user

        Args:
            search (str):   plaintext search query
            odata (str):    odata-formatted query

        Returns:
            dict or list:   list of mails or dictionary when single item is returned
        """
        suffix = f'/users/{self._mailbox_to_fetch}/messages'
        pages_to_pull = demisto.args().get('pages_to_pull', 1)
        page_size = demisto.args().get('page_size', 20)
        odata = f'{odata}&$top={page_size}' if odata else f'$top={page_size}'

        if search:
            # Data is being handled as a JSON so in cases the search phrase contains double quote ",
            # we should escape it.
            search = search.replace('"', '\\"')
            odata = f'{odata}&$search="{quote(search)}"'
        if odata:
            suffix += f'?{odata}'
        demisto.debug(f"URL suffix is {suffix}")
        response = self.ms_client.http_request('GET', suffix)
        return self.pages_puller(response, assert_pages(pages_to_pull))

    def list_attachments(self, message_id: str, folder_id: str) -> dict:
        """Listing all the attachments

        Args:
            message_id (str): ID of a message to pull
            folder_id (str):  ID of folder from which to pull message

        Returns:
            dict: Attachments Data
        """
        no_folder = f'/users/{self._mailbox_to_fetch}/messages/{message_id}/attachments/'
        with_folder = f'/users/{self._mailbox_to_fetch}/{build_folders_path(folder_id)}/messages/{message_id}/attachments/'
        suffix = with_folder if folder_id else no_folder
        return self.ms_client.http_request('GET', suffix)

    def get_mailbox_to_fetch(self):
        return self._mailbox_to_fetch

    def get_attachment(self, message_id: str, attachment_id: str, folder_id: str = None) -> dict:
        """

        Args:
            message_id (str):       ID of a message to pull
            attachment_id (str):    ID of an attachment to pull
            folder_id (str):        ID of folder from which to pull message

        Returns:
            dict:                   Attachment Data
        """
        no_folder = f'/users/{self._mailbox_to_fetch}/messages/{message_id}/attachments/{attachment_id}/' \
                    f'?$expand=microsoft.graph.itemattachment/item'
        with_folder = (f'/users/{self._mailbox_to_fetch}/{build_folders_path(folder_id)}/'  # type: ignore
                       f'messages/{message_id}/attachments/{attachment_id}/'
                       f'?$expand=microsoft.graph.itemattachment/item')
        suffix = with_folder if folder_id else no_folder

        response = self.ms_client.http_request('GET', suffix)
        return response

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

    def pages_puller(self, response: dict, page_count: int) -> list:
        """ Gets first response from API and returns all pages

        Args:
            response (dict):        raw http response data
            page_count (int):       amount of pages

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

    def test_connection(self):
        """
        Basic connection test instead of test-module.

        :return: Returns markdown string representation of success or Exception in case of login failure.
        rtype: ``str`` or Exception
        """
        suffix_endpoint = f'users/{self._mailbox_to_fetch}'
        user_response = self.ms_client.http_request('GET', suffix_endpoint)

        if user_response.get('mail') != '' and user_response.get('id') != '':
            return '```✅ Success!```'
        else:
            raise Exception("Failed validating the user.")

    def add_attachments_via_upload_session(self, email: str, draft_id: str, attachments: list[dict]):
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
                attachment_data=attachment.get('data', ''),
                attachment_name=attachment.get('name', ''),
                is_inline=attachment.get('isInline', False)
            )

    def get_upload_session(self, email: str, draft_id: str, attachment_name: str, attachment_size: int, is_inline: bool) -> dict:
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

    def add_attachment_with_upload_session(self, email: str, draft_id: str, attachment_data: bytes,
                                           attachment_name: str, is_inline: bool = False):
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
        created_draft = self.create_draft(email=email, json_data=json_data, reply_message_id=reply_message_id)
        draft_id = created_draft.get('id', '')
        self.add_attachments_via_upload_session(  # add attachments via upload session.
            email=email, draft_id=draft_id, attachments=attachments_more_than_3mb
        )
        self.send_draft(email=email, draft_id=draft_id)  # send the draft email


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


def list_attachments_command(client: MsGraphClient, args):
    message_id = args.get('message_id')
    folder_id = args.get('folder_id')
    raw_response = client.list_attachments(message_id, folder_id)
    attachments = raw_response.get('value')
    if attachments:
        attachment_list = [{
            'ID': attachment.get('id'),
            'Name': attachment.get('name') or attachment.get('id'),
            'Type': attachment.get('contentType')
        } for attachment in attachments]
        entry_context = {'ID': message_id, 'Attachment': attachment_list, 'UserID': client.get_mailbox_to_fetch()}

        # Build human readable
        file_names = [attachment.get('Name') for attachment in attachment_list if isinstance(
            attachment, dict) and attachment.get('Name')]
        human_readable = tableToMarkdown(
            f'Total of {len(attachment_list)} attachments found in message {message_id}',
            {'File names': file_names}
        )
        command_results = CommandResults(
            outputs_prefix='MSGraphMailAttachment',
            outputs_key_field='ID',

            outputs=entry_context,
            readable_output=human_readable,
            raw_response=raw_response
        )
    else:
        human_readable = f'### No attachments found in message {message_id}'
        command_results = CommandResults(
            outputs_prefix='MSGraphMailAttachment',
            outputs_key_field='ID',

            outputs=dict(),
            readable_output=human_readable,
            raw_response=raw_response
        )
    return command_results


def list_mails_command(client: MsGraphClient, args):
    search = args.get('search')
    odata = args.get('odata')

    raw_response = client.list_mails(search=search, odata=odata)
    last_page_response = raw_response[len(raw_response) - 1]
    metadata = ''
    next_page = last_page_response.get('@odata.nextLink')
    if next_page:
        metadata = '\nPay attention there are more results than shown. For more data please ' \
                   'increase "pages_to_pull" argument'

    mail_context = build_mail_object(raw_response)
    if mail_context:
        entry_context = mail_context
        if next_page:
            if isinstance(entry_context, dict):
                entry_context['MSGraphMail(val.NextPage.indexOf(\'http\')>=0)'] = {'NextPage': next_page}  # type: ignore
            else:
                entry_context[-1]['MSGraphMail(val.NextPage.indexOf(\'http\')>=0)'] =\
                    {'NextPage': next_page}  # type: ignore

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
        entry_context = {}

    command_results = CommandResults(
        outputs_prefix='MSGraphMail',
        outputs_key_field='ID',

        outputs=entry_context,
        readable_output=human_readable,
        raw_response=raw_response
    )
    return command_results


def get_email_as_eml_command(client: MsGraphClient, args):
    user_id = client.get_mailbox_to_fetch()
    message_id = args.get('message_id')

    eml_content = client.get_email_as_eml(user_id, message_id)
    file_result = fileResult(f'{message_id}.eml', eml_content)

    return file_result


def update_email_status_command(client: MsGraphClient, args) -> CommandResults:
    folder_id = args.get('folder_id')
    message_ids = argToList(args['message_ids'])
    status: str = args['status']
    mark_as_read = (status.lower() == 'read')

    raw_responses = []

    for message_id in message_ids:
        raw_responses.append(
            client.update_email_read_status(message_id=message_id, folder_id=folder_id, read=mark_as_read)
        )

    return CommandResults(
        readable_output=f'Emails status has been updated to {status}.',
        raw_response=raw_responses[0] if len(raw_responses) == 1 else raw_responses
    )


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!msgraph-mail-test** to verify the authentication.'


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


def build_mail_object(raw_response: Union[dict, list], get_body: bool = False, user_id: str = None) -> Union[dict, list]:
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


def main():     # pragma: no cover
    """ COMMANDS MANAGER / SWITCH PANEL """
    params = demisto.params()
    # params related to common instance configuration
    base_url = 'https://graph.microsoft.com/v1.0/'
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    ok_codes = (200, 201, 202)
    refresh_token = params.get('creds_refresh_token', {}).get('password') or params.get('refresh_token', '')
    auth_and_token_url = params.get('creds_auth_id', {}).get('password') or params.get('auth_id', '')
    enc_key = params.get('creds_enc_key', {}).get('password') or params.get('enc_key', '')
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier') or params.get('certificate_thumbprint')
    private_key = replace_spaces_in_credential(params.get('creds_certificate', {}).get('password')) or params.get('private_key')
    auth_code = params.get('creds_auth_code', {}).get('password') or params.get('auth_code', '')
    app_name = 'ms-graph-mail-listener'
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed = params.get('self_deployed', False) or managed_identities_client_id is not None

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

    # params related to mailbox to fetch incidents
    mailbox_to_fetch = params.get('mailbox_to_fetch', '')
    folder_to_fetch = params.get('folder_to_fetch', 'Inbox')
    first_fetch_interval = params.get('first_fetch', '15 minutes')
    emails_fetch_limit = int(params.get('fetch_limit', '50'))
    display_full_email_body = argToBoolean(params.get("display_full_email_body", "false"))
    mark_fetched_read = argToBoolean(params.get("mark_fetched_read", "false"))

    # params related to self deployed
    tenant_id = refresh_token if self_deployed else ''

    # params related to oproxy
    # In case the script is running for the first time, refresh token is retrieved from integration parameters,
    # in other case it's retrieved from integration context.

    # Client gets refresh_token_param as well as refresh_token which is the current refresh token from the integration
    # context (if exists) so It will be possible to manually update the refresh token param for an existing integration
    # instance.
    refresh_token_param = refresh_token  # Refresh token from the integration parameters (i.e current instance config)
    refresh_token = get_integration_context().get('current_refresh_token') or refresh_token_param

    client = MsGraphClient(self_deployed, tenant_id, auth_and_token_url, enc_key, app_name, base_url, use_ssl, proxy,
                           ok_codes, refresh_token, mailbox_to_fetch, folder_to_fetch,
                           first_fetch_interval, emails_fetch_limit, auth_code=auth_code, private_key=private_key,
                           display_full_email_body=display_full_email_body, mark_fetched_read=mark_fetched_read,
                           redirect_uri=params.get('redirect_uri', ''), certificate_thumbprint=certificate_thumbprint,
                           refresh_token_param=refresh_token_param,
                           managed_identities_client_id=managed_identities_client_id)
    try:
        command = demisto.command()
        args = prepare_args(command, demisto.args())
        LOG(f'Command being called is {command}')

        if command == 'test-module':
            if managed_identities_client_id:
                client.test_connection()
                return_results('ok')
            else:
                # cannot use test module due to the lack of ability to set refresh token to integration context
                raise Exception("Please use !msgraph-mail-test instead")
        if command == 'msgraph-mail-test':
            return_results(client.test_connection())
        if command == 'msgraph-mail-auth-reset':
            return_results(reset_auth())
        if command == 'fetch-incidents':
            next_run, incidents = client.fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'msgraph-mail-create-draft':
            human_readable, ec, raw_response = client.create_draft_command(**args)
            return_outputs(human_readable, ec, raw_response)
        elif command == 'msgraph-mail-reply-to':
            human_readable = client.mail_reply_to_command(**args)  # pylint: disable=E1123
            return_outputs(human_readable)
        elif command == 'msgraph-mail-send-draft':
            human_readable = client.send_draft_command(**args)  # pylint: disable=E1123
            return_outputs(human_readable)
        elif command == 'send-mail':
            human_readable, ec = client.send_email_command(**args)
            return_outputs(human_readable, ec)
        elif command == 'reply-mail':
            return_results(client.reply_mail_command(args))
        elif command == 'msgraph-mail-list-emails':
            return_results(list_mails_command(client, args))
        elif command == 'msgraph-mail-list-attachments':
            return_results(list_attachments_command(client, args))
        elif command == 'msgraph-mail-get-email-as-eml':
            return_results(get_email_as_eml_command(client, args))
        elif command == 'msgraph-update-email-status':
            return_results(update_email_status_command(client, args))
        elif command == 'msgraph-mail-generate-login-url':
            return_results(generate_login_url(client.ms_client))
    except Exception as e:
        return_error(str(e))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
