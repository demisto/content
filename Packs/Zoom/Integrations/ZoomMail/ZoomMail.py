import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
import json
import base64
import os
from dateparser import parse
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.header import Header
import mimetypes
from typing import List, Dict, Tuple


ZOOM_MAIL_COMMAND_PREFIX = 'zoom-mail'


class ZoomMailClient(BaseClient):
    def __init__(self, base_url, client_id, client_secret, account_id, verify=True, proxy=False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.account_id = account_id
        self.access_token = None
        self.token_time = None

    def obtain_access_token(self):
        """
        Obtains an access token using the 'account_credentials' grant type.
        """
        client_credentials = base64.b64encode(f'{self.client_id}:{self.client_secret}'.encode()).decode()

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {client_credentials}"
        }

        body = {
            "grant_type": "account_credentials",
            "account_id": self.account_id
        }

        response = super()._http_request(
            method='POST',
            full_url='https://zoom.us/oauth/token',
            headers=headers,
            data=body
        )

        access_token = response.get('access_token')
        if access_token:
            self.access_token = access_token
            self.token_time = time.time()
            return {'success': True, 'token': access_token}
        else:
            return {'success': False, 'error': "Failed to retrieve access token from ZoomMail API"}

    def _http_request(self, *args, **kwargs):
        """
        Override the _http_request method to include the access token in the headers.
        """
        if not self.access_token or (time.time() - self.token_time) >= 3500:
            self.obtain_access_token()
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self.access_token}'
        kwargs['headers'] = headers
        return super()._http_request(*args, **kwargs)

    def get_email_thread(self, email: str, thread_id: str, format: str = 'full', metadata_headers: str = '',
                         maxResults: str = '50', pageToken: str = ''):
        """
        Retrieves the specified email thread.

        :param email: The mailbox address, or "me" for the primary mailbox of the authenticated user.
        :param thread_id: The ID of the thread to retrieve.
        :param format: The format to return the messages in ('full', 'metadata', 'minimal').
        :param metadata_headers: When format is 'metadata', only include headers specified.
        :param maxResults: Maximum number of thread messages to return.
        :param pageToken: Page token to retrieve a specific page of results.
        """
        url_suffix = f'/emails/mailboxes/{email}/threads/{thread_id}'

        params = {
            'format': format,
            'metadata_headers': metadata_headers,
            'maxResults': maxResults,
            'pageToken': pageToken
        }

        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params
        )

        return response

    def trash_email(self, email: str, message_id: str):
        """
        Moves the specified message to the TRASH folder.

        :param email: The mailbox address, or "me" for the primary mailbox of the authenticated user.
        :param message_id: The ID of the message to be trashed.
        """
        url_suffix = f'/emails/mailboxes/{email}/messages/{message_id}/trash'

        response = self._http_request(
            method='POST',
            url_suffix=url_suffix
        )

        return response

    def list_emails(self, email: str, max_results: str = '50', page_token: str = '', label_ids: str = '', query: str = '',
                    include_spam_trash: bool = False):
        """
        Lists the messages in the user's mailbox.

        :param email: The mailbox address, or "me" for the primary mailbox of the authenticated user.
        :param max_results: Maximum number of messages to return (defaults to 50).
        :param page_token: Page token to retrieve a specific page of results.
        :param label_ids: Filter messages by label IDs.
        :param query: Filter messages by search query.
        :param include_spam_trash: Whether to include messages from SPAM and TRASH.
        """
        url_suffix = f'/emails/mailboxes/{email}/messages'

        params = {
            'maxResults': max_results,
            'pageToken': page_token,
            'q': query,
            'includeSpamTrash': str(include_spam_trash).lower()
        }

        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params
        )

        return response

    def get_email_attachment(self, email: str, message_id: str, attachment_id: str):
        """
        Retrieves the specified message attachment.

        :param email: The mailbox address, or "me" for the primary mailbox of the authenticated user.
        :param message_id: The ID of the message to retrieve the attachment from.
        :param attachment_id: The ID of the attachment to retrieve.
        """
        url_suffix = f'/emails/mailboxes/{email}/messages/{message_id}/attachments/{attachment_id}'

        response = self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

        return response

    def get_email_message(self, email: str, message_id: str, format: str = 'full', metadata_headers: str = ''):
        """
        Retrieves the specified email message.

        :param email: The mailbox address, or "me" for the primary mailbox of the authenticated user.
        :param message_id: The ID of the message to retrieve.
        :param format: The format to return the message with ('full', 'minimal', 'metadata', 'raw').
        :param metadata_headers: When requested format is 'metadata', only include headers specified in this parameter.
        """
        url_suffix = f'/emails/mailboxes/{email}/messages/{message_id}'

        params = {
            'format': format,
            'metadata_headers': metadata_headers
        }

        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params
        )

        return response

    def send_email(self, email, raw_message):
        """
        Sends a preformatted email message.

        :param email: The mailbox address to send the email from, or "me" to indicate the primary mailbox of the authenticated user.
        :param raw_message: The entire email message in an RFC 2822 formatted and base64url encoded string.
        """
        url_suffix = f'/emails/mailboxes/{email}/messages/send'
        body = {"raw": raw_message}
        response = self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=body
        )
        return response

    def get_mailbox_profile(self, email: str):
        """
        Retrieves the mailbox profile.

        :param email: The mailbox address, or "me" for the primary mailbox of the authenticated user.
        """
        url_suffix = f'/emails/mailboxes/{email}/profile'

        response = self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

        return response

    def list_users(self, status="active", page_size=30, role_id="", page_number="1", include_fields="", next_page_token="",
                   license=""):
        params = {
            "status": status,
            "page_size": page_size,
            "role_id": role_id,
            "page_number": page_number,
            "include_fields": include_fields,
            "next_page_token": next_page_token,
            "license": license
        }
        return self._http_request(
            method='GET',
            url_suffix='/users',
            params=params
        )


def testing_module(client: ZoomMailClient) -> str:
    """
    Tests authentication for the ZoomMail API by attempting to obtain an access token.
    """
    token_response = client.obtain_access_token()

    if token_response.get('success'):
        return 'ok'
    else:
        error_message = token_response.get('error', 'Unknown error occurred.')
        return f'Authorization Error: {error_message}'


def fetch_incidents(client: ZoomMailClient, params: dict) -> None:
    """
    Fetches email messages from ZoomMail API and creates incidents.

    :param client: The ZoomMailClient instance.
    """
    fetch_from = params.get('fetch_from')
    fetch_query = params.get('fetch_query', '')
    first_fetch_time = params.get('first_fetch', '3 days')

    max_fetch = min(int(params.get('max_fetch', 50)), 200)

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch')
    processed_ids: Set[str] = set(last_run.get('processed_ids', []))

    if not last_fetch:
        first_fetch_dt = parse(first_fetch_time)
        if not first_fetch_dt:
            first_fetch_dt = datetime.now() - timedelta(days=3)
        last_fetch = first_fetch_dt.timestamp()

    new_last_fetch = last_fetch
    new_processed_ids = processed_ids.copy()

    incidents: List[Dict[str, Any]] = []

    query = fetch_query + f' after:{int(last_fetch)}'
    messages_response = client.list_emails(email=fetch_from, max_results=str(max_fetch), query=query)
    messages = messages_response.get('messages', [])
    message_dates: List[float] = []

    for msg in messages:
        message_id = msg.get('id')
        thread_id = msg.get('threadId', '')
        message_details = client.get_email_message(email=fetch_from, message_id=message_id)
        internal_date = float(message_details.get('internalDate')) / 1000.0

        if internal_date > last_fetch and message_id not in processed_ids and message_id == thread_id:
            labels = create_incident_labels(message_details)
            incident = zoom_mail_to_incident(message_details, client, fetch_from)
            incidents.append(incident)
            new_processed_ids.add(message_id)
            message_dates.append(internal_date)

    if message_dates:
        new_last_fetch = min(message_dates)

    demisto.setLastRun({
        'last_fetch': new_last_fetch,
        'processed_ids': list(new_processed_ids)
    })

    demisto.incidents(incidents)



""" COMMAND FUNCTIONS """


def get_email_thread_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email')
    thread_id = args.get('thread_id')
    format = args.get('format', 'full')
    metadata_headers = args.get('metadata_headers', '')
    maxResults = args.get('max_results', '50')
    pageToken = args.get('page_token', '')

    if not email or not thread_id:
        raise ValueError("Both 'email' and 'thread_id' arguments are required.")

    response = client.get_email_thread(email, thread_id, format, metadata_headers, maxResults, pageToken)

    if 'messages' in response:
        readable_output = f'Email Thread {thread_id} in mailbox {email}:\n' + '\n'.join(
            [f'- Message ID: {msg["id"]}' for msg in response['messages']])
    else:
        readable_output = f'Email Thread {thread_id} in mailbox {email} has no messages.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='ZoomMail.EmailThread',
        outputs_key_field='id',
        outputs=response
    )


def trash_email_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email')
    message_id = args.get('message_id')

    if not email or not message_id:
        raise ValueError("Both 'email' and 'message_id' arguments are required.")

    response = client.trash_email(email, message_id)

    readable_output = f'Message with ID {message_id} was moved to TRASH.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='ZoomMail.TrashedEmail',
        outputs_key_field='id',
        outputs=response
    )


def list_emails_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email')
    max_results = args.get('max_results', '50')
    page_token = args.get('page_token', '')
    label_ids = args.get('label_ids', '')
    query = args.get('query', '')
    include_spam_trash = args.get('include_spam_trash', 'false').lower() in ['true', '1', 't', 'y', 'yes']

    response = client.list_emails(email, max_results, page_token, label_ids, query, include_spam_trash)

    messages = response.get('messages', [])
    readable_output = f'Messages in mailbox {email}:\n' + '\n'.join(
        [f'- ID: {msg["id"]} Thread ID: {msg.get("threadId", "N/A")}' for msg in messages])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='ZoomMail.Emails',
        outputs_key_field='id',
        outputs=messages
    )


def get_email_message_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email')
    message_id = args.get('message_id')
    format = args.get('format', 'full')
    metadata_headers = args.get('metadata_headers', '')

    if not email or not message_id:
        raise ValueError("Both 'email' and 'message_id' arguments are required.")

    message = client.get_email_message(email, message_id, format, metadata_headers)

    message_payload = message.get('payload', [])
    body, html, attachments = parse_mail_parts([message_payload])

    human_readable = f"### Email Message {message_id}\n" \
                     f"* **From**: {message.get('from')}\n" \
                     f"* **To**: {message.get('to')}\n" \
                     f"* **Subject**: {message.get('subject')}\n" \
                     f"* **Date**: {message.get('date')}\n\n" \
                     f"**Body:**\n{body}\n\n" \
                     f"**HTML:**\n{html}\n\n" \
                     f"**Attachments:**\n{attachments}"

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='ZoomMail.EmailMessage',
        outputs_key_field='id',
        outputs=message
    )


def get_email_attachment_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email')
    message_id = args.get('message_id')
    attachment_id = args.get('attachment_id')

    if not email or not message_id or not attachment_id:
        raise ValueError("The 'email', 'message_id', and 'attachment_id' arguments are required.")

    attachment = client.get_email_attachment(email, message_id, attachment_id)

    if 'data' in attachment and attachment['data']:
        attachment_data = base64.urlsafe_b64decode(attachment['data'].encode('ascii'))
        file_result = fileResult(f"{attachment_id}", attachment_data)
        return_results(file_result)

        return CommandResults(
            readable_output=f"Attachment with ID {attachment_id} retrieved successfully.",
            raw_response=attachment,
            outputs_prefix='ZoomMail.EmailAttachment',
            outputs_key_field='attachmentId',
            outputs=attachment
        )
    else:
        return CommandResults(readable_output=f"No data found for attachment ID {attachment_id}.")


def get_mailbox_profile_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email')

    if not email:
        raise ValueError("The 'email' argument is required.")

    profile = client.get_mailbox_profile(email)

    #TODO: This should probably be handled differently
    readable_output = f"### Mailbox Profile for {email}\n" \
                      f"* **Email Address**: {profile.get('emailAddress')}\n" \
                      f"* **Group Emails**: {', '.join(profile.get('groupEmails', []))}\n" \
                      f"* **Creation Time**: {datetime.utcfromtimestamp(profile.get('createTime')).strftime('%Y-%m-%dT%H:%M:%SZ') if profile.get('createTime') else 'N/A'}\n" \
                      f"* **Status**: {profile.get('status')}\n" \
                      f"* **Mailbox Size**: {profile.get('mboxSize')} bytes\n" \
                      f"* **Total Messages**: {profile.get('messagesTotal')}\n" \
                      f"* **Total Threads**: {profile.get('threadsTotal')}\n" \
                      f"* **Encryption Enabled**: {'Yes' if profile.get('encryptionEnabled') else 'No'}\n" \
                      f"* **Label Encryption Enabled**: {'Yes' if profile.get('labelEncryptionEnabled') else 'No'}\n" \
                      f"* **Last History ID**: {profile.get('historyId')}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='ZoomMail.MailboxProfile',
        outputs_key_field='emailAddress',
        outputs=profile
    )


def list_users_command(client, args):
    status = args.get('status', 'active')
    page_size = args.get('page_size', 30)
    role_id = args.get('role_id', '')
    page_number = args.get('page_number', '1')
    include_fields = args.get('include_fields', '')
    next_page_token = args.get('next_page_token', '')
    license = args.get('license', '')

    response = client.list_users(status, page_size, role_id, page_number, include_fields, next_page_token, license)
    users = response.get('users', [])

    readable_output = f"### Zoom Mail Users\n"
    readable_output += tableToMarkdown('Users', users, headers=['email', 'first_name', 'last_name', 'type', 'status'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='ZoomMail.Users',
        outputs_key_field='id',
        outputs=users
    )


def send_email_command(client, args):
    email = args.get('from')
    subject = args.get('subject')
    body = args.get('body')
    html_body = args.get('html_body', '')
    entry_ids = argToList(args.get('attachments', []))
    recipients = args.get('to')

    message = MIMEMultipart('mixed' if html_body or entry_ids else 'alternative')
    message['From'] = email
    message['To'] = recipients
    message['Subject'] = subject

    if body:
        message.attach(MIMEText(body, 'plain'))
    if html_body:
        message.attach(MIMEText(html_body, 'html'))

    for entry_id in entry_ids:
        res = demisto.getFilePath(entry_id)
        if res and 'path' in res:
            file_path = res['path']
            file_name = res['name']
            part = MIMEBase('application', "octet-stream")
            with open(file_path, 'rb') as file:
                part.set_payload(file.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment', filename=file_name)
            message.attach(part)

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    response = client.send_email(email, raw_message)
    if response.get('id'):
        return CommandResults(readable_output=f"Email sent successfully with ID: {response['id']}")
    else:
        return CommandResults(readable_output="Failed to send email.")


""" HELPER FUNCtIONS """


def parse_mail_parts(parts: List[Dict[str, Any]]) -> Tuple[str, str, List[Dict[str, str]]]:
    body = ''
    html = ''
    attachments = []

    for part in parts:
        if 'multipart' in part['mimeType'] and 'parts' in part:
            part_body, part_html, part_attachments = parse_mail_parts(part['parts'])
            body += part_body
            html += part_html
            attachments.extend(part_attachments)
        elif not part.get('filename'):
            text = base64.urlsafe_b64decode(part['body'].get('data', '').encode('ascii')).decode('utf-8')
            if 'text/html' in part['mimeType']:
                html += text
            else:
                body += text
        else:
            if 'attachmentId' in part['body']:
                attachments.append({
                    'ID': part['body']['attachmentId'],
                    'Name': part['filename'],
                    'Size': part['body'].get('size')
                })

    return body, html, attachments


def create_incident_labels(message_details):
    headers = message_details.get('payload', {}).get('headers', [])
    headers_dict = {header['name']: header['value'] for header in headers}

    labels = [
        {'type': 'Email/ID', 'value': message_details.get('id')},
        {'type': 'Email/subject', 'value': message_details.get('subject', '')},
        {'type': 'Email/text', 'value': message_details.get('snippet', '')},
        {'type': 'Email/from', 'value': headers_dict.get('From', '')},
        {'type': 'Email/html', 'value': headers_dict.get('Html', '')},
    ]
    labels.extend([{'type': 'Email/to', 'value': to} for to in headers_dict.get('To', '').split(',')])
    labels.extend([{'type': 'Email/cc', 'value': cc} for cc in headers_dict.get('Cc', '').split(',')])
    labels.extend([{'type': 'Email/bcc', 'value': bcc} for bcc in headers_dict.get('Bcc', '').split(',')])

    for key, val in headers_dict.items():
        labels.append({'type': 'Email/Header/' + key, 'value': val})

    return labels


def zoom_mail_to_incident(msg, client, email):
    body_content, html_content, attachments = parse_mail_parts(msg['payload']['parts'])
    occurred_str = datetime.utcfromtimestamp(int(msg['internalDate']) / 1000).isoformat() + 'Z'

    headers_list = msg['payload'].get('headers', [])
    subject = "No Subject"
    for header in headers_list:
        if header['name'].lower() == 'subject':
            subject = header['value']
            break

    file_names = []

    if 'attachments' in msg:
        for attachment in msg['attachments']:
            try:
                attachment_data = client.get_email_attachment(email, msg['id'], attachment['ID'])
                if attachment_data.get('data'):
                    file_data = base64.urlsafe_b64decode(attachment_data['data'].encode('ascii'))
                    file_result = fileResult(attachment['Name'], file_data)

                    if file_result['Type'] == entryTypes['error']:
                        demisto.error(file_result['Contents'])
                        continue

                    file_names.append({
                        'path': file_result['FileID'],
                        'name': attachment['Name'],
                    })
            except Exception as e:
                demisto.error(f"Failed to retrieve attachment {attachment['ID']} from message {msg['id']}: {str(e)}")

    incident = {
        'type': 'ZoomMail',
        'name': subject,
        'details': body_content,
        'labels': create_incident_labels(msg),
        'occurred': occurred_str,
        'attachment': file_names,
        'rawJSON': json.dumps(msg),
    }
    return incident


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    client_id = params.get('credentials', {}).get('identifier') or params().get('client_id')
    client_secret = params.get('credentials', {}).get('password') or params().get('client_secret')
    account_id = params.get('account_id')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = ZoomMailClient(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        account_id=account_id,
        verify=verify_certificate,
        proxy=proxy
    )

    command = demisto.command()
    params = demisto.params()

    COMMAND_FUNCTIONS = {
        'fetch-incidents': fetch_incidents,
        'test-module': testing_module,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-trash-email': trash_email_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-list-emails': list_emails_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-get-email-thread': get_email_thread_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-get-email-attachment': get_email_attachment_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-get-email-message': get_email_message_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-send-email': send_email_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-get-mailbox-profile': get_mailbox_profile_command,
        f'{ZOOM_MAIL_COMMAND_PREFIX}-list-users': list_users_command,
    }
    if command in COMMAND_FUNCTIONS:
        function_to_execute = COMMAND_FUNCTIONS[command]
        return_results(function_to_execute(client, args, params))
    else:
        raise NotImplementedError(f"Command '{command}' is not implemented.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
