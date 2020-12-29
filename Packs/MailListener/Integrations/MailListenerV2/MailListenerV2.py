import ssl
from datetime import timezone
from typing import Any, Dict, Tuple, List, Optional

from dateparser import parse
from mailparser import parse_from_bytes
from imap_tools import OR
from imapclient import IMAPClient

import demistomock as demisto
from CommonServerPython import *


class Email(object):
    def __init__(self, message_bytes: bytes, include_raw_body: bool, save_file: bool, id_: int) -> None:
        """
        Initialize Email class with all relevant data
        Args:
            id_: The unique ID with which the email can be fetched from the server specifically
            message_bytes: The raw email bytes
            include_raw_body: Whether to include the raw body of the mail in the incident's body
            save_file: Whether to save the .eml file of the incident's mail
        """
        email_object = parse_from_bytes(message_bytes)
        self.id = id_
        self.mail_bytes = message_bytes
        self.to = [mail_addresses for _, mail_addresses in email_object.to]
        self.cc = [mail_addresses for _, mail_addresses in email_object.cc]
        self.bcc = [mail_addresses for _, mail_addresses in email_object.bcc]
        self.attachments = email_object.attachments
        self.from_ = [mail_addresses for _, mail_addresses in email_object.from_][0]
        self.format = email_object.message.get_content_type()
        self.html = email_object.text_html[0] if email_object.text_html else ''
        self.text = email_object.text_plain[0] if email_object.text_plain else ''
        self.subject = email_object.subject
        self.headers = email_object.headers
        self.raw_body = email_object.body if include_raw_body else None
        # According to the mailparser documentation the datetime object is in utc
        self.date = email_object.date.replace(tzinfo=timezone.utc)
        self.raw_json = self.generate_raw_json()
        self.save_eml_file = save_file
        self.labels = self._generate_labels()

    def _generate_labels(self) -> List[Dict[str, str]]:
        """
        Generates the labels needed for the incident
        Returns:
            A list of dicts with the form {type: <label name>, value: <label-value>}
        """
        labels = [{'type': 'Email/headers', 'value': json.dumps(self.headers)},
                  {'type': 'Email/from', 'value': self.from_},
                  {'type': 'Email/format', 'value': self.format},
                  {'type': 'Email/text', 'value': self.text},
                  {'type': 'Email/subject', 'value': self.subject},
                  ]
        labels.extend([
            {'type': f'Email/headers/{header_name}',
             'value': header_value} for header_name, header_value in self.headers.items()
        ])
        labels.extend([{'type': 'Email', 'value': mail_to} for mail_to in self.to])
        labels.extend([{'type': 'Email/cc', 'value': cc_mail} for cc_mail in self.cc])
        labels.extend([{'type': 'Email/bcc', 'value': bcc_mail} for bcc_mail in self.bcc])
        if self.html:
            labels.append({'type': 'Email/html', 'value': self.html})
        if self.attachments:
            labels.append({'type': 'Email/attachments',
                           'value': ','.join([attachment['filename'] for attachment in self.attachments])})
        return labels

    def parse_attachments(self) -> list:
        """
        Writes the attachments of the files and returns a list of file entry details.
        If self.save_eml_file is set, will also save the email itself as file
        Returns:
            A list of the written files entries
        """
        files = []
        for attachment in self.attachments:
            payload = attachment.get('payload')

            file_data = base64.b64decode(payload) if attachment.get('binary') else payload

            # save the attachment
            file_result = fileResult(attachment.get('filename'), file_data, attachment.get('mail_content_type'))

            # check for error
            if file_result['Type'] == entryTypes['error']:
                demisto.error(file_result['Contents'])

            files.append({
                'path': file_result['FileID'],
                'name': file_result['File']
            })
        if self.save_eml_file:
            file_result = fileResult('original-email-file.eml', self.mail_bytes)
            files.append({
                'path': file_result['FileID'],
                'name': file_result['File']
            })
        return files

    def convert_to_incident(self) -> Dict[str, Any]:
        """
        Convert an Email class instance to a demisto incident
        Returns:
            A dict with all relevant fields for an incident
        """
        return {
            'labels': self._generate_labels(),
            'occurred': self.date.isoformat(),
            'created': datetime.now(timezone.utc).isoformat(),
            'details': self.text or self.html,
            'name': self.subject,
            'attachment': self.parse_attachments(),
            'rawJSON': json.dumps(self.raw_json)
        }

    def generate_raw_json(self, parse_attachments: bool = False) -> dict:
        """

        Args:
            parse_attachments: whether to parse the attachments and write them to files
            during the execution of this method or not.
        """
        raw_json = {
            'to': ','.join(self.to),
            'cc': ','.join(self.cc),
            'bcc': ','.join(self.bcc),
            'from': self.from_,
            'format': self.format,
            'text': self.text,
            'subject': self.subject,
            'attachments': self.parse_attachments() if parse_attachments else ','.join(
                [attachment['filename'] for attachment in self.attachments]),
            'rawHeaders': self.parse_raw_headers(),
            'headers': remove_empty_elements(self.headers)
        }
        if self.html:
            raw_json['HTML'] = self.html
        if self.raw_body:
            raw_json['rawBody'] = self.raw_body
        return raw_json

    def parse_raw_headers(self) -> str:
        """
        Parses the dict with the mail headers into a string representation

        Returns:
            A string representation of the headers with the form  <key>: <value>\n for al keys and values in the headers dict
        """
        headers_string_lines = [f'{key}: {value}' for key, value in self.headers.items()]
        return '\n'.join(headers_string_lines)


def fetch_incidents(client: IMAPClient,
                    last_run: dict,
                    first_fetch_time: str,
                    include_raw_body: bool,
                    permitted_from_addresses: str,
                    permitted_from_domains: str,
                    delete_processed: bool,
                    limit: int,
                    save_file: bool
                    ) -> Tuple[dict, list]:
    """
    This function will execute each interval (default is 1 minute).
    The search is based on the criteria of the SINCE time and the UID.
    We will always store the latest email message UID that came up in the search, even if it will not be ingested as
    incident (can happen in the first fetch where the email messages that were returned from the search are before the
    value that was set in the first fetch parameter).
    This is required because the SINCE criterion disregards the time and timezone (i.e. considers only the date),
    so it might be that in the first fetch we will fetch only email messages that are occurred before the first fetch
    time (could also happen that the limit parameter, which is implemented in the code and cannot be passed as a
    criterion to the search, causes us to keep retrieving the same email messages in the search result)
    The SINCE criterion will be sent only for the first fetch, and then the fetch will be by UID

    Args:
        client: IMAP client
        last_run: The greatest incident created_time we fetched from last fetch
        first_fetch_time: If last_run is None then fetch all incidents since first_fetch_time
        include_raw_body: Whether to include the raw body of the mail in the incident's body
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from
        delete_processed: Whether to delete processed mails
        limit: The maximum number of incidents to fetch each time
        save_file: Whether to save the .eml file of the incident's mail

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    uid_to_fetch_from = last_run.get('last_uid', 1)
    # time_to_fetch_from is required only for the first fetch, as after that we will use UID to fetch from
    time_to_fetch_from = parse(f'{first_fetch_time} UTC') if not last_run else None
    if uid_to_fetch_from == 1 and last_run.get('last_fetch'):
        # for back compatibility, if an instance was using the timestamp and was upgraded to use UID
        time_to_fetch_from = datetime.fromisoformat(last_run.get('last_fetch'))
    mails_fetched, messages, uid_to_fetch_from = fetch_mails(
        client=client,
        include_raw_body=include_raw_body,
        time_to_fetch_from=time_to_fetch_from,
        limit=limit,
        permitted_from_addresses=permitted_from_addresses,
        permitted_from_domains=permitted_from_domains,
        save_file=save_file,
        uid_to_fetch_from=uid_to_fetch_from
    )
    incidents = []
    for mail in mails_fetched:
        incidents.append(mail.convert_to_incident())
        uid_to_fetch_from = max(uid_to_fetch_from, mail.id)
    next_run = {'last_uid': uid_to_fetch_from}
    if delete_processed:
        client.delete_messages(messages)
    return next_run, incidents


def fetch_mails(client: IMAPClient,
                time_to_fetch_from: datetime = None,
                permitted_from_addresses: str = '',
                permitted_from_domains: str = '',
                include_raw_body: bool = False,
                limit: int = 200,
                save_file: bool = False,
                message_id: int = None,
                uid_to_fetch_from: int = 1) -> Tuple[list, list, int]:
    """
    This function will fetch the mails from the IMAP server.

    Args:
        client: IMAP client
        time_to_fetch_from: Fetch all incidents since first_fetch_time
        include_raw_body: Whether to include the raw body of the mail in the incident's body
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from
        limit: The maximum number of incidents to fetch each time, if the value is -1 all
               mails will be fetched (used with list-messages command)
        save_file: Whether to save the .eml file of the incident's mail
        message_id: A unique message ID with which a specific mail can be fetched
        uid_to_fetch_from: The email message UID to start the fetch from as offset

    Returns:
        mails_fetched: A list of Email objects
        messages_fetched: A list of the ids of the messages fetched
        last_message_in_current_batch: The UID of the last message fetchedd
    """
    if message_id:
        messages_uids = [message_id]
    else:
        messages_query = generate_search_query(time_to_fetch_from,
                                               permitted_from_addresses,
                                               permitted_from_domains,
                                               uid_to_fetch_from)
        demisto.debug(f'Searching for email messages with criteria: {messages_query}')
        messages_uids = client.search(messages_query)[:limit]
    mails_fetched = []
    messages_fetched = []
    demisto.debug(f'Messages to fetch: {messages_uids}')
    for mail_id, message_data in client.fetch(messages_uids, 'RFC822').items():
        message_bytes = message_data.get(b'RFC822')
        if not message_bytes:
            continue
        email_message_object = Email(message_bytes, include_raw_body, save_file, mail_id)
        if (time_to_fetch_from and time_to_fetch_from < email_message_object.date) or \
                int(email_message_object.id) > int(uid_to_fetch_from):
            mails_fetched.append(email_message_object)
            messages_fetched.append(email_message_object.id)
        else:
            demisto.debug(f'Skipping {email_message_object.id} with date {email_message_object.date}. '
                          f'uid_to_fetch_from: {uid_to_fetch_from}, first_fetch_time: {time_to_fetch_from}')
    last_message_in_current_batch = uid_to_fetch_from
    if messages_uids:
        last_message_in_current_batch = messages_uids[-1]

    return mails_fetched, messages_fetched, last_message_in_current_batch


def generate_search_query(time_to_fetch_from: Optional[datetime],
                          permitted_from_addresses: str,
                          permitted_from_domains: str,
                          uid_to_fetch_from: int) -> list:
    """
    Generates a search query for the IMAP client 'search' method. with the permitted domains, email addresses and the
    starting date from which mail should be fetched.
    Input example:
    time_to_fetch_from: datetime.datetime(2020, 8, 7, 12, 14, 32, 918634, tzinfo=datetime.timezone.utc)
    permitted_from_addresses: ['test1@mail.com', 'test2@mail.com']
    permitted_from_domains: ['test1.com', 'domain2.com']
    output example:
    ['OR',
     'OR',
     'OR',
     'FROM',
     'test1@mail.com',
     'FROM',
     'test2@mail.com',
     'FROM',
     'test1.com',
     'FROM',
     'domain2.com',
     'SINCE',
     datetime.datetime(2020, 8, 7, 12, 14, 32, 918634, tzinfo=datetime.timezone.utc)]
    Args:
        time_to_fetch_from: The greatest incident created_time we fetched from last fetch
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from
        uid_to_fetch_from: The email message UID to start the fetch from as offset

    Returns:
        A list with arguments for the email search query
    """
    permitted_from_addresses_list = argToList(permitted_from_addresses)
    permitted_from_domains_list = argToList(permitted_from_domains)
    messages_query = ''
    if permitted_from_addresses_list + permitted_from_domains_list:
        messages_query = OR(from_=permitted_from_addresses_list + permitted_from_domains_list).format()
        # Removing Parenthesis and quotes
        messages_query = messages_query.strip('()').replace('"', '')
    # Creating a list of the OR query words
    messages_query_list = messages_query.split()
    if time_to_fetch_from:
        messages_query_list += ['SINCE', time_to_fetch_from]  # type: ignore[list-item]
    if uid_to_fetch_from:
        messages_query_list += ['UID', f'{uid_to_fetch_from}:*']
    return messages_query_list


def test_module(client: IMAPClient) -> str:
    yesterday = parse('1 day UTC')
    client.search(['SINCE', yesterday])
    return 'ok'


def list_emails(client: IMAPClient,
                first_fetch_time: str,
                permitted_from_addresses: str,
                permitted_from_domains: str) -> CommandResults:
    """
    Lists all emails that can be fetched with the given configuration and return a preview version of them.
    Args:
        client: IMAP client
        first_fetch_time: Fetch all incidents since first_fetch_time
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from

    Returns:
        The Subject, Date, To, From and ID of the fetched mails wrapped in command results object.
    """
    fetch_time = parse(f'{first_fetch_time} UTC')

    mails_fetched, _, _ = fetch_mails(client=client,
                                      time_to_fetch_from=fetch_time,
                                      permitted_from_addresses=permitted_from_addresses,
                                      permitted_from_domains=permitted_from_domains)
    results = [{'Subject': email.subject,
                'Date': email.date.isoformat(),
                'To': email.to,
                'From': email.from_,
                'ID': email.id} for email in mails_fetched]

    return CommandResults(outputs_prefix='MailListener.EmailPreview',
                          outputs_key_field='ID',
                          outputs=results)


def get_email(client: IMAPClient, message_id: int) -> CommandResults:
    mails_fetched, _, _ = fetch_mails(client, message_id=message_id)
    mails_json = [mail.generate_raw_json(parse_attachments=True) for mail in mails_fetched]
    return CommandResults(outputs_prefix='MailListener.Email',
                          outputs_key_field='ID',
                          outputs=mails_json)


def get_email_as_eml(client: IMAPClient, message_id: int) -> dict:
    mails_fetched, _, _ = fetch_mails(client, message_id=message_id)
    mail_file = [fileResult('original-email-file.eml', mail.mail_bytes) for mail in mails_fetched]
    return mail_file[0] if mail_file else {}


def main():
    params = demisto.params()
    mail_server_url = params.get('MailServerURL')
    port = int(params.get('port'))
    folder = params.get('folder')
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    verify_ssl = not params.get('insecure', False)
    tls_connection = params.get('TLS_connection', True)
    include_raw_body = demisto.params().get('Include_raw_body', False)
    permitted_from_addresses = demisto.params().get('permittedFromAdd', '')
    permitted_from_domains = demisto.params().get('permittedFromDomain', '')
    delete_processed = demisto.params().get("delete_processed", False)
    limit = min(int(demisto.params().get('limit', '50')), 200)
    save_file = params.get('save_file', False)
    first_fetch_time = demisto.params().get('first_fetch', '3 days').strip()
    ssl_context = ssl.create_default_context()

    args = demisto.args()
    if not verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    LOG(f'Command being called is {demisto.command()}')
    try:
        with IMAPClient(mail_server_url, ssl=tls_connection, port=port, ssl_context=ssl_context) as client:
            client.login(username, password)
            client.select_folder(folder)
            if demisto.command() == 'test-module':
                result = test_module(client)
                demisto.results(result)
            elif demisto.command() == 'mail-listener-list-emails':
                return_results(list_emails(client=client,
                                           first_fetch_time=first_fetch_time,
                                           permitted_from_addresses=permitted_from_addresses,
                                           permitted_from_domains=permitted_from_domains))
            elif demisto.command() == 'mail-listener-get-email':
                return_results(get_email(client=client,
                                         message_id=args.get('message-id')))
            elif demisto.command() == 'mail-listener-get-email-as-eml':
                return_results(get_email_as_eml(client=client,
                                                message_id=args.get('message-id')))
            elif demisto.command() == 'fetch-incidents':
                next_run, incidents = fetch_incidents(client=client, last_run=demisto.getLastRun(),
                                                      first_fetch_time=first_fetch_time,
                                                      include_raw_body=include_raw_body,
                                                      permitted_from_addresses=permitted_from_addresses,
                                                      permitted_from_domains=permitted_from_domains,
                                                      delete_processed=delete_processed, limit=limit,
                                                      save_file=save_file)

                demisto.setLastRun(next_run)
                demisto.incidents(incidents)
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
