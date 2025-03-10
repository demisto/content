import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import ssl
import email
from datetime import timezone
from typing import Any
from email.message import Message
from dateparser import parse
from mailparser import parse_from_bytes, parse_from_string
from imap_tools import OR
from imapclient import IMAPClient
from tempfile import NamedTemporaryFile


class Email:
    def __init__(self, message_bytes: bytes, include_raw_body: bool, save_file: bool, id_: int) -> None:
        """
        Initialize Email class with all relevant data
        Args:
            id_: The unique ID with which the email can be fetched from the server specifically
            message_bytes: The raw email bytes
            include_raw_body: Whether to include the raw body of the mail in the incident's body
            save_file: Whether to save the .eml file of the incident's mail
        """
        self.mail_bytes = message_bytes
        try:
            email_object = parse_from_bytes(message_bytes)
        except UnicodeDecodeError as e:
            demisto.info(
                f"Failed parsing mail from bytes: [{e}]\n{traceback.format_exc()}."
                "\nWill replace backslash and try to parse again"
            )
            message_bytes = self.handle_message_slashes(message_bytes)
            email_object = parse_from_bytes(message_bytes)
        except TypeError as e:
            demisto.info(f"Failed parsing mail from bytes: [{e}]\n{traceback.format_exc()}." "\nWill try to parse from string")
            message_string = message_bytes.decode("ISO-8859-1")
            email_object = parse_from_string(message_string)

        eml_attachments = self.get_eml_attachments(message_bytes)
        self.id = id_
        self.to = [mail_addresses for _, mail_addresses in email_object.to]
        self.cc = [mail_addresses for _, mail_addresses in email_object.cc]
        self.bcc = [mail_addresses for _, mail_addresses in email_object.bcc]
        self.attachments = email_object.attachments
        self.attachments.extend(eml_attachments)
        self.from_ = [mail_addresses for _, mail_addresses in email_object.from_][0]
        self.format = email_object.message.get_content_type()
        self.html = email_object.text_html[0] if email_object.text_html else ""
        self.text = email_object.text_plain[0] if email_object.text_plain else ""
        self.subject = email_object.subject
        self.headers = email_object.headers
        self.raw_body = email_object.body if include_raw_body else None
        # According to the mailparser documentation the datetime object is in utc
        self.date = email_object.date.replace(tzinfo=timezone.utc) if email_object.date else None  # noqa: UP017
        self.raw_json = self.generate_raw_json()
        self.save_eml_file = save_file
        self.labels = self._generate_labels()
        self.message_id = email_object.message_id

    @staticmethod
    def get_eml_attachments(message_bytes: bytes) -> list:
        def get_attachment_payload(part: Message) -> bytes:
            """Returns the payload of the email attachment as bytes object"""
            payload = part.get_payload(decode=False)
            if isinstance(payload, list) and isinstance(payload[0], Message):
                payload = payload[0].as_bytes()
            elif isinstance(payload, str):
                payload = payload.encode("utf-8")
            else:
                raise DemistoException(f"Could not parse the email attachment: {part.get_filename()}")

            return payload

        eml_attachments = []
        msg = email.message_from_bytes(message_bytes)

        if msg:
            for part in msg.walk():
                if part.get_content_maintype() == "multipart" or part.get("Content-Disposition") is None:
                    continue

                filename = part.get_filename()
                if filename and filename.endswith(".eml"):
                    eml_attachments.append(
                        {
                            "filename": filename,
                            "payload": get_attachment_payload(part),
                            "binary": False,
                            "mail_content_type": part.get_content_subtype(),
                            "content-id": part.get("content-id"),
                            "content-disposition": part.get("content-disposition"),
                            "charset": part.get_content_charset(),
                            "content_transfer_encoding": part.get_content_charset(),
                        }
                    )

        return eml_attachments

    @staticmethod
    def handle_message_slashes(message_bytes: bytes) -> bytes:
        """
        Handles the case where message bytes containing backslashes  which needs escaping
        Returns:
            The message bytes after escaping
        """

        #   Input example # 1:
        #       message_bytes = b'\\U'
        #   Output example # 1 (added escaping for the slash):
        #       b'\\\\U'
        #
        #   Input example # 2:
        #       message_bytes = b'\\\\U'
        #   Output example # 2 (no need to add escaping since the number of slashes is even):
        #       b'\\\\U'

        regex = re.compile(rb"\\+U", flags=re.IGNORECASE)

        def escape_message_bytes(m):
            s = m.group(0)
            if len(s) % 2 == 0:
                # The number of slashes prior to 'u' is odd - need to add one backslash
                s = b"\\" + s
            return s

        message_bytes = regex.sub(escape_message_bytes, message_bytes)
        return message_bytes

    def _generate_labels(self) -> list[dict[str, str]]:
        """
        Generates the labels needed for the incident
        Returns:
            A list of dicts with the form {type: <label name>, value: <label-value>}
        """
        labels = [
            {"type": "Email/headers", "value": json.dumps(self.headers)},
            {"type": "Email/from", "value": self.from_},
            {"type": "Email/format", "value": self.format},
            {"type": "Email/text", "value": self.text.strip()},
            {"type": "Email/subject", "value": self.subject},
        ]
        labels.extend(
            [
                {"type": f"Email/headers/{header_name}", "value": header_value}
                for header_name, header_value in self.headers.items()
            ]
        )
        labels.extend([{"type": "Email", "value": mail_to} for mail_to in self.to])
        labels.extend([{"type": "Email/cc", "value": cc_mail} for cc_mail in self.cc])
        labels.extend([{"type": "Email/bcc", "value": bcc_mail} for bcc_mail in self.bcc])
        if self.html:
            labels.append({"type": "Email/html", "value": self.html.strip()})
        if self.attachments:
            labels.append(
                {"type": "Email/attachments", "value": ",".join([attachment["filename"] for attachment in self.attachments])}
            )
        return labels

    def parse_attachments(self, output_to_warroom: bool = False) -> list:
        """
        Writes the attachments of the files and returns a list of file entry details.
        If self.save_eml_file is set, will also save the email itself as file
        Returns:
            A list of the written files entries
        """
        files = []
        for attachment in self.attachments:
            payload = attachment.get("payload")

            try:
                file_data = base64.b64decode(payload) if attachment.get("binary") else payload
            except Exception as e:
                file_data = payload
                demisto.error(f"parse_attachments: Failed to decode the attachment data - {str(e)}")

            # save the attachment
            file_result = fileResult(attachment.get("filename"), file_data)
            if output_to_warroom:
                demisto.results(file_result)

            # check for error
            if file_result["Type"] == entryTypes["error"]:
                demisto.error(file_result["Contents"])

            files.append({"path": file_result["FileID"], "name": file_result["File"]})
        if self.save_eml_file:
            file_result = fileResult("original-email-file.eml", self.mail_bytes)
            files.append({"path": file_result["FileID"], "name": file_result["File"]})
        return files

    def convert_to_incident(self) -> dict[str, Any]:
        """
        Convert an Email class instance to a demisto incident
        Returns:
            A dict with all relevant fields for an incident
        """
        date = self.date
        if not date:
            demisto.info(f"Could not identify date for mail with ID {self.id}. Setting its date to be now.")
            date = datetime.now(timezone.utc).isoformat()  # noqa: UP017
        else:
            date = self.date.isoformat()  # type: ignore[union-attr]
        return {
            "labels": self._generate_labels(),
            "occurred": date,
            "created": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "details": self.text or self.html,
            "name": self.subject,
            "attachment": self.parse_attachments(),
            "rawJSON": json.dumps(self.raw_json),
        }

    def generate_raw_json(self, parse_attachments: bool = False, output_to_warroom: bool = False) -> dict:
        """

        Args:
            parse_attachments: whether to parse the attachments and write them to files
            during the execution of this method or not.
        """
        raw_json = {
            "to": ",".join(self.to),
            "cc": ",".join(self.cc),
            "bcc": ",".join(self.bcc),
            "from": self.from_,
            "format": self.format,
            "text": self.text,
            "subject": self.subject,
            "attachments": self.parse_attachments(output_to_warroom)
            if parse_attachments
            else ",".join([attachment["filename"] for attachment in self.attachments]),
            "rawHeaders": self.parse_raw_headers(),
            "headers": remove_empty_elements(self.headers),
        }
        if self.html:
            raw_json["HTML"] = self.html
        if self.raw_body:
            raw_json["rawBody"] = self.raw_body
        return raw_json

    def parse_raw_headers(self) -> str:
        """
        Parses the dict with the mail headers into a string representation

        Returns:
            A string representation of the headers with the form  <key>: <value>\n for al keys and values in the headers dict
        """
        headers_string_lines = [f"{key}: {value}" for key, value in self.headers.items()]
        return "\n".join(headers_string_lines)


def fetch_incidents(
    client: IMAPClient,
    last_run: dict,
    first_fetch_time: str,
    include_raw_body: bool,
    with_headers: bool,
    permitted_from_addresses: str,
    permitted_from_domains: str,
    delete_processed: bool,
    limit: int,
    save_file: bool,
) -> tuple[dict | None, list]:
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
    We will continue using the first fetch time as it may take more than one fetch interval to get to the mail that
    was actually received after the first fetch time

    Args:
        client: IMAP client
        last_run: The greatest incident created_time we fetched from last fetch
        first_fetch_time: If last_run is None then fetch all incidents since first_fetch_time
        include_raw_body: Whether to include the raw body of the mail in the incident's body
        with_headers: Whether to add headers to the search query
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from
        delete_processed: Whether to delete processed mails
        limit: The maximum number of incidents to fetch each time
        save_file: Whether to save the .eml file of the incident's mail

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    logger(fetch_incidents)
    time_to_fetch_from = None
    # First fetch - using the first_fetch_time
    demisto.debug(f"{last_run=}")
    if not last_run:
        time_to_fetch_from = parse(f"{first_fetch_time} UTC", settings={"TIMEZONE": "UTC"})
        demisto.debug(f"no last_run, using {time_to_fetch_from=}")

    # Otherwise use the mail UID
    uid_to_fetch_from = arg_to_number(last_run.get("last_uid", 0))
    mails_fetched, messages, uid_to_fetch_from = fetch_mails(
        client=client,
        include_raw_body=include_raw_body,
        time_to_fetch_from=time_to_fetch_from,
        limit=limit,
        with_headers=with_headers,
        permitted_from_addresses=permitted_from_addresses,
        permitted_from_domains=permitted_from_domains,
        save_file=save_file,
        uid_to_fetch_from=uid_to_fetch_from,  # type: ignore[arg-type]
    )
    incidents: list = []
    demisto.debug(f"fetched {len(incidents)} incidents")
    for mail in mails_fetched:
        incidents.append(mail.convert_to_incident())
        uid_to_fetch_from = max(uid_to_fetch_from, mail.id)
    next_run = {"last_uid": str(uid_to_fetch_from)} if uid_to_fetch_from != 0 else None
    demisto.debug(f"{next_run=}")
    if delete_processed:
        client.delete_messages(messages)
    return next_run, incidents


def fetch_mails(
    client: IMAPClient,
    time_to_fetch_from: datetime | None = None,
    with_headers: bool = False,
    permitted_from_addresses: str = "",
    permitted_from_domains: str = "",
    include_raw_body: bool = False,
    limit: int = 200,
    save_file: bool = False,
    message_id: int | None = None,
    uid_to_fetch_from: int = 0,
) -> tuple[list, list, int]:
    """
    This function will fetch the mails from the IMAP server.

    Args:
        client: IMAP client
        time_to_fetch_from: Fetch all incidents since first_fetch_time
        include_raw_body: Whether to include the raw body of the mail in the incident's body
        with_headers: Whether to add headers to the search query
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

    if uid_to_fetch_from:
        uid_to_fetch_from = int(uid_to_fetch_from)

    if message_id:
        messages_uids = [message_id]
        demisto.debug("message_id provided, using it for message_uids")
    else:
        messages_query = generate_search_query(
            time_to_fetch_from, with_headers, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from
        )
        demisto.debug(f"message_id not provided, using generated query {messages_query}")
        messages_uids = client.search(messages_query)
        # convert the uids to int in case one of them is str
        messages_uids = [int(x) for x in messages_uids]

        demisto.debug(f"client returned {len(messages_uids)} message ids: {messages_uids=}")

        if len(messages_uids) > limit:  # If there's any reason to shorten the list
            if uid_to_fetch_from == 0:
                # first fetch takes last page only (workaround as first_fetch filter is date accurate)
                messages_uids = messages_uids[-limit:]
                demisto.debug(f"limiting to the LAST {limit=} messages since uid_to_fetch_from == 0")
            else:
                messages_uids = messages_uids[:limit]
                demisto.debug(f"limiting to the first {limit=} messages")
        demisto.debug(f"{messages_uids=}")

    fetched_email_objects = []
    demisto.debug(f"Messages to fetch: {messages_uids}")

    for mail_id, message_data in client.fetch(messages_uids, "RFC822").items():
        demisto.debug(f"Starting to parse the mail with {mail_id=}")
        message_bytes = message_data.get(b"RFC822")
        # For cases the message_bytes is returned as a string. If failed, will try to use the message_bytes returned.
        try:
            message_bytes = bytes(message_bytes)
        except Exception as e:
            demisto.debug(f"{mail_id=}: Converting to bytest failed. {message_data=}. Error: {e}")

        if not message_bytes:
            demisto.debug(f"{mail_id=}: Skipping because did not managed to convert to bytes")
            continue

        try:
            demisto.debug("Creating email object")
            email_message_object = Email(message_bytes, include_raw_body, save_file, mail_id)
            demisto.debug(f"{mail_id=}: Created email object.")
        except Exception as e:
            demisto.debug(f"{mail_id=}: Failed creating Email object, skipping. {message_data=}. Error: {e}")
            continue

        demisto.debug(f"{mail_id=}: Created email object successfully.")
        # Add mails if the current email UID is higher than the previous incident UID
        if int(email_message_object.id) > uid_to_fetch_from:
            fetched_email_objects.append(email_message_object)
            demisto.debug(f"{mail_id=}: Collecting {email_message_object.id=} since it's > {uid_to_fetch_from=}")
        else:
            demisto.debug(
                f"{mail_id=}: Skipping {email_message_object.id=} since it's <= {uid_to_fetch_from=}."
                f"{email_message_object.date=}"
            )
    if messages_uids:
        next_uid_to_fetch_from = max(messages_uids[-1], uid_to_fetch_from)
        demisto.debug(f"messages_uids NOT empty, setting {next_uid_to_fetch_from=}")
    else:
        next_uid_to_fetch_from = uid_to_fetch_from
        demisto.debug(f"messages_uids IS empty, setting {next_uid_to_fetch_from=}")

    ids_fetched = [mail.id for mail in fetched_email_objects]
    demisto.debug(f"fetched {len(fetched_email_objects)} emails, {ids_fetched=}")
    return fetched_email_objects, ids_fetched, next_uid_to_fetch_from


def generate_search_query(
    time_to_fetch_from: datetime | None,
    with_headers: bool,
    permitted_from_addresses: str,
    permitted_from_domains: str,
    uid_to_fetch_from: int,
) -> list:
    """
    Generates a search query for the IMAP client 'search' method. with the permitted domains, email addresses and the
    starting date from which mail should be fetched.
    Input example #1:
        time_to_fetch_from: datetime.datetime(2020, 8, 7, 12, 14, 32, 918634, tzinfo=datetime.timezone.utc)
        with_headers: True
        permitted_from_addresses: ['test1@mail.com']
        permitted_from_domains: ['test1.com']
    output example #1:
        ['OR',
         'HEADER',
         'FROM',
         'test1.com',
         'HEADER',
         'FROM',
         'test1@mail.com',
         'SINCE',
         datetime.datetime(2020, 8, 7, 12, 14, 32, 918634, tzinfo=datetime.timezone.utc)]
    Input example #2:
        time_to_fetch_from: datetime.datetime(2020, 8, 7, 12, 14, 32, 918634, tzinfo=datetime.timezone.utc)
        with_headers: False
        permitted_from_addresses: ['test1@mail.com']
        permitted_from_domains: ['test1.com']
    output example #2:
        ['OR',
         'FROM',
         'test1.com',
         'FROM',
         'test1@mail.com',
         'SINCE',
         datetime.datetime(2020, 8, 7, 12, 14, 32, 918634, tzinfo=datetime.timezone.utc)]
    Args:
        time_to_fetch_from: The greatest incident created_time we fetched from last fetch
        with_headers: Whether to add headers to the search query
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from
        uid_to_fetch_from: The email message UID to start the fetch from as offset

    Returns:
        A list with arguments for the email search query
    """
    logger(generate_search_query)
    permitted_from_addresses_list = argToList(permitted_from_addresses)
    permitted_from_domains_list = argToList(permitted_from_domains)
    messages_query = ""
    if permitted_from_addresses_list + permitted_from_domains_list:
        messages_query = OR(from_=permitted_from_addresses_list + permitted_from_domains_list).format()
        # Removing Parenthesis and quotes
        messages_query = messages_query.strip("()").replace('"', "")
        if with_headers:
            messages_query = messages_query.replace("FROM", "HEADER FROM")
    # Creating a list of the OR query words
    messages_query_list = messages_query.split()
    if time_to_fetch_from:
        messages_query_list += ["SINCE", time_to_fetch_from]  # type: ignore[list-item]
    if uid_to_fetch_from:
        messages_query_list += ["UID", f"{uid_to_fetch_from}:*"]
    return messages_query_list


def script_test_module(client: IMAPClient) -> str:
    yesterday = parse("1 day UTC")
    client.search(["SINCE", yesterday])
    return "ok"


def list_emails(
    client: IMAPClient,
    first_fetch_time: str,
    with_headers: bool,
    permitted_from_addresses: str,
    permitted_from_domains: str,
    _limit: int,
) -> CommandResults:
    """
    Lists all emails that can be fetched with the given configuration and return a preview version of them.
    Args:
        client: IMAP client
        first_fetch_time: Fetch all incidents since first_fetch_time
        with_headers: Whether to add headers to the search query
        permitted_from_addresses: A string representation of list of mail addresses to fetch from
        permitted_from_domains: A string representation list of domains to fetch from
        _limit: Upper limit as set in the integration params.

    Returns:
        The Subject, Date, To, From and ID of the fetched mails wrapped in command results object.
    """
    fetch_time = parse(f"{first_fetch_time} UTC")

    mails_fetched, _, _ = fetch_mails(
        client=client,
        time_to_fetch_from=fetch_time,
        with_headers=with_headers,
        permitted_from_addresses=permitted_from_addresses,
        permitted_from_domains=permitted_from_domains,
        limit=_limit,
    )
    results = [
        {
            "Subject": email.subject,
            "Date": email.date.isoformat() if email.date else datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "To": email.to,
            "From": email.from_,
            "ID": email.id,
        }
        for email in mails_fetched
    ]

    return CommandResults(outputs_prefix="MailListener.EmailPreview", outputs_key_field="ID", outputs=results)


def get_email(client: IMAPClient, message_id: int) -> CommandResults:
    mails_fetched, _, _ = fetch_mails(client, message_id=message_id)
    mails_json = [mail.generate_raw_json(parse_attachments=True, output_to_warroom=True) for mail in mails_fetched]
    return CommandResults(outputs_prefix="MailListener.Email", outputs_key_field="ID", outputs=mails_json)


def get_email_as_eml(client: IMAPClient, message_id: int) -> dict:
    mails_fetched, _, _ = fetch_mails(client, message_id=message_id)
    mail_file = [fileResult("original-email-file.eml", mail.mail_bytes) for mail in mails_fetched]
    return mail_file[0] if mail_file else {}


def replace_spaces_in_credentials(credentials: str | None) -> str | None:
    """
    This function is used in case of credential from type: 9 is in the wrong format
    of one line with spaces instead of multiple lines.

    :param credentials: the credentials to replace spaces in.
    :return: the credential with spaces replaced with new lines if the credential is in the correct format,
             otherwise the credential will be returned as is.
    """
    if not credentials:
        return credentials

    return re.sub(
        r"(?P<lseps>\s*)(?P<begin>-----BEGIN(.*?)-----)(?P<body>.*?)(?P<end>-----END(.*?)-----)(?P<tseps>\s*)",
        lambda m: m.group("lseps").replace(" ", "\n")
        + m.group("begin")
        + m.group("body").replace(" ", "\n")
        + m.group("end")
        + m.group("tseps").replace(" ", "\n"),
        credentials,
        flags=re.DOTALL,
    )


def load_client_cert_and_key(ssl_context: ssl.SSLContext, params: dict[str, Any]) -> bool:
    """Load client certificates and private keys to the SSL context.

    :param ssl_context: The SSL context to which client certs/keys will be loaded.
    :param params: The integration parameters.
    :return: True if certificates and private keys are loaded, otherwise False.
    """
    cred_params = params.get("clientCertAndKey") or {}
    if cert_and_pkey_pem := cred_params.get("password"):
        cert_and_pkey_pem = replace_spaces_in_credentials(cert_and_pkey_pem)
    else:
        cert_and_pkey_pem = demisto.get(cred_params, "credentials.sshkey")
        if not cert_and_pkey_pem:
            # No client certificates and private keys
            return False

    # Load client certificates and private keys
    with NamedTemporaryFile(mode="w") as pem_file:
        pem_file.write(cert_and_pkey_pem)
        pem_file.flush()
        pem_file.seek(0)
        ssl_context.load_cert_chain(certfile=pem_file.name, keyfile=None)
        return True


def main():  # pragma: no cover
    params = demisto.params()
    mail_server_url = params.get("MailServerURL")
    port = arg_to_number(params.get("port"))
    folder = params.get("folder")
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    verify_ssl = not params.get("insecure", False)
    tls_connection = params.get("TLS_connection", True)
    include_raw_body = params.get("Include_raw_body", False)
    permitted_from_addresses = params.get("permittedFromAdd", "")
    permitted_from_domains = params.get("permittedFromDomain", "")
    with_headers = params.get("with_headers")
    delete_processed = params.get("delete_processed") or False
    limit = arg_to_number(params.get("limit")) or 50
    demisto.debug(f"{limit=}")
    save_file = params.get("save_file") or False
    first_fetch_time = (params.get("first_fetch") or "3 days").strip()
    ssl_context = ssl.create_default_context()

    args = demisto.args()
    if not verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        load_client_cert_and_key(ssl_context, params)

        with IMAPClient(mail_server_url, ssl=tls_connection, port=port, ssl_context=ssl_context) as client:
            client.login(username, password)
            client.select_folder(folder)
            if demisto.command() == "test-module":
                result = script_test_module(client)
                return_results(result)
            elif demisto.command() == "mail-listener-list-emails":
                return_results(
                    list_emails(
                        client=client,
                        first_fetch_time=first_fetch_time,
                        with_headers=with_headers,
                        permitted_from_addresses=permitted_from_addresses,
                        permitted_from_domains=permitted_from_domains,
                        _limit=limit,
                    )
                )
            elif demisto.command() == "mail-listener-get-email":
                return_results(get_email(client=client, message_id=arg_to_number(args.get("message-id")) or 0))
            elif demisto.command() == "mail-listener-get-email-as-eml":
                return_results(get_email_as_eml(client=client, message_id=arg_to_number(args.get("message-id")) or 0))
            elif demisto.command() == "fetch-incidents":
                next_run, incidents = fetch_incidents(
                    client=client,
                    last_run=demisto.getLastRun(),
                    first_fetch_time=first_fetch_time,
                    include_raw_body=include_raw_body,
                    with_headers=with_headers,
                    permitted_from_addresses=permitted_from_addresses,
                    permitted_from_domains=permitted_from_domains,
                    delete_processed=delete_processed,
                    limit=limit,
                    save_file=save_file,
                )
                demisto.debug(f"{next_run=}")
                # if next_run is None, we will not update last_run
                if next_run:
                    demisto.setLastRun(next_run)
                demisto.incidents(incidents)
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
