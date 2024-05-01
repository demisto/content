import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import base64
from dateparser import parse
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from typing import List, Dict, Tuple, Callable

ZOOM_MAIL_COMMAND_PREFIX = "zoom-mail"


class ZoomMailClient(BaseClient):
    def __init__(
        self, base_url, client_id, client_secret, account_id, verify=True, proxy=False
    ):
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
        client_credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {client_credentials}",
        }

        body = {"grant_type": "account_credentials", "account_id": self.account_id}

        response = super()._http_request(
            method="POST",
            full_url="https://zoom.us/oauth/token",
            headers=headers,
            data=body,
        )

        access_token = response.get("access_token")
        if access_token:
            self.access_token = access_token
            self.token_time = time.time()
            return {"success": True, "token": access_token}
        else:
            return {
                "success": False,
                "error": "Failed to retrieve access token from ZoomMail API",
            }

    def _http_request(self, *args, **kwargs):
        """
        Override the _http_request method to include the access token in the headers.
        """
        if not self.access_token or (time.time() - self.token_time) >= 3500:
            self.obtain_access_token()
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"
        kwargs["headers"] = headers
        return super()._http_request(*args, **kwargs)

    def get_email_thread(
        self,
        email: str,
        thread_id: str,
        format: str = "full",
        metadata_headers: str = "",
        maxResults: str = "50",
        pageToken: str = "",
    ):
        """
        Retrieves the specified email thread from a mailbox using the provided parameters.

        Args:
            email (str): The mailbox address, or "me" for the primary mailbox of the authenticated user.
            thread_id (str): The unique identifier of the email thread to retrieve.
            format (str): Specifies the format to return the messages in. Options are 'full', 'metadata', 'minimal'.
            metadata_headers (str): A comma-separated string of header names to include in the response when format is 'metadata'.
            maxResults (str): The maximum number of thread messages to return. Default is "50".
            pageToken (str): A token to specify the page of results to retrieve.

        Returns:
            dict: A dictionary containing the requested email thread. The structure of the dictionary will depend on the specified format.
        """
        url_suffix = f"/emails/mailboxes/{email}/threads/{thread_id}"

        params = {
            "format": format,
            "metadata_headers": metadata_headers,
            "maxResults": maxResults,
            "pageToken": pageToken,
        }

        response = self._http_request(
            method="GET", url_suffix=url_suffix, params=params
        )

        return response

    def trash_email(self, email: str, message_id: str):
        """
        Moves the specified email message to the TRASH folder of the user's mailbox.

        Args:
            email (str): The email address of the mailbox from which the message will be trashed.
                        Use "me" to refer to the primary mailbox of the authenticated user.
            message_id (str): The unique identifier of the email message to be trashed.

        Returns:
            dict: A dictionary representing the server's response to the trash request. The contents will vary based on the API's response structure.

        """
        url_suffix = f"/emails/mailboxes/{email}/messages/{message_id}/trash"

        response = self._http_request(method="POST", url_suffix=url_suffix)

        return response

    def list_emails(
        self,
        email: str,
        max_results: str = "50",
        page_token: str = "",
        label_ids: str = "",
        query: str = "",
        include_spam_trash: bool = False,
    ):
        """
        Retrieves a list of email messages from a specified mailbox, with optional filtering and pagination.

        Args:
            email (str): The email address of the mailbox to query, or "me" to indicate the primary mailbox of the authenticated user.
            max_results (str): The maximum number of messages to return. Defaults to "50".
            page_token (str): A token specifying a page of results to retrieve in a paginated query.
            label_ids (str): Comma-separated list of label IDs to filter the messages by. Currently not used.
            query (str): Query string to filter messages based on conditions, such as subject, body content, etc.
            include_spam_trash (bool): If True, includes messages from SPAM and TRASH in the results.

        Returns:
            dict: A dictionary containing the list of email messages and any associated metadata, formatted according to the API's response structure.
        """
        url_suffix = f"/emails/mailboxes/{email}/messages"

        params = {
            "maxResults": max_results,
            "pageToken": page_token,
            "q": query,
            "includeSpamTrash": str(include_spam_trash).lower(),
        }

        response = self._http_request(
            method="GET", url_suffix=url_suffix, params=params
        )

        return response

    def get_email_attachment(self, email: str, message_id: str, attachment_id: str):
        """
        Retrieves a specific attachment from an email message in a user's mailbox.

        Args:
            email (str): The email address of the mailbox, or "me" to indicate the primary mailbox of the authenticated user.
            message_id (str): The unique identifier of the email message from which the attachment is to be retrieved.
            attachment_id (str): The unique identifier of the attachment to retrieve.

        Returns:
            dict: A dictionary containing the attachment data if available, including any relevant metadata as provided by the API response.
        """
        url_suffix = f"/emails/mailboxes/{email}/messages/{message_id}/attachments/{attachment_id}"

        response = self._http_request(method="GET", url_suffix=url_suffix)

        return response

    def get_email_message(
        self,
        email: str,
        message_id: str,
        msg_format: str = "full",
        metadata_headers: str = "",
    ):
        """
        Retrieves a specific email message from the specified mailbox in the requested format.

        Args:
            email (str): The email address of the mailbox, or "me" to refer to the primary mailbox of the authenticated user.
            message_id (str): The unique identifier of the email message to be retrieved.
            msg_format (str): Specifies the format in which to return the message. Options are 'full', 'minimal', 'metadata', or 'raw'.
            metadata_headers (str): A comma-separated list of headers to include in the response when the format is set to 'metadata'.

        Returns:
            dict: A dictionary containing the email message details formatted according to the specified msg_format,
            including any metadata headers if requested.

        """
        url_suffix = f"/emails/mailboxes/{email}/messages/{message_id}"

        params = {"format": msg_format, "metadata_headers": metadata_headers}

        response = self._http_request(
            method="GET", url_suffix=url_suffix, params=params
        )

        return response

    def send_email(self, email: str, raw_message: str):
        """
        Sends a preformatted email message from a specified email address. The email content is expected to be preformatted and encoded.

        Args:
            email (str): The email address to send the email from, or "me" to indicate the primary mailbox of the authenticated user.
            raw_message (str): The entire email message formatted according to RFC 2822 standards and encoded in base64url format.

        Returns:
            dict: A dictionary containing the API's response to the email sending operation. Typically includes status codes or message identifiers.
        """
        url_suffix = f"/emails/mailboxes/{email}/messages/send"
        body = {"raw": raw_message}
        response = self._http_request(
            method="POST", url_suffix=url_suffix, json_data=body
        )
        return response

    def get_mailbox_profile(self, email: str):
        """
        Retrieves the profile information of a specified mailbox.

        Args:
            email (str): The email address of the mailbox to retrieve the profile for, or "me" to indicate the primary mailbox of the authenticated user.

        Returns:
            dict: A dictionary containing the profile details of the specified mailbox as provided by the API response.
        """
        url_suffix = f"/emails/mailboxes/{email}/profile"

        response = self._http_request(method="GET", url_suffix=url_suffix)

        return response

    def list_users(
        self,
        status="active",
        page_size=30,
        role_id="",
        page_number="1",
        include_fields="",
        next_page_token="",
        license="",
    ):
        params = {
            "status": status,
            "page_size": page_size,
            "role_id": role_id,
            "page_number": page_number,
            "include_fields": include_fields,
            "next_page_token": next_page_token,
            "license": license,
        }
        return self._http_request(method="GET", url_suffix="/users", params=params)


def the_testing_module(client: ZoomMailClient) -> str:
    """
    Tests authentication for the ZoomMail API by attempting to obtain an access token.
    """
    token_response = client.obtain_access_token()

    if token_response.get("success"):
        return "ok"
    error_message = token_response.get("error", "Unknown error occurred.")
    return f"Authorization Error: {error_message}"


def fetch_incidents(client: ZoomMailClient, params: dict) -> None:
    """
    Fetches email messages from ZoomMail API and creates incidents.

    :param client: The ZoomMailClient instance.
    """
    fetch_from = params.get("fetch_from")
    fetch_query = params.get("fetch_query", "")
    first_fetch_time = params.get("first_fetch", "3 days")

    max_fetch = min(int(params.get("max_fetch", 50)), 200)

    last_run = demisto.getLastRun()
    last_fetch = last_run.get("last_fetch")
    processed_ids: Set[str] = set(last_run.get("processed_ids", []))

    if not last_fetch:
        first_fetch_dt = parse(first_fetch_time)
        if not first_fetch_dt:
            first_fetch_dt = datetime.now() - timedelta(days=3)
        last_fetch = first_fetch_dt.timestamp()

    new_last_fetch = last_fetch
    new_processed_ids = processed_ids.copy()

    incidents: List[Dict[str, Any]] = []

    query = fetch_query + f" after:{int(last_fetch)}"
    messages_response = client.list_emails(
        email=fetch_from, max_results=str(max_fetch), query=query
    )
    messages = messages_response.get("messages", [])
    message_dates: List[float] = []

    for msg in messages:
        message_id = msg.get("id")
        thread_id = msg.get("threadId", "")
        message_details = client.get_email_message(
            email=fetch_from, message_id=message_id
        )
        internal_date = float(message_details.get("internalDate")) / 1000.0

        if (
            internal_date > last_fetch
            and message_id not in processed_ids
            and message_id == thread_id
        ):
            incident = zoom_mail_to_incident(message_details, client, fetch_from)
            incidents.append(incident)
            new_processed_ids.add(message_id)
            message_dates.append(internal_date)

    if message_dates:
        new_last_fetch = min(message_dates)

    demisto.setLastRun(
        {"last_fetch": new_last_fetch, "processed_ids": list(new_processed_ids)}
    )

    demisto.incidents(incidents)


""" COMMAND FUNCTIONS """


def get_email_thread_command(
    client: ZoomMailClient, args: Dict[str, str]
) -> CommandResults:
    """
    Retrieves an email thread from the ZoomMail service and formats it for output.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, str]): Command arguments including:
            - email: The email address to retrieve the thread from.
            - thread_id: The identifier of the thread to retrieve.
            - format: The format in which to return the messages ('full', 'metadata', 'minimal').
            - metadata_headers: A comma-separated list of headers to include when format is 'metadata'.
            - max_results: Maximum number of messages to return in the thread.
            - page_token: Token for pagination.

    Returns:
        CommandResults: A CommandResults object containing the readable output and the raw response.

    Raises:
        ValueError: If required arguments are missing.
    """
    # Validate required arguments
    email = args.get("email")
    thread_id = args.get("thread_id")
    if not email or not thread_id:
        raise ValueError("Both 'email' and 'thread_id' arguments are required.")

    # Optional arguments with defaults
    msg_format = args.get("format", "full")
    metadata_headers = args.get("metadata_headers", "")
    max_results = args.get("max_results", "50")
    page_token = args.get("page_token", "")

    # API call to get the email thread
    response = client.get_email_thread(
        email, thread_id, msg_format, metadata_headers, max_results, page_token
    )

    # Prepare readable output
    if "messages" in response:
        messages_list = [f'- Message ID: {msg["id"]}' for msg in response["messages"]]
        readable_output = f"Email Thread {thread_id} in mailbox {email}:\n" + "\n".join(
            messages_list
        )
    else:
        readable_output = (
            f"Email Thread {thread_id} in mailbox {email} has no messages."
        )

    # Return command results
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ZoomMail.EmailThread",
        outputs_key_field="id",
        outputs=response,
    )


def trash_email_command(client: ZoomMailClient, args: Dict[str, str]) -> CommandResults:
    """
    Moves a specified email to the TRASH folder using the ZoomMail API.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, str]): Command arguments, expected to contain:
            - email: The email address from which the message is being trashed.
            - message_id: The identifier of the message to trash.

    Returns:
        CommandResults: A CommandResults object that contains the readable output,
                        the API response, and other metadata for use in other parts of the system.

    Raises:
        ValueError: If 'email' or 'message_id' arguments are not provided.
    """
    # Extract required parameters
    email = args.get("email")
    message_id = args.get("message_id")
    if not email or not message_id:
        raise ValueError("Both 'email' and 'message_id' arguments are required.")

    # Call the client function to trash the email
    response = client.trash_email(email, message_id)

    # Generate the human-readable output
    readable_output = f"Message with ID {message_id} was moved to TRASH."

    # Return the results with structured data
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ZoomMail.TrashedEmail",
        outputs_key_field="id",
        outputs=response,
    )


def list_emails_command(client: ZoomMailClient, args: Dict[str, str]) -> CommandResults:
    """
    Lists emails from a specified mailbox using the ZoomMail API based on given criteria.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, str]): Command arguments, expected to contain:
            - email: The email address of the mailbox.
            - max_results: Maximum number of messages to retrieve (default is '50').
            - page_token: Token for pagination to continue listing emails from a previous request.
            - label_ids: IDs of labels to filter the messages.
            - query: Search query to filter messages.
            - include_spam_trash: Flag to include emails from SPAM and TRASH in the results.

    Returns:
        CommandResults: A CommandResults object that contains the readable output,
                        the API response, and other metadata for use in other parts of the system.

    """
    email = args.get("email")
    if not email:
        raise ValueError("The 'email' argument is required.")

    max_results = args.get("max_results", "50")
    page_token = args.get("page_token", "")
    label_ids = args.get("label_ids", "")
    query = args.get("query", "")
    include_spam_trash = args.get("include_spam_trash", "false").lower() in [
        "true",
        "1",
        "t",
        "y",
        "yes",
    ]

    response = client.list_emails(
        email, max_results, page_token, label_ids, query, include_spam_trash
    )

    if "messages" in response:
        messages_list = [
            f'- ID: {msg["id"]} Thread ID: {msg.get("threadId", "N/A")}'
            for msg in response["messages"]
        ]
        readable_output = f"Messages in mailbox {email}:\n" + "\n".join(messages_list)
    else:
        readable_output = f"No messages found in mailbox {email}."

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ZoomMail.Emails",
        outputs_key_field="id",
        outputs=response,
    )


def get_email_message_command(
    client: ZoomMailClient, args: Dict[str, str]
) -> CommandResults:
    """
    Retrieves a specific email message and formats a detailed human-readable output.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, str]): Command arguments, expected to contain:
            - email: The email address of the mailbox.
            - message_id: The identifier of the specific message to retrieve.
            - format: The format in which to return the message ('full', 'metadata', 'minimal').
            - metadata_headers: Specific headers to include when format is 'metadata'.

    Returns:
        CommandResults: A CommandResults object that contains the human-readable output,
                        the API response, and other metadata for use in other parts of the system.

    Raises:
        ValueError: If 'email' or 'message_id' are not provided in the command arguments.
    """
    email = args.get("email")
    message_id = args.get("message_id")
    if not email or not message_id:
        raise ValueError("Both 'email' and 'message_id' arguments are required.")

    format = args.get("format", "full")
    metadata_headers = args.get("metadata_headers", "")

    message = client.get_email_message(email, message_id, format, metadata_headers)

    if "payload" in message:
        body, html, attachments = parse_mail_parts([message.get("payload")])
        human_readable = (
            f"### Email Message {message_id}\n"
            f"* **From**: {message.get('from')}\n"
            f"* **To**: {message.get('to')}\n"
            f"* **Subject**: {message.get('subject')}\n"
            f"* **Date**: {message.get('date')}\n\n"
            f"**Body:**\n{body}\n\n"
            f"**HTML:**\n{html}\n\n"
            f"**Attachments:**\n{', '.join([att['Name'] for att in attachments])}"
        )
    else:
        human_readable = f"No content found for Email Message {message_id}."

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="ZoomMail.EmailMessage",
        outputs_key_field="id",
        outputs=message,
    )


def get_email_attachment_command(
    client: ZoomMailClient, args: Dict[str, Any]
) -> CommandResults:
    """
    Retrieves a specific email attachment and returns it to the user, providing detailed feedback.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, Any]): Command arguments that include:
            - email (str): The email address of the mailbox from which to retrieve the attachment.
            - message_id (str): The unique identifier of the email message.
            - attachment_id (str): The unique identifier of the attachment to retrieve.

    Returns:
        CommandResults: Contains the command's readable output, the raw response data,
                        and the output data structured for automation.

    Raises:
        ValueError: If any required arguments ('email', 'message_id', 'attachment_id') are missing.
    """
    email = args.get("email")
    message_id = args.get("message_id")
    attachment_id = args.get("attachment_id")

    # Validate that necessary arguments are provided
    if not email or not message_id or not attachment_id:
        raise ValueError(
            "The 'email', 'message_id', and 'attachment_id' arguments are required."
        )

    # API call to get the attachment
    attachment = client.get_email_attachment(email, message_id, attachment_id)

    if "data" in attachment and attachment["data"]:
        # Decode the attachment data and prepare it for presentation
        attachment_data = base64.urlsafe_b64decode(attachment["data"].encode("ascii"))
        file_result = fileResult(f"{attachment_id}", attachment_data)
        return_results(file_result)  # Present the file to the user in the War Room

        # Provide detailed feedback on retrieval success
        return CommandResults(
            readable_output=f"Attachment with ID {attachment_id} retrieved successfully.",
            raw_response=attachment,
            outputs_prefix="ZoomMail.EmailAttachment",
            outputs_key_field="attachmentId",
            outputs=attachment,
        )
    else:
        # Return a failure message if no data found
        return CommandResults(
            readable_output=f"No data found for attachment ID {attachment_id}."
        )


def get_mailbox_profile_command(
    client: ZoomMailClient, args: Dict[str, Any]
) -> CommandResults:
    """
    Retrieves and displays the mailbox profile for a specified email address.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, Any]): Command arguments containing:
            - email (str): The email address of the mailbox whose profile is to be retrieved.

    Returns:
        CommandResults: Contains the command's readable output and the raw response data structured for automation.

    Raises:
        ValueError: If the 'email' argument is missing.
    """
    email = args.get("email")

    # Validate that the email parameter is provided
    if not email:
        raise ValueError("The 'email' argument is required.")

    # Retrieve the mailbox profile using the API client
    profile = client.get_mailbox_profile(email)

    # Prepare the human-readable output
    readable_output = (
        f"### Mailbox Profile for {email}\n"
        f"* **Email Address**: {profile.get('emailAddress')}\n"
        f"* **Group Emails**: {', '.join(profile.get('groupEmails', []))}\n"
        f"* **Creation Time**: {datetime.utcfromtimestamp(profile.get('createTime')).strftime('%Y-%m-%dT%H:%M:%SZ') if profile.get('createTime') else 'N/A'}\n"
        f"* **Status**: {profile.get('status')}\n"
        f"* **Mailbox Size**: {profile.get('mboxSize')} bytes\n"
        f"* **Total Messages**: {profile.get('messagesTotal')}\n"
        f"* **Total Threads**: {profile.get('threadsTotal')}\n"
        f"* **Encryption Enabled**: {'Yes' if profile.get('encryptionEnabled') else 'No'}\n"
        f"* **Label Encryption Enabled**: {'Yes' if profile.get('labelEncryptionEnabled') else 'No'}\n"
        f"* **Last History ID**: {profile.get('historyId')}"
    )

    # Return command results including readable output and structured data
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ZoomMail.MailboxProfile",
        outputs_key_field="emailAddress",
        outputs=profile,
    )


def list_users_command(client: ZoomMailClient, args: Dict[str, str]) -> CommandResults:
    """
    Lists users from the ZoomMail service based on the provided criteria.

    Args:
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        args (Dict[str, str]): Command arguments specifying filters and pagination controls.

    Returns:
        CommandResults: An object containing the human-readable output, the raw API response, and
                        the list of users to be outputted in the context data of the workflow.

    """
    # Extract and process arguments with defaults
    status = args.get("status", "active")
    page_size = args.get("page_size", 30)
    role_id = args.get("role_id", "")
    page_number = args.get("page_number", "1")
    include_fields = args.get("include_fields", "")
    next_page_token = args.get("next_page_token", "")
    license = args.get("license", "")

    # API call to list users
    response = client.list_users(
        status,
        int(page_size),
        role_id,
        page_number,
        include_fields,
        next_page_token,
        license,
    )
    users = response.get("users", [])

    # Generating human-readable output
    readable_output = "### Zoom Mail Users\n{0}".format(
        tableToMarkdown(
            "Users",
            users,
            headers=["email", "first_name", "last_name", "type", "status"],
        )
    )

    # Return command results with structured data
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ZoomMail.Users",
        outputs_key_field="id",
        outputs=users,
    )


def send_email_command(client: ZoomMailClient, args: Dict[str, Any]) -> CommandResults:
    """
    Constructs and sends an email based on provided arguments.

    Args:
        client (ZoomMailClient): The client used to interact with the email API.
        args (Dict[str, Any]): Dictionary containing the arguments necessary for email construction.

    Returns:
        CommandResults: Results object containing a message indicating the success or failure of the send operation.
    """
    email = args.get("from")
    subject = args.get("subject")
    body = args.get("body")
    html_body = args.get("html_body", "")
    entry_ids = argToList(args.get("attachments", []))
    recipients = args.get("to")

    message = create_email_message(
        email, recipients, subject, body, html_body, entry_ids
    )

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    response = client.send_email(email, raw_message)
    return generate_send_email_results(response)


""" HELPER FUNCTIONS """


def create_email_message(
    from_email: str,
    to: str,
    subject: str,
    body: str,
    html_body: str,
    attachment_ids: List[str],
) -> MIMEMultipart:
    """
    Creates an email message object ready for sending.

    Args:
        from_email (str): Sender's email address.
        to (str): Recipient's email address.
        subject (str): Subject of the email.
        body (str): Plain text body of the email.
        html_body (str): HTML body of the email.
        attachment_ids (List[str]): List of attachment file IDs to include.

    Returns:
        MIMEMultipart: The constructed email message object.
    """
    message = MIMEMultipart("mixed" if html_body or attachment_ids else "alternative")
    message["From"] = from_email
    message["To"] = to
    message["Subject"] = subject

    if body:
        message.attach(MIMEText(body, "plain"))
    if html_body:
        message.attach(MIMEText(html_body, "html"))
    attach_files_to_email(message, attachment_ids)

    return message


def attach_files_to_email(message: MIMEMultipart, attachment_ids: List[str]):
    """
    Attaches files to an email message.

    Args:
        message (MIMEMultipart): The email message object to attach files to.
        attachment_ids (List[str]): List of attachment file IDs.
    """
    for entry_id in attachment_ids:
        res = demisto.getFilePath(entry_id)
        if res and "path" in res:
            attach_file(message, res["path"], res["name"])


def attach_file(message: MIMEMultipart, file_path: str, file_name: str):
    """
    Attaches a single file to the email message.

    Args:
        message (MIMEMultipart): The email message object to attach the file to.
        file_path (str): Path to the file.
        file_name (str): Name of the file to use in the attachment.
    """
    part = MIMEBase("application", "octet-stream")
    with open(file_path, "rb") as file:
        part.set_payload(file.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=file_name)
    message.attach(part)


def generate_send_email_results(response: Dict[str, Any]) -> CommandResults:
    """
    Generates a CommandResults object based on the response from the email send operation.

    Args:
        response (Dict[str, Any]): The response from the email sending function.

    Returns:
        CommandResults: Results object containing a message indicating the success or failure of the send operation.
    """
    if response.get("id"):
        return CommandResults(
            readable_output=f"Email sent successfully with ID: {response['id']}"
        )
    return CommandResults(readable_output="Failed to send email.")


def create_incident_labels(message_details: Dict[str, any]) -> List[Dict[str, str]]:
    """
    Creates a list of labels for an incident based on the email message details.

    This function dynamically constructs labels from both fixed fields and headers
    within the message, allowing for easy extension and modification.

    Args:
        message_details (Dict[str, any]): A dictionary containing details of the email message.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, each representing a label for the incident.
    """
    # Base labels from message details
    labels = [
        {"type": "Email/ID", "value": message_details.get("id", "")},
        {"type": "Email/subject", "value": message_details.get("subject", "")},
        {"type": "Email/text", "value": message_details.get("snippet", "")},
    ]

    # Extract headers and dynamically add header specific labels
    headers = message_details.get("payload", {}).get("headers", [])
    headers_dict = {header["name"]: header["value"] for header in headers}

    # General email fields from headers that might have multiple values
    multi_fields = ["To", "Cc", "Bcc"]
    for field in multi_fields:
        if headers_dict.get(field):
            labels.extend(
                [
                    {"type": f"Email/{field.lower()}", "value": addr.strip()}
                    for addr in headers_dict[field].split(",")
                    if addr.strip()
                ]
            )

    # Add from and potentially other single headers directly
    single_fields = ["From", "Html"]
    for field in single_fields:
        if headers_dict.get(field):
            labels.append(
                {"type": f"Email/{field.lower()}", "value": headers_dict[field]}
            )

    # Dynamic headers, attempting to future-proof the integration
    dynamic_headers = [
        key for key in headers_dict if key not in multi_fields + single_fields
    ]
    for key in dynamic_headers:
        labels.append({"type": f"Email/Header/{key}", "value": headers_dict[key]})

    return labels


def zoom_mail_to_incident(
    msg: Dict[str, Any], client: ZoomMailClient, email: str
) -> Dict[str, Any]:
    """
    Converts an email message into an incident format suitable for processing in an incident response system.

    This function parses the email message, extracts necessary information such as the subject,
    body, and attachments, and formats them into a structured incident dictionary.

    Args:
        msg (Dict[str, Any]): A dictionary representing the email message, including metadata and content.
        client (ZoomMailClient): The client used to interact with the ZoomMail API.
        email (str): The email address associated with the mailbox from which the message was retrieved.

    Returns:
        Dict[str, Any]: A dictionary representing the incident created from the email message.
    """
    # Extract body content and attachments from the email parts
    body_content, html_content, attachments = parse_mail_parts(msg["payload"]["parts"])
    occurred_str = (
        datetime.utcfromtimestamp(int(msg["internalDate"]) / 1000).isoformat() + "Z"
    )
    subject = next(
        (
            header["value"]
            for header in msg["payload"].get("headers", [])
            if header["name"].lower() == "subject"
        ),
        "No Subject",
    )

    # Process attachments and handle errors locally
    file_names = process_attachments(msg, client, email)

    # Construct and return the incident dictionary
    incident = {
        "type": "ZoomMail",
        "name": subject,
        "details": body_content,
        "labels": create_incident_labels(msg),
        "occurred": occurred_str,
        "attachments": file_names,
        "rawJSON": json.dumps(msg),
    }
    return incident


def process_attachments(
    msg: Dict[str, Any], client: ZoomMailClient, email: str
) -> List[Dict[str, str]]:
    """
    Process the attachments of an email, downloading and storing them if applicable.

    Args:
        msg (Dict[str, Any]): The email message containing potential attachments.
        client (ZoomMailClient): The API client to interact with the mail service.
        email (str): The email address from which the attachment will be retrieved.

    Returns:
        List[Dict[str, str]]: A list of dictionaries with attachment information.
    """
    file_names = []
    if "attachments" in msg:
        for attachment in msg["attachments"]:
            try:
                attachment_data = client.get_email_attachment(
                    email, msg["id"], attachment["ID"]
                )
                if attachment_data.get("data"):
                    file_data = base64.urlsafe_b64decode(
                        attachment_data["data"].encode("ascii")
                    )
                    file_result = fileResult(attachment["Name"], file_data)
                    if file_result["Type"] == entryTypes["error"]:
                        demisto.error(file_result["Contents"])
                        continue
                    file_names.append(
                        {"path": file_result["FileID"], "name": attachment["Name"]}
                    )
            except Exception as e:
                demisto.error(
                    f"Failed to retrieve attachment {attachment['ID']} from message {msg['id']}: {str(e)}"
                )
    return file_names


def parse_mail_parts(
    parts: List[Dict[str, Any]]
) -> Tuple[str, str, List[Dict[str, str]]]:
    """
    Parses the parts of an email message to extract body, HTML content, and attachments.

    Args:
        parts (List[Dict[str, Any]]): The parts of the email payload.

    Returns:
        Tuple[str, str, List[Dict[str, str]]]: A tuple containing the plain text body,
                                               HTML content, and a list of attachments.
    """
    body = ""
    html = ""
    attachments = []
    for part in parts:
        if "filename" in part:
            attachments.append(
                {
                    "ID": part.get("body", {}).get("attachmentId", ""),
                    "Name": part.get("filename"),
                    "Size": part.get("body", {}).get("size", 0),
                }
            )
        elif "text/html" in part.get("mimeType", ""):
            html += part.get("body", {}).get("data", "")
        else:
            body += part.get("body", {}).get("data", "")
    return body, html, attachments


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    client_id = params.get("credentials", {}).get("identifier") or params.get(
        "client_id"
    )
    client_secret = params.get("credentials", {}).get("password") or params.get(
        "client_secret"
    )
    account_id = params.get("account_id")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    client = ZoomMailClient(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        account_id=account_id,
        verify=verify_certificate,
        proxy=proxy,
    )

    COMMAND_FUNCTIONS: Dict[str, Callable] = {
        "fetch-incidents": lambda: fetch_incidents(client, params),
        "test-module": lambda: the_testing_module(client),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-trash-email": lambda: trash_email_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-list-emails": lambda: list_emails_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-get-email-thread": lambda: get_email_thread_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-get-email-attachment": lambda: get_email_attachment_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-get-email-message": lambda: get_email_message_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-send-email": lambda: send_email_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-get-mailbox-profile": lambda: get_mailbox_profile_command(
            client, args
        ),
        f"{ZOOM_MAIL_COMMAND_PREFIX}-list-users": lambda: list_users_command(
            client, args
        ),
    }

    command = demisto.command()
    if command in COMMAND_FUNCTIONS:
        return_results(COMMAND_FUNCTIONS[command]())
    else:
        raise NotImplementedError(f"Command '{command}' is not implemented.")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
