import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """

from MicrosoftApiModule import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBAL VARS """


""" CLIENT """


class MsGraphClient:
    def __init__(
        self,
        tenant_id,
        auth_id,
        enc_key,
        app_name,
        base_url,
        verify,
        proxy,
        self_deployed,
        redirect_uri,
        auth_code,
        handle_error,
        certificate_thumbprint: str | None = None,
        private_key: str | None = None,
        delegated_user: str | None = None,
    ):
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        resource = None if self_deployed else ""
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id,
            auth_id=auth_id,
            enc_key=enc_key,
            app_name=app_name,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            self_deployed=self_deployed,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            grant_type=grant_type,
            resource=resource,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            command_prefix="msgraph-teams",
        )
        self.handle_error = handle_error

        self.delegated_user = delegated_user

    @staticmethod
    def _build_members_input(user_id, members):
        """
        Builds valid members input for the chat.

        :type members: ``list``
        :param members: List of principle names (email)

        :return: List of valid member objects
        :rtype: ``list``
        """
        member_list = []
        member_list.append(
            {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "roles": ["owner"],
                "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')",
            }
        )
        for member in members:
            member_list.append(
                {
                    "@odata.type": "#microsoft.graph.aadUserConversationMember",
                    "roles": ["owner"],
                    "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{member}')",
                }
            )

        return member_list

    @staticmethod
    def _get_user_name(user: dict):
        """
        Receives dict of form  "emailAddress":{"name":"_", "address":"_"} and return the address

        :type user: ``dict``
        :param user: user

        :return: The name of the user
        :rtype: ``str``
        """
        return user.get("user", {}).get("displayName", "")

    @staticmethod
    def _get_body_content(body: dict):
        """
        Receives dict of form  "emailAddress":{"name":"_", "address":"_"} and return the address

        :type body: ``dict``
        :param body: body

        :return: The content of the body
        :rtype: ``str``
        """
        return body.get("content", "")

    def pages_puller(self, response: dict, page_count: int = 100) -> list:
        """Gets first response from API and returns all pages

        Args:
            response (dict):
            page_count (int):

        Returns:
            list: list of all pages
        """
        responses = [response]
        for _i in range(page_count - 1):
            next_link = response.get("@odata.nextLink")
            if next_link:
                response = self.ms_client.http_request("GET", full_url=next_link, url_suffix=None)
                responses.append(response)
            else:
                return responses
        return responses

    def list_chats(self, user_id: str = None, odata: str = None, limit: str = "20") -> dict | list:
        """Returning all chats from given user

        Args:
            user_id (str):
            odata (str):
            limit (str):

        Returns:
            dict or list:
        """
        user_id = user_id if user_id else self.delegated_user
        suffix = f"users/{user_id}/chats"
        odata = f"{odata}&$top={limit}" if odata else f"$top={limit}"

        if odata:
            suffix += f"?{odata}"
        demisto.debug(f"URL suffix is {suffix}")
        response = self.ms_client.http_request(method="GET", url_suffix=suffix)
        return self.pages_puller(response, 1)

    def create_chat(self, subject: str, members: list, user_id: str = None, type="group") -> dict:
        """Create a new chat for a given user

        Args:
            subject (str):
            members (list):
            user_id (str):
            type (str):

        Returns:
            dict:
        """
        user_id = user_id if user_id else self.delegated_user
        suffix = "chats"

        if type == "group":
            json_data = {"chatType": type, "topic": subject, "members": self._build_members_input(user_id, members)}
        else:
            json_data = {"chatType": type, "members": self._build_members_input(user_id, members)}
        return self.ms_client.http_request(method="POST", url_suffix=suffix, json_data=json_data)

    def get_chat(self, chat_id: str, user_id: str = None) -> dict:
        """retrieves an existing chat for a given user

        Args:
            chat_id (str):
            user_id (str):

        Returns:
            dict:
        """
        user_id = user_id if user_id else self.delegated_user
        suffix = f"users/{user_id}/chats/{chat_id}"

        demisto.debug(f"URL suffix is {suffix}")
        response = self.ms_client.http_request(method="GET", url_suffix=suffix)
        return response

    def update_chat(self, chat_id: str, subject: str) -> dict:
        """Updates an existing chat for a given user

        Args:
            chat_id (str):
            subject (str):

        Returns:
            dict:
        """
        suffix = f"chats/{chat_id}"

        json_data = {"topic": subject}
        return self.ms_client.http_request(method="PATCH", url_suffix=suffix, json_data=json_data)

    def list_members(self, chat_id: str, user_id: str = None) -> dict | list:
        """Returning all members from given chat

        Args:
            chat_id (str):
            user_id (str):

        Returns:
            dict or list:
        """
        user_id = user_id if user_id else self.delegated_user
        suffix = f"users/{user_id}/chats/{chat_id}/members"

        demisto.debug(f"URL suffix is {suffix}")
        response = self.ms_client.http_request(method="GET", url_suffix=suffix)
        return response

    def add_member(self, chat_id: str, user_id: str, share_history: bool) -> bool:
        """Add a member to a given chat

        Args:
            chat_id (str):
            user_id (str):
            share_history (bool):

        Returns:
            bool:
        """
        suffix = f"chats/{chat_id}/members"

        json_data = {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "roles": ["owner"],
            "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')",
            "visibleHistoryStartDateTime": "0001-01-01T00:00:00Z" if share_history else "",
        }
        self.ms_client.http_request(method="POST", url_suffix=suffix, json_data=json_data, resp_type="text")

        return True

    def list_messages(self, chat_id: str, user_id: str = None, limit: str = "50") -> dict | list:
        """Returning all mails from given user

        Args:
            chat_id (str):
            user_id (str):
            limit (str):

        Returns:
            dict or list:
        """
        user_id = user_id if user_id else self.delegated_user
        suffix = f"chats/{chat_id}/messages"
        suffix += f"?$top={limit}"

        demisto.debug(f"URL suffix is {suffix}")
        response = self.ms_client.http_request(method="GET", url_suffix=suffix)
        return self.pages_puller(response)

    def send_message(self, chat_id: str, body: str) -> dict:
        """Returning all mails from given user

        Args:
            chat_id (str):
            body (str):

        Returns:
            dict:
        """
        suffix = f"chats/{chat_id}/messages"

        json_data = {"body": {"contentType": "html", "content": body}}
        return self.ms_client.http_request(method="POST", url_suffix=suffix, json_data=json_data)


""" HELPER FUNCTIONS """


def build_chat_object(raw_response: dict | list, user_id: str = None):
    """Building chat entry context
    Getting a list from build_chat_object

    Args:
        user_id (str): user id
        raw_response (dict or list): list of pages

    Returns:
        dict or list: output context
    """

    def build_chat(given_chat: dict) -> dict:
        """

        Args:
            given_chat (dict):

        Returns:
            dict:
        """
        # Dicts
        chat_properties = {
            "ID": "id",
            "Subject": "topic",
            "Created": "createdDateTime",
            "LastUpdatedTime": "lastUpdatedDateTime",
            "Type": "chatType",
        }

        # Create entry properties
        entry = {k: given_chat.get(v) for k, v in chat_properties.items()}

        if user_id:
            entry["UserID"] = user_id
        return entry

    chat_list = []
    if isinstance(raw_response, list):  # response from list_emails_command
        for page in raw_response:
            # raw_response is a list containing multiple pages or one page
            # if value is not empty, there are emails in the page
            value = page.get("value")
            if value:
                for chat in value:
                    chat_list.append(build_chat(chat))
    elif isinstance(raw_response, dict):  # response from get_message_command
        value = raw_response.get("value")
        if value:
            for chat in value:
                chat_list.append(build_chat(chat))
        else:
            return build_chat(raw_response)
    return chat_list


def build_member_object(raw_response: dict | list, chat_id: str) -> dict | list:
    """Building member entry context
    Getting a list from build_member_object

    Args:
        raw_response (dict or list): list of members
        chat_id (str): chat id

    Returns:
        dict or list: output context
    """

    def build_member(given_member: dict) -> dict:
        """

        Args:
            given_member (dict):

        Returns:
            dict:
        """
        # Dicts
        member_properties = {
            "ID": "id",
            "Name": "displayName",
            "HistoryStartTime": "visibleHistoryStartDateTime",
        }

        # Create entry properties
        entry = {k: given_member.get(v) for k, v in member_properties.items()}

        if chat_id:
            entry["ChatID"] = chat_id
        return entry

    member_list = []
    if isinstance(raw_response, list):  # response from list_emails_command
        for page in raw_response:
            # raw_response is a list containing multiple pages or one page
            # if value is not empty, there are emails in the page
            value = page.get("value")
            if value:
                for member in value:
                    member_list.append(build_member(member))
    elif isinstance(raw_response, dict):  # response from get_message_command
        value = raw_response.get("value")
        if value:
            for member in value:
                member_list.append(build_member(member))
        else:
            return build_member(raw_response)
    return member_list


def build_message_object(raw_response: dict | list, chat_id: str) -> dict | list:
    """Building message entry context
    Getting a list from build_message_object

    Args:
        raw_response (dict or list): list of messages
        chat_id (str): chat id

    Returns:
        dict or list: output context
    """

    def build_message(given_message: dict) -> dict:
        """

        Args:
            given_message (dict):

        Returns:
            dict:
        """
        # Dicts
        message_properties = {
            "ID": "id",
            "Created": "createdDateTime",
            "LastModifiedTime": "lastModifiedDateTime",
        }

        # Create entry properties
        entry = {k: given_message.get(v) for k, v in message_properties.items()}

        entry["From"] = given_message.get("from", {}).get("user", {}).get("displayName", "")
        entry["Body"] = given_message.get("body", {}).get("content", "")

        if chat_id:
            entry["ChatID"] = chat_id
        return entry

    message_list = []
    if isinstance(raw_response, list):  # response from list_emails_command
        for page in raw_response:
            # raw_response is a list containing multiple pages or one page
            # if value is not empty, there are emails in the page
            value = page.get("value")
            if value:
                for message in value:
                    if message.get("messageType") == "message" and message.get("from", {}).get("user"):
                        message_list.append(build_message(message))
    elif isinstance(raw_response, dict):  # response from get_message_command
        value = raw_response.get("value")
        if value:
            for message in value:
                if message.get("messageType") == "message":
                    message_list.append(build_message(message))
        else:
            return build_message(raw_response)
    return message_list


""" COMMANDS """


def test_function(client, _):
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns ok if successful.
    """
    response = "ok"
    if demisto.params().get("self_deployed", False):
        response = "```✅ Success!```"
        if demisto.command() == "test-module":
            # cannot use test module due to the lack of ability to set refresh token to integration context
            # for self deployed app
            raise Exception(
                "When using a self-deployed configuration, "
                "Please enable the integration and run the !msgraph-teams-test command in order to test it"
            )

    client.ms_client.http_request(method="GET", url_suffix="chats")
    return_results(CommandResults(readable_output="✅ Success!"))
    return response, None, None


def list_chats_command(client: MsGraphClient, args):
    user_id = args.get("user_id")
    odata = args.get("odata")
    limit = args.get("limit")

    raw_response = client.list_chats(user_id=user_id, odata=odata, limit=limit)
    last_page_response = raw_response[len(raw_response) - 1]
    metadata = ""
    next_page = last_page_response.get("@odata.nextLink")
    if next_page:
        metadata = "\nPay attention there are more results than shown"

    chat_context = build_chat_object(raw_response, user_id)
    entry_context = {}
    if chat_context:
        entry_context = {"MSGraphTeamsChat(val.ID === obj.ID)": chat_context}
        if next_page:
            # .NextPage.indexOf(\'http\')>=0 : will make sure the NextPage token will always be updated because it's a url
            entry_context["MSGraphTeamsChat(val.NextPage.indexOf('http')>=0)"] = {"NextPage": next_page}

        # human_readable builder
        human_readable_header = (
            f"{len(chat_context)} chats found {metadata}" if metadata else f"Total of {len(chat_context)} chats found"
        )
        human_readable = tableToMarkdown(
            human_readable_header, chat_context, headers=["Subject", "Created", "LastUpdatedTime", "Type", "ID"]
        )
    else:
        human_readable = "### No chats were found"
    return_outputs(human_readable, entry_context, raw_response)


def create_chat_command(client: MsGraphClient, args):
    user_id = args.get("user_id")
    subject = args.get("subject")
    type = args.get("type")
    members = argToList(args.get("members"))

    raw_response = client.create_chat(subject, members, user_id=user_id, type=type)
    chat_context = build_chat_object(raw_response, user_id)
    entry_context = {}
    if chat_context:
        entry_context = {"MSGraphTeamsChat(val.ID === obj.ID)": chat_context}  # human_readable builder
        human_readable_header = f"The chat was created with subject: {subject}"
        human_readable = tableToMarkdown(
            human_readable_header, chat_context, headers=["Subject", "Created", "LastUpdatedTime", "Type", "ID"]
        )
    else:
        human_readable = "### No chats were created"
    return_outputs(human_readable, entry_context, raw_response)


def get_chat_command(client: MsGraphClient, args):
    user_id = args.get("user_id")
    chat_id = args.get("chat_id")

    raw_response = client.get_chat(chat_id, user_id=user_id)
    chat_context: dict = build_chat_object(raw_response, user_id)
    entry_context = {}
    if chat_context:
        entry_context = {"MSGraphTeamsChat(val.ID === obj.ID)": chat_context}  # human_readable builder
        subject = chat_context.get("Subject")
        human_readable_header = f"The chat was found, with subject: {subject}"
        human_readable = tableToMarkdown(
            human_readable_header, chat_context, headers=["Subject", "Created", "LastUpdatedTime", "Type", "ID"]
        )
    else:
        human_readable = "### No chats were found"
    return_outputs(human_readable, entry_context, raw_response)


def update_chat_command(client: MsGraphClient, args):
    chat_id = args.get("chat_id")
    subject = args.get("subject")

    raw_response = client.update_chat(chat_id, subject)
    chat_context = build_chat_object(raw_response)
    entry_context = {}
    if chat_context:
        entry_context = {"MSGraphTeamsChat(val.ID === obj.ID)": chat_context}  # human_readable builder
        human_readable_header = f"The chat was updated with subject: {subject}"
        human_readable = tableToMarkdown(
            human_readable_header, chat_context, headers=["Subject", "Created", "LastUpdatedTime", "Type", "ID"]
        )
    else:
        human_readable = "### No chats were updated"
    return_outputs(human_readable, entry_context, raw_response)


def list_members_command(client: MsGraphClient, args):
    user_id = args.get("user_id")
    chat_id = args.get("chat_id")

    raw_response = client.list_members(chat_id, user_id=user_id)
    member_context = build_member_object(raw_response, chat_id)
    entry_context = {}
    if member_context:
        entry_context = {"MSGraphTeamsChatMember(val.ID === obj.ID)": member_context}

        # human_readable builder
        human_readable_header = f"Total of {len(member_context)} members found"
        human_readable = tableToMarkdown(
            human_readable_header, member_context, headers=["Name", "HistoryStartTime", "ID", "ChatID"]
        )
    else:
        human_readable = "### No members were found"
    return_outputs(human_readable, entry_context, raw_response)


def add_member_command(client: MsGraphClient, args):
    chat_id = args.get("chat_id")
    user_id = args.get("user_id")
    share_history = args.get("share_history") == "true"

    client.add_member(chat_id, user_id, share_history)

    human_readable = tableToMarkdown(
        "Member has been added successfully",
        {"Chat ID": chat_id, "User ID": user_id, "Share history": share_history},
        headers=["Chat ID", "User ID", "Share history"],
        removeNull=True,
    )
    return_outputs(human_readable)


def list_messages_command(client: MsGraphClient, args):
    user_id = args.get("user_id")
    chat_id = args.get("chat_id")
    limit = args.get("limit")

    raw_response = client.list_messages(chat_id, user_id=user_id, limit=limit)
    # return_outputs(raw_response)
    last_page_response = raw_response[len(raw_response) - 1]
    metadata = ""
    next_page = last_page_response.get("@odata.nextLink")
    if next_page:
        metadata = "\nPay attention there are more results than shown"

    message_context = build_message_object(raw_response, chat_id)
    entry_context = {}
    if message_context:
        entry_context = {"MSGraphTeamsChatMessage(val.ID === obj.ID)": message_context}
        if next_page:
            # .NextPage.indexOf(\'http\')>=0 : will make sure the NextPage token will always be updated because it's a url
            entry_context["MSGraphTeamsChatMessage(val.NextPage.indexOf('http')>=0)"] = {"NextPage": next_page}

        # human_readable builder
        human_readable_header = (
            f"{len(message_context)} messages found {metadata}" if metadata else f"Total of {len(message_context)} messages found"
        )
        human_readable = tableToMarkdown(
            human_readable_header, message_context, headers=["Body", "Created", "From", "ID", "ChatID"]
        )
    else:
        human_readable = "### No messages were found"
    return_outputs(human_readable, entry_context, raw_response)


def send_message_command(client: MsGraphClient, args):
    chat_id = args.get("chat_id")
    body = args.get("body")

    raw_response = client.send_message(chat_id, body)
    message_context = build_message_object(raw_response, chat_id)
    entry_context = {}
    if message_context:
        entry_context = {"MSGraphTeamsChatMessage(val.ID === obj.ID)": message_context}  # human_readable builder
        human_readable_header = "The message was send"
        human_readable = tableToMarkdown(
            human_readable_header, message_context, headers=["Body", "Created", "From", "ID", "ChatID"]
        )
    else:
        human_readable = "### No messages were send"
    return_outputs(human_readable, entry_context, raw_response)


def run_command(commands, command, client: MsGraphClient, args, tries):
    while tries > 0:
        try:
            commands[command](client, demisto.args())  # type: ignore
        except NotFoundError as err:
            tries = tries - 1
            if tries == 0:
                return_error(err)
        else:
            tries = 0


def main():
    """COMMANDS MANAGER / SWITCH PANEL"""
    params: dict = demisto.params()
    url = params.get("url", "").rstrip("/") + "/v1.0/"
    tenant: str = params.get("tenant_id", "")
    auth_and_token_url: str = params.get("client_id", "")
    enc_key: str = params.get("secret", "")
    verify: bool = not params.get("insecure", False)
    self_deployed: bool = params.get("self_deployed", False)
    redirect_uri: str = params.get("redirect_uri", "")
    auth_code: str = params.get("auth_code", "")
    app_name: str = "ms-graph-teams"
    proxy: bool = params.get("proxy", False)
    handle_error: bool = argToBoolean(params.get("handle_error", "true"))
    certificate_thumbprint: str = params.get("certificate_thumbprint", "")
    private_key: str = params.get("private_key", "")
    if not self_deployed and not enc_key:
        raise DemistoException(
            "Key must be provided. For further information see "
            "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
        )
    elif not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException("Key or Certificate Thumbprint and Private Key must be provided.")

    # params related to teams to fetch incidents
    delegated_user = params.get("delegated_user", "")
    tries = 3

    commands = {
        "msgraph-teams-test": test_function,
        "test-module": test_function,
        "msgraph-teams-list-chats": list_chats_command,
        "msgraph-teams-create-chat": create_chat_command,
        "msgraph-teams-get-chat": get_chat_command,
        "msgraph-teams-update-chat": update_chat_command,
        "msgraph-teams-list-members": list_members_command,
        "msgraph-teams-add-member": add_member_command,
        "msgraph-teams-list-messages": list_messages_command,
        "msgraph-teams-send-message": send_message_command,
    }
    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client: MsGraphClient = MsGraphClient(
            tenant_id=tenant,
            auth_id=auth_and_token_url,
            enc_key=enc_key,
            app_name=app_name,
            base_url=url,
            verify=verify,
            proxy=proxy,
            self_deployed=self_deployed,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            handle_error=handle_error,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            delegated_user=delegated_user,
        )
        if command == "msgraph-teams-generate-login-url":
            return_results(generate_login_url(client.ms_client))
        elif command == "msgraph-teams-auth-reset":
            return_results(reset_auth())
        else:
            run_command(commands, command, client, demisto.args(), tries)

    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
