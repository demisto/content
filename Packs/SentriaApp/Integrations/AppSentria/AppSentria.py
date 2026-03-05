import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

import dateparser


""" CONSTANTS """
LOG_LINE = "HelloWorldDebugLog: "  # Make sure to use a line easily to search and read in logs.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


""" CLIENT CLASS """


class Client(BaseClient):

    def __init__(self, base_url, headers, verify):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify)
        self.headers = headers

    def send_info(self, body):

        url_suffix = f"/api/alert/upsert"

        response = self._http_request(method="POST", url_suffix=url_suffix, json_data=body, headers=self.headers)

        return response

    def send_message(self, body):

        url_suffix = f"/api/alert/response"

        response = self._http_request(method="POST", url_suffix=url_suffix, json_data=body, headers=self.headers)

        return response

    def send_msg_to_chat(self, body):

        url_suffix = f"/api/chat/system-message"

        response = self._http_request(method="POST", url_suffix=url_suffix, json_data=body, headers=self.headers)

        return response

    def send_request_status(self, body):

        url_suffix = f"/api/case-request-status/wh"

        response = self._http_request(method="POST", url_suffix=url_suffix, json_data=body, headers=self.headers)

        return response


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client, params: dict[str, Any]) -> str:

    return "ok"


def send_info_command(client: Client, args: dict[str, Any]) -> CommandResults:

    res = client.send_info(args)

    return res


def send_message_command(client: Client, args: dict[str, Any]) -> CommandResults:

    res = client.send_message(args)

    return res


def send_msg_to_chat_command(client: Client, args: dict[str, Any]) -> CommandResults:

    res = client.send_msg_to_chat(args)

    return res


def send_request_status_command(client: Client, args: dict[str, Any]) -> CommandResults:

    args["sentriaappinternalcaseid"] = int(args["sentriaappinternalcaseid"])

    res = client.send_request_status(args)

    return res


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("credentials", {}).get("password")

    base_url = params.get("url")

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"x-api-key": f"{api_key}"}
        client = Client(base_url=base_url, headers=headers, verify=False)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        elif command == "app-sentria-send-info":
            return_results(send_info_command(client, args))

        elif command == "app-sentria-send-message":
            return_results(send_message_command(client, args))

        elif command == "app-sentria-send-msg-to-chat":
            return_results(send_msg_to_chat_command(client, args))

        elif command == "app-sentria-send-request-status":
            return_results(send_request_status_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
