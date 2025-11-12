import re
import urllib3
import demistomock as demisto
from CommonServerPython import *


# Disable insecure connection warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, base_url: str, proxy: bool, verify: bool, headers: dict):
        """
        Client to use. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request. Webhook url.
        """
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)

    def unshorten_request(self, short_url: str):
        """Sends the unshorten request to the unshorten.me API.

        This method constructs and sends a GET request to the /unshorten
        endpoint. It checks the API response for a 'success' status and
        raises an exception if the API indicates an error.

        Args:
            short_url (str): The shortened URL to be resolved.

        Returns:
            CommandResults: An object containing the API response and
            formatted markdown for the War Room.

        Raises:
            DemistoException: If the API returns a non-successful status
            or if the request fails.
        """
        outputs = []
        res = self._http_request(method="GET", raise_on_status=True, url_suffix="/unshorten", params={"url": short_url})
        demisto.info(f"Request sent. Respons{res}")

        if not res.get("success"):
            error_message = res.get("error_message", "Unknown API Error")
            raise DemistoException(f"unshorten.me API error: {error_message}")

        outputs.append(
            {
                "unshortened_url": res.get("unshortened_url"),
                "shortened_url": res.get("shortened_url"),
                "success": res.get("success"),
            }
        )

        table_headers = ["unshortened_url", "shortened_url", "success"]
        return CommandResults(
            outputs_prefix="unshortenMe",
            outputs=outputs,
            readable_output=tableToMarkdown("unshorten.me results", outputs, table_headers, removeNull=True),
            raw_response=res,
        )

    def is_valid(self, url: str):
        """
        This regex checks for the basic components of a URL
        """
        regex = re.compile(
            r"^(?:http|ftp)s?://"  # http:// or https://
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"  # subdomain
            r"(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # top-level domain
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return re.match(regex, url) is not None


def unshorten_url_command(client: Client, short_url):
    """Validates and processes the URL unshorten command.

    This function serves as the command handler. It first validates
    that the input string is a properly formatted URL and then passes
    it to the client to perform the unshortening request.

    Args:
        client (Client): The API client instance.
        short_url (str): The user-provided URL to unshorten.

    Returns:
        CommandResults: The result object from the client's
                        unshorten_request method.

    Raises:
        ValueError: If the input `short_url` is not in a valid
                    URL format (e.g., missing http:// or https://).
    """
    is_url = client.is_valid(short_url)
    if is_url is False:
        raise ValueError(
            f"Input is not a valid URL format. It must include http:// or https://." f"\nInput provided: {short_url}"
        )

    res = client.unshorten_request(short_url)
    return res


def test_module(client):
    """
    Test command will send a Shortened URL

    Args:
        client (Client): unshorten.me client to use

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        short_url = "https://bit.ly/3DKWm5t"
        client.unshorten_request(short_url=short_url)
        return "ok"
    except DemistoException as e:
        return f"Error: {e}"


def main():
    """
    Main function, pares integratio parameters, runs
    command functions, executes a test, unshortens URLs
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    token = params.get("credentials", {}).get("password")
    base_url = "https://unshorten.me/api/v2/"
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)
    headers = {"Authorization": f"Token {token}"}

    try:
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, headers=headers)

        # Runs the unshorten command
        if command == "unshorten-me-unshorten-url":
            short_url = args.get("shortUrl")
            return_results(unshorten_url_command(client, short_url))
        # Runs the test module when the test button is selected
        elif command == "test-module":
            return_results(test_module(client))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} encountered {e}.")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
