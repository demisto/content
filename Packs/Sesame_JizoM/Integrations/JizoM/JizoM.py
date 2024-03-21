import demistomock as demisto  # noqa: F401
# from CommonServerPython import *  # noqa: F401
import urllib3
import requests
# Disable insecure warnings
urllib3.disable_warnings()


class JizoMClient():
    """
    Add description
    """

    def __init__(
        self,
        url: str,
        headers: dict = {},
        credentials: dict = {},
        proxy: bool = False,
        verify: bool = False,
    ) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.url = url
        self.headers = headers
        self.credentials = credentials
        self.proxy = proxy
        self.verify = verify

    def test_module(self):
        return True


def get_token(client: JizoMClient):
    try:
        url = f"http://{client.url}/login"

        # Include username and password as JSON in the request body
        data = {
            "username": client.credentials["username"],
            "password": client.credentials["password"],
        }

        # Define headers
        headers = {"Content-Type": "application/json"}

        # Sending POST request to the API endpoint with the specified headers and request body
        response = requests.post(
            url, headers=headers, json=data, verify=False
        )  # Setting verify=False ignores SSL certificate verification. Be cautious about using it in a production environment.
        # Checking if the request was successful (status code 200)
        if response.status_code == 200:
            return response.json()
        else:
            # return_error(f"Error: {response.status_code} - {response.text}")
            print(f"Error: {response.status_code} - {response.text}")

    except Exception as e:
        # return_error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")


def get_info(client: JizoMClient, token: str, endpoint: str):
    try:
        url = f"http://{client.url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        # Sending GET request to the API endpoint with the specified headers
        response = requests.get(
            url, headers=headers, verify=False
        )  # Setting verify=False ignores SSL certificate verification. Be cautious about using it in a production environment.

        # Checking if the request was successful (status code 200)
        if response.status_code == 200:
            return response.json()
        else:
            # return_error(f"Error: {response.status_code} - {response.text}")
            print(f"Error: {response.status_code} - {response.text}")

    except Exception as e:
        # return_error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")


def test_module(client: JizoMClient) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: Viper client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    if client.test_module():
        return "ok"
    else:
        return "error"


def main():

    # Parse parameters
    params=demisto.params()
    command = demisto.command()
    args=demisto.args()
    # api_url = params.get("url")
    api_url = "127.0.0.1:9001"
    # credentials = {
    #     "username": params.get("username"),
    #     "password": params.get("password"),
    # }
    credentials = {
        "username": "operator",
        "password": "Sesame@debian01",
    }
    headers = {"Accept": "application/json"}
    demisto.debug(f"Command being called is {command}")
    try:
        client = JizoMClient(
            url=api_url,
            headers=headers,
            credentials=credentials,
            proxy=False,
            verify=False,
        )
        # Get token to connect
        connect = get_token(client)
        token = connect["token"]
        print(token)
        print("*************")
        result = get_info(client, token=token, endpoint="/jizo_get_peers")
        print(result)
        # if command == "test-module":
        #     # This is the call made when clicking the integration Test button.
        #     return_results(test_module(client))

        # elif command == "protocols":
        #     return_results(
        #         get_info(client, token=token, endpoint="/jizo_get_protocols")
        #     )
        # elif command == "peers":
        #     return_results(
        #         get_info(client, token=token, endpoint="/jizo_get_peers")
        #     )
        # elif command == "query_records":
        #     return_results(
        #         get_info(client, token=token, endpoint="/jizo_query_records")
        #     )
        # elif command == "alert_rules":
        #     return_results(
        #         get_info(client, token=token, endpoint="/jizo_get_alert_rules")
        #     )
        # elif command == "device_records":
        #     return_results(
        #         get_info(client, token=token, endpoint="/jizo_device_records")
        #     )
        # elif command == "device_alerts":
        #     return_results(
        #         get_info(client, token=token, endpoint="/jizo_get_devicealerts")
        #     )
        # else:
        #     f"{command} command is not implemented."
    # Log exceptions
    except Exception as e:
        # return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")
        print(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
