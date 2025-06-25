import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"


""" CLIENT CLASS """

class Client(BaseClient):
    """
    Client to use in the Anomali ThreatStream Feed integration. Overrides BaseClient
    """

    def __init__(self, base_url, user_name, password, base64String, verify):
        super().__init__(base_url=base_url, verify=verify, ok_codes=(200, 201, 202))
        self.credentials = {
             "Authorization": "Basic " + base64String, "Content-Type": "application/json"
        }

    def http_request(
        self,
        method,
        url_suffix,
        params=None,
        data=None,
        headers=None,
        files=None,
        json=None,
        without_credentials=False,
        resp_type="json",
    ):
        """
        A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        headers = headers or {}
        if not without_credentials:
            headers.update(self.credentials)
        res = super()._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            data=data,
            json_data=json,
            files=files,
            resp_type=resp_type,
            error_handler=self.error_handler,
            retries=2,
        )
        return res

    def error_handler(self, res: requests.Response):  # pragma: no cover
        """
        Error handler to call by super()._http_request in case an error was occurred.
        Handles specific HTTP status codes and raises a DemistoException.
        Args:
            res (requests.Response): The HTTP response object.
        """
        # Handle error responses gracefully
        if res.status_code == 401:
            raise DemistoException(f"{SAP_CLOUD} - Got unauthorized from the server. Check the credentials. {res.text}")
        elif res.status_code == 204:
            return
        elif res.status_code == 404:
            raise DemistoException(f"{SAP_CLOUD} - The resource was not found. {res.text}")
        raise DemistoException(f"{SAP_CLOUD} - Error in API call {res.status_code} - {res.text}")

""" HELPER FUNCTIONS """

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

""" COMMAND FUNCTIONS """

def encode_to_base64(input_string):
  """
  Encodes a given string into its Base64 representation.

  Args:
    input_string: The string to be encoded.

  Returns:
    The Base64 encoded string.
  """
  bytes_string = input_string.encode('utf-8')
  encoded_bytes = base64.b64encode(bytes_string)
  encoded_string = encoded_bytes.decode('utf-8')
  return encoded_string


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): The client object to use for API requests.
    Returns:
        str: 'ok' if the test passed, otherwise raises an exception.
    """
    url = """/sap/c4c/odata/ana_businessanalytics_analytics.svc/RPZA9F4655905ABCDBA01BD67QueryResults?"""
    client.http_request("GET", url_suffix=f"{url}/", params={"$filter": "CTIMESTAMP ge '25.06.2025 17:46:40 INDIA'", "$top": 2,
                                                             "$format": "json"})
    return "ok"


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(
    client: Client, args: Dict[str, Any]):
    # dummy = args.get("dummy")  # dummy is a required argument, no default
    # dummy2 = args.get("dummy2")  # dummy2 is not a required argument

    # # Call the Client function and get the raw response
    # result = client.baseintegration_dummy(dummy, dummy2)

    # return CommandResults(
    #     outputs_prefix="BaseIntegration",
    #     outputs_key_field="",
    #     outputs=result,
    # )
    pass


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    params = demisto.params()

    # init credentials
    user_name = demisto.get(params, "username.identifier")
    password = demisto.get(params, "username.password")
    server_url = params.get("url", "").strip("/")
    try:
        
        base64String = encode_to_base64(user_name + ":" + password) # type: ignore
        client = Client(
            base_url=f"{server_url}/api/",
            user_name=user_name,
            password=password,
            base64String = base64String,
            verify=not params.get("insecure", False),
        )

        if command == "test-module":
            # This call is made when clicking the integration 'Test' button.
            return_results(test_module(client))
        elif command == "baseintegration-dummy":
            # result = baseintegration_dummy_command(client, args)
            pass
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
