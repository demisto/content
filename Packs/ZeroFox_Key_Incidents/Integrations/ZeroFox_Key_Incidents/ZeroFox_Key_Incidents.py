from typing import Any, Callable

import urllib3
import json
from requests import Response
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

""" GLOBALS / PARAMS  """
FETCH_TIME_DEFAULT = "3 days"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
MAX_ALERT_IDS_STORED = 300

# Disable insecure warnings
urllib3.disable_warnings()

class ZFClient(BaseClient):
    def __init__(
        self, username, token, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.credentials = {
            "username": username,
            "password": token
        }

    def _make_rest_call(
        self,
        method: str,
        url_suffix: str = "/",
        cti: bool = True,
        full_url: str | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        ok_codes: tuple[int, ...] = None,
        empty_response: bool = False,
        **kwargs
    ) -> dict[str, Any]:
        """
        :param method: HTTP request type
        :param url_suffix: The suffix of the URL
        :param cti: If the request is to cti endpoint
        :param params: The request's query parameters
        :param data: The request's body parameters
        :param empty_response: Indicates if the response data is empty or not
        :param error_handler: Function that receives the response and manage
        the error
        :return: Returns the content of the response received from the API.
        """
        headers = {}
        if cti:
            headers = self.get_cti_request_header()

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            params=params,
            json_data=data,
            ok_codes=ok_codes,
            empty_valid_codes=(200, 201),
            return_empty_response=empty_response,
            error_handler=self.handle_zerofox_error,
            **kwargs
        )


    def handle_zerofox_error(self, raw_response: Response):
        status_code = raw_response.status_code
        if status_code >= 500:
            raise ZeroFoxInternalException(
                status_code=status_code,
                cause=raw_response.text,
            )
        cause = self._build_exception_cause(raw_response)
        response = raw_response.json()
        if status_code in [401, 403]:
            raise ZeroFoxAuthException(cause=cause)
        raise ZeroFoxInternalException(
            status_code=status_code,
            cause=str(response),
        )

    def _build_exception_cause(self, raw_response: Response) -> str:
        try:
            response = raw_response.json()
            if non_field_errors := response.get("non_field_errors", []):
                return non_field_errors[0]
            return str(response)
        except json.JSONDecodeError:
            return raw_response.text

    # CTI
    def get_cti_request_header(self) -> dict[str, str]:
        token: str = self.get_cti_authorization_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "zf-source": "XSOAR",
        }

    def get_cti_authorization_token(self) -> str:
        """
        :return: returns the authorization token for the CTI feed
        """
        token = self._get_new_access_token()
        if not token:
            raise Exception("Unable to retrieve token.")
        return token

    def _get_new_access_token(self) -> str:
        url_suffix: str = "/auth/token/"
        response_content = self._make_rest_call(
            "POST",
            url_suffix,
            data=self.credentials,
            cti=False,
        )
        return response_content.get("access", "")

    def get_key_incidents(self, start_time, end_time) -> dict[str, Any]:
        """
        :param start_time: The earliest point in time for which data should be fetched
        :param end_time: The latest point in time for which data should be fetched
        :return: HTTP request content.
        """
        url_suffix = "/cti/key-incidents/"
        params = remove_none_dict({"updated_after": start_time, "updated_before": end_time})
        response_content = self._http_request(
            "GET",
            url_suffix,
            params=params,
            headers_builder_type="cti",
        )
        return response_content

""" HELPERS """
class ZeroFoxInternalException(Exception):
    def __init__(self, status_code: int, cause: str):
        self.status_code = status_code
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred within ZeroFox, please try again later.\
              If the issue persists, contact support.\
              Status Code: {self.status_code}, Response: {self.cause}"


class ZeroFoxAuthException(Exception):
    def __init__(self, cause: str):
        self.cause = cause
        super().__init__(self._generate_msg())

    def _generate_msg(self) -> str:
        return f"An error occurred while trying to authenticate with ZeroFox:\
            \n {self.cause}"


def remove_none_dict(input_dict: dict[Any, Any]) -> dict[Any, Any]:
    """
    removes all none values from a dict
    :param input_dict: any dictionary in the world is OK
    :return: same dictionary but without None values
    """
    return {
        key: value for key, value in input_dict.items()
        if value is not None
    }


""" COMMAND FUNCTIONS """

def get_key_incidents_command(
    client: ZFClient,
    args: dict[str, Any]
) -> CommandResults:
    start_time: str = args.get("start_time", "")
    end_time: str = args.get("end_time", "")
    key_incidents = client.get_key_incidents(start_time, end_time)

    if len(key_incidents) == 0:
        return CommandResults(
            readable_output="No Key Incidents were found",
            outputs=key_incidents,
            outputs_prefix="ZeroFox_Key_Incidents.Key_Incidents",
        )
    return CommandResults(
        outputs=key_incidents,
        readable_output=tableToMarkdown("Key Incidents", outputs),
        outputs_prefix="ZeroFox_Key_Incidents.Key_Incidents",
    )


def test_conectivity(client: ZFClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        ZFClient: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.get_cti_authorization_token()
    return "ok"


def main():
    params = demisto.params()
    USERNAME: str = params.get("credentials", {}).get("identifier")
    API_KEY: str = params.get("credentials", {}).get("password")
    BASE_URL: str = (
        params["url"][:-1]
        if params["url"].endswith("/")
        else params["url"]
    )
    USE_SSL: bool = not params.get("insecure", False)
    PROXY: bool = params.get('proxy', False)

    commands: dict[str, Callable[[ZFClient, dict[str, Any]], Any]] = {
        "zerofox-get-key-incidents": get_key_incidents_command,
    }
    try:
        handle_proxy()
        command = demisto.command()

        client = ZFClient(
            username=USERNAME,
            token=API_KEY,
            base_url=BASE_URL,
            ok_codes={200, 201},
            verify=USE_SSL,
            proxy=PROXY,
        )
        if command == "test-module":
            results = test_conectivity(client)
            return_results(results)
        elif command in commands:
            command_handler = commands[command]
            results = command_handler(client, demisto.args())
            return_results(results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()