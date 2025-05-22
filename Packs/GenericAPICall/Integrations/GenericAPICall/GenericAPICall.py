import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
import requests
import json
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """

CONTENT_TYPE_MAPPER = {
    "json": "application/json",
    "xml": "text/xml",
    "form": "application/x-www-form-urlencoded",
    "data": "multipart/form-data",
}

RAW_RESPONSE = "raw_response"


class Client(BaseClient):
    def __init__(self, base_url: str, auth, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, auth=auth, verify=verify, proxy=proxy)

    def http_request(
        self,
        method: str,
        full_url: str = "",
        headers: dict = None,
        resp_type: str = RAW_RESPONSE,
        params: dict = None,
        data: str = None,
        timeout: int = 10,
        retries: int = 0,
        status_list_to_retry: list = None,
        raise_on_status: bool = False,
        allow_redirects: bool = True,
        backoff_factor: int = 5,
    ):
        try:
            res = self._http_request(
                method=method,
                full_url=full_url,
                headers=headers,
                params=params,
                timeout=timeout,
                resp_type=resp_type,
                status_list_to_retry=status_list_to_retry,
                raise_on_status=raise_on_status,
                retries=retries,
                data=data,
                error_handler=self._generic_error_handler,
                allow_redirects=allow_redirects,
                backoff_factor=backoff_factor,
            )
        except Exception as e:
            return_error(f"Failed to execute API call. Error: {str(e)}")
        return res

    @staticmethod
    def _generic_error_handler(res: requests.Response):
        status_code = res.status_code
        if status_code == 400:
            raise DemistoException(f"Bad request. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 401:
            raise DemistoException(f"Unauthorized. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 403:
            raise DemistoException(f"Invalid permissions. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 404:
            raise DemistoException(
                f"The server has not found anything matching the request URI. Status code:"
                f" {status_code}. Origin response from server: {res.text}"
            )
        if status_code == 500:
            raise DemistoException(f"Internal server error. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 502:
            raise DemistoException(f"Bad gateway. Status code: {status_code}. Origin response from server: {res.text}")


def create_headers(headers: Dict, request_content_type_header: str, response_content_type_header: str) -> Dict[str, str]:
    """
    Create a dictionary of headers. It will map the header if it exists in the CONTENT_TYPE_MAPPER.
    Args:
        headers: The headers the user insert.
        request_content_type_header: The content type header.
        response_content_type_header: The response type header.

    Returns:
        A dictionary of headers to send in the request.
    """
    if request_content_type_header in CONTENT_TYPE_MAPPER:
        request_content_type_header = CONTENT_TYPE_MAPPER[request_content_type_header]
    if response_content_type_header in CONTENT_TYPE_MAPPER:
        response_content_type_header = CONTENT_TYPE_MAPPER[response_content_type_header]
    if request_content_type_header and not headers.get("Content-Type"):
        headers["Content-Type"] = request_content_type_header
    if response_content_type_header and not headers.get("Accept"):
        headers["Accept"] = response_content_type_header

    return headers


def get_parsed_response(res, resp_type: str) -> Any:
    try:
        resp_type = resp_type.lower()
        if resp_type == "json":
            res = res.json()
        elif resp_type == "xml":
            res = json.loads(xml2json(res.content))
        else:
            res = res.text
        return res
    except ValueError as e:
        raise DemistoException(f"Failed to parse json object from response: {res.content}\n\nError Message: {e}")


def format_status_list(status_list: list) -> List[int]:
    """
    Get a status list and format it to a range of status numbers.
    Example:
        given: ['400-404',500,501]
        return: [400,401,402,403,500,501]
    Args:
        status_list: The given status list.
    Returns:
        A list of statuses to retry.
    """
    final_status_list = []
    for status in status_list:
        # Checks if the status is a range of statuses
        if "-" in status:
            range_numbers = status.split("-")
            status_range = list(range(int(range_numbers[0]), int(range_numbers[1]) + 1))
            final_status_list.extend(status_range)
        elif status.isdigit():
            final_status_list.append(int(status))
    return final_status_list


def build_outputs(parsed_res, res: requests.Response) -> Dict:
    return {
        "ParsedBody": parsed_res,
        "Body": res.text,
        "StatusCode": res.status_code,
        "StatusText": res.reason,
        "URL": res.url,
        "Headers": dict(res.headers),
    }


def parse_headers(headers: str) -> Dict:
    """
    Parsing headers from str type to dict.
    The allowed format are:
    1. {"key": "value"}
    2. "key": "value"
    """
    if not headers.startswith("{") and not headers.endswith("}"):
        headers = "{" + headers + "}"
    try:
        headers_dict = json.loads(headers)
    except json.decoder.JSONDecodeError:
        raise DemistoException("Make sure the headers are in one of the allowed formats.")
    return headers_dict


def api_call_command(client: Client):
    dmst_params = demisto.params()
    apikey_in_header = dmst_params.get("apikey_in_header", True)
    api_call_key = dmst_params.get("api_call_key", "")
    is_auth = argToBoolean(dmst_params.get("is_auth", "False"))

    cmd_args = demisto.args()
    method = cmd_args.get("method", "")
    body = cmd_args.get("body", "")
    request_content_type = cmd_args.get("request_content_type", "")
    response_content_type = cmd_args.get("response_content_type", "")
    parse_response_as = cmd_args.get("parse_response_as", RAW_RESPONSE)
    params = cmd_args.get("params", {})
    headers = cmd_args.get("headers", {})
    if not api_call_key and is_auth:
        demisto.error("Parameter/Header key used for API call must be specified")
    elif is_auth:
        if apikey_in_header:
            headers.update({api_call_key: demisto.getParam("credentials")["password"]})
        else:
            params.update({api_call_key: demisto.getParam("credentials")["password"]})
    url_path = cmd_args.get("urlpath", "/")
    if isinstance(headers, str):
        headers = parse_headers(headers)
    headers = create_headers(headers, request_content_type, response_content_type)
    save_as_file = argToBoolean(cmd_args.get("save_as_file", False))
    file_name = cmd_args.get("filename", "http-file")
    timeout = arg_to_number(cmd_args.get("timeout", 10))
    timeout_between_retries = cmd_args.get("timeout_between_retries", 5)
    retry_count = arg_to_number(cmd_args.get("retry_count", 3))

    kwargs = {
        "method": method,
        "full_url": client._base_url + url_path,
        "headers": headers,
        "data": body,
        "timeout": timeout,
        "params": params,
        "backoff_factor": timeout_between_retries,
    }

    retry_on_status = cmd_args.get("retry_on_status", None)
    raise_on_status = bool(retry_on_status)
    retry_status_list = format_status_list(argToList(retry_on_status))

    if raise_on_status:
        kwargs.update({"retries": retry_count, "status_list_to_retry": retry_status_list, "raise_on_status": raise_on_status})

    enable_redirect = argToBoolean(cmd_args.get("enable_redirect", True))

    if not enable_redirect:
        kwargs.update({"allow_redirects": enable_redirect})

    res = client.http_request(**kwargs)
    parsed_res = get_parsed_response(res, parse_response_as)

    if save_as_file:
        return fileResult(file_name, res.content)

    outputs = build_outputs(parsed_res, res)

    return CommandResults(
        readable_output=f"Sent a {method} request to {client._base_url}",
        outputs_prefix="APICall",
        outputs=outputs,
        raw_response={"data": parsed_res},
    )


def test_module(client):
    # Basic test logic to validate the connection or configuration
    return """Test-module is not implemented in this integration due to the number
            of possible API endpoints that may be configured."""


""" MAIN FUNCTION """


def main():
    try:
        params = demisto.params()
        results = ""
        auth: Optional[tuple[str, str]] = None
        base_url = params.get("base_url", "")
        is_auth = params.get("is_auth", True)
        creds = params.get("credentials", "")
        proxy = params.get("proxy", False)
        verify = not params.get("insecure", True)

        command = demisto.command()

        if command == "generic-api-call":
            if is_auth:
                # Credential object - API Key or HTTP Basic Auth
                if "credentials" in creds and creds["credentials"]["name"]:
                    auth = (creds["credentials"]["user"], creds["credentials"]["password"])
                # Creds configured in integration instance
                elif "credentials" not in creds:
                    auth = (creds["identifier"], creds["password"])
            else:
                auth = None

            client = Client(base_url, auth=auth, verify=verify, proxy=proxy)

            demisto.debug(f"Command being called is {command}")
            results = api_call_command(client)
        elif command == "test-module":
            return_results(test_module(client))
        return_results(results)

    except Exception as e:
        return_error(f"Failed to execute generic API call. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
