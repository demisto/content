from typing import (
    Any,
    Dict
)
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


class GwAPIException(Exception):
    """A base class from which all other exceptions inherit.

    If you want to catch all errors that the gwapi_benedictine package might raise,
    catch this base exception.
    """


class GwRequests():
    """Allows to easily interact with HTTP server.

    Class features:
      - Get requests package wrapper.
      - Put requests package wrapper.
      - Post requests package wrapper.
      - Delete requests package wrapper.
    """

    PROXIES = {
        "http": "",
        "https": ""
    }

    def __init__(self, token: str, headers: dict = {}, check_cert: bool = False, proxy: bool = False) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.url = "api.client.lastinfosec.com/v2"
        self.token = token
        self.headers = headers
        self.check_cert = check_cert
        if proxy:
            self.PROXIES["http"] = os.getenv("http_proxy", "")
            self.PROXIES["https"] = os.getenv("https_proxy", "")

    def _gen_request_kwargs(self,
                            endpoint: str,
                            data: dict,
                            json_data: dict,
                            params: dict,
                            headers: dict,
                            cookies: dict,
                            redirects: bool,
                            files: dict = None) -> dict:
        """Generate requests arguments.

        Args:
            endpoint: URL endpoint in format /XX/YY/ZZ.
            data: request data.
            json_data: Set to True if data is in json_data format and False instead.
            params: Set to True if data need to be send with the url and False instead.
            headers: Set to True if redirection is allowed and False instead.
            cookies: Set to True if redirection is allowed and False instead.
            redirects: Set to True if redirection is allowed and False instead.
            files: files to upload in multipart/form-data

        Returns:
            Return requests arguments in dictionnary format.
        """
        kwargs = {
            "url": f"https://{self.url}{endpoint}",
            "headers": headers if headers else self.headers,
            "cookies": cookies,
            "verify": self.check_cert,
            "proxies": self.PROXIES,
            "allow_redirects": redirects,
            "data": data,
            "json": json_data,
            "params": params,
            "files": files
        }
        return kwargs

    def _get(self, endpoint: str,
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
             redirects: bool = True) -> requests.Response:
        """Wrap the get requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects
        )
        return requests.get(**kwargs)

    def _post(self, endpoint: str,
              data: dict = None,
              json_data: dict = None,
              params: dict = None,
              headers: dict = None,
              cookies: dict = None,
              redirects: bool = True,
              files: dict = None) -> requests.Response:
        """Wrap the post requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.post(**kwargs)


class GwClient(GwRequests):
    """Client class to interact with the service API."""

    def test_module(self):
        """Return True if status_code == 200 and False instead.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint=f"/lis/getbyminutes/0?api_key={self.token}&headers=false"
        )
        if response.status_code == 200:
            demisto.info(
                "Get healthchecks on LIS API: [OK]"
            )
            return True
        else:
            demisto.error(
                "Get healthchecks on LIS API: [FAILED]",
                response.text, response.status_code, response.reason
            )
            return False

    def get_by_minute(self, minute) -> list:
        """Retrieve the data from Gatewatcher CTI feed by minute.
            Max 1440 minutes.

        Args:
            minute: Number of minutes to get. (max 1440 min)

        Returns:
            LIS Json response

        Raises:
            GwAPIException: If status_code != 200.
        """

        response = self._get(
            endpoint=f"/lis/getbyminutes/{arg_to_number(minute)}?api_key={self.token}&headers=false"
        )
        if response.status_code == 200:
            demisto.info("Get ioc by minute : [OK]")
            return response.json()
        else:
            raise GwAPIException(
                "Get ioc by minute: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_by_value(self, value: str) -> dict:
        """Allows you to search for an IOC (url, hash, host) or a vulnerability in the Gatewatcher CTI database.
            If the data is known, only the IOC corresponding to the value will be returned.

        Args:
            value: Value to be search

        Returns:
            Value data

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._post(
            endpoint=f"/lis/search?api_key={self.token}&headers=false",
            json_data=assign_params(value=value)
        )
        if response.status_code == 200:
            demisto.info("Get search ioc: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                "Get search ioc: [FAILED]",
                response.text, response.status_code, response.reason
            )


def test_module(client: GwClient) -> str:  # noqa: E501
    """tests API connectivity.

    Args:
        client: Client to interact with the LIS API.

    Returns:
        'Request successful' when the LIS connection works.
        'Request error' when the LIS connection doesn't works.
    """
    if client.test_module():
        return "ok"
    else:
        return "Request error, please check ip/user/password/token: [ERROR]"


def lis_get_by_minute(client: GwClient, args: Dict[Any, Any]) -> CommandResults:  # noqa: E501
    """Retrieve the data from Gatewatcher CTI feed by minute.
        Max 1440 minutes.

    Args:
        client: Client to interact with the LIS API.
        args: Command arguments.

    Returns:
        CommandResults object with the "LIS.IoC.GetByMinute" prefix.
    """
    minute = arg_to_number(args.get("Minute"))
    categories = argToList(args.get("Categories"))
    risk = argToList(args.get("Risk"))
    tlp = argToList(args.get("TLP"))
    ftype = argToList(args.get("Type"))
    mode = args.get("Mode")

    if "Filename" in ftype:
        raise ValueError("Filter filename is not a valid filter. Please use a different filter option.")
    if "Informational" in risk:
        raise ValueError("Filter informational is not a valid filter. Please use a different filter option.")

    response = client.get_by_minute(minute=minute)

    for case in response:
        if categories:
            case["IOCs"] = [ioc for ioc in case["IOCs"] if set(categories) & set(ioc["Categories"])]
        if ftype:
            case["IOCs"] = [ioc for ioc in case["IOCs"] if ioc["Type"] in ftype]
        if mode:
            case["IOCs"] = [ioc for ioc in case["IOCs"] if mode == ioc["UsageMode"]]
        if risk:
            case["IOCs"] = [ioc for ioc in case["IOCs"] if ioc["Risk"] in risk]
        if tlp:
            case["IOCs"] = [ioc for ioc in case["IOCs"] if ioc["TLP"] in tlp]
    result = [ioc["Value"] for case in response for ioc in case['IOCs']]

    readable_result = tableToMarkdown("Get IoC by minute", result, headers="Value")
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="LIS.GetByMinute",
        outputs_key_field="Value",
        outputs=result,
        raw_response=result
    )


def lis_get_by_value(client: GwClient, args: Dict[Any, Any]) -> CommandResults:  # noqa: E501
    """Allows you to search for an IOC (url, hash, host) or a vulnerability in the Gatewatcher CTI database.
        If the data is known, only the IOC corresponding to the value will be returned.

    Args:
        client: Client to interact with the LIS API.
        args: Command arguments.

    Returns:
        CommandResults object with the "LIS.IoC.GetByValue" prefix.
    """
    value = args["Value"]
    response = client.get_by_value(value=value)

    ioc = list(filter(lambda x: x["Value"] == value, response["IOCs"]))[0]
    result = {
        "Value": ioc["Value"],
        "Risk": ioc["Risk"],
        "Categories": ioc["Categories"],
        "Type": ioc["Type"],
        "TLP": ioc["TLP"],
        "UsageMode": ioc["UsageMode"],
        "Vulnerabilities": ioc["Vulnerabilities"]
    }

    readable_result = tableToMarkdown("Get IoC corresponding to the value", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="LIS.GetByValue",
        outputs_key_field="Value",
        outputs=result,
        raw_response=result
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    token = params.get("token")
    check_cert = params.get("check_cert", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(token=token, proxy=proxy, check_cert=check_cert)
        if command == 'test-module':
            return_results(
                test_module(client=client)
            )
        elif command == "gw-lis-get-by-minute":
            return_results(
                lis_get_by_minute(client=client, args=args)
            )
        elif command == "gw-lis-get-by-value":
            return_results(
                lis_get_by_value(client=client, args=args)
            )
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
