from typing import (
    Any
)
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

INDICATOR_TYPE_TO_DBOT_SCORE = {
    'FILE': DBotScoreType.FILE,
    'URL': DBotScoreType.URL,
    'DOMAIN': DBotScoreType.DOMAIN,
}

INTEGRATION_NAME = "LastInfoSec"


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
                "Get ioc by value: [FAILED]",
                response.text,
                response.status_code,
                response.reason,
            )

    def get_leaked_email_by_domain(self, domain: str, after: str) -> dict:
        """Allows you to search for leaked email by domain in Gatewatcher's CTI database.

        Args:
            domain: Domain to be searched
            after: results before this date won't be returned.

        Returns:
            Value data

        Raises:
            GwAPIException: If status_code != 200.
        """
        url = f"/lis/leaked_emails/get_by_domain/{domain}?api_key={self.token}&headers=false"
        url += f"&added_after={after}" if after else ""

        response = self._get(endpoint=url)

        if response.status_code == 200:
            demisto.info("Get search leaked email: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                "Get leaked email: [FAILED]",
                response.text,
                response.status_code,
                response.reason,
            )

    def get_is_email_leaked(self, email: str, after: str) -> dict:
        """Allows you to search if an email has leaked in Gatewatcher's CTI database.

        Args:
            email: Email to be searched.
            after: results before this date won't be returned.

        Returns:
            Value data

        Raises:
            GwAPIException: If status_code != 200.
        """
        url = f"/lis/leaked_emails/get_by_email/{email}?api_key={self.token}&headers=false"
        url += f"&added_after={after}" if after else ""

        response = self._get(
            endpoint=url,
            json_data=assign_params(value=email),
        )
        if response.status_code == 200:
            demisto.info("Get search leaked email: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                "Get is email leaked: [FAILED]",
                response.text,
                response.status_code,
                response.reason,
            )


def get_dbot_score(risk: str) -> int:
    if risk == 'Malicious':
        return Common.DBotScore.BAD
    if risk == 'Suspicious':
        return Common.DBotScore.SUSPICIOUS
    if risk == 'High suspicious':
        return Common.DBotScore.SUSPICIOUS
    return Common.DBotScore.NONE


def file_indicator(ioc: dict):
    md5 = None
    sha1 = None
    sha256 = None
    sha512 = None

    hash = ioc["Value"]
    hash_type = ioc["Type"]

    if hash_type == 'MD5':
        md5 = hash
    elif hash_type == 'SHA1':
        sha1 = hash
    elif hash_type == 'SHA256':
        sha256 = hash
    elif hash_type == 'SHA512':
        sha512 = hash

    return Common.File(
        dbot_score=get_dbot_score(ioc.get("Risk", "")),
        description=ioc.get("Description"),
        ssdeep=ioc.get("MetaData", {}).get("ssdeep"),
        file_type=ioc.get("MetaData", {}).get("filetype"),
        traffic_light_protocol=ioc.get("TLP"),
        imphash=ioc.get("MetaData", {}).get("imphash"),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        sha512=sha512,
    )


def domain_indicator(ioc: dict):
    return Common.Domain(
        domain=ioc.get("Value"),
        dbot_score=get_dbot_score(ioc.get("Risk", "")),
        description=ioc.get("Description"),
        traffic_light_protocol=ioc.get("TLP"),
    )


def url_indicator(ioc: dict):
    return Common.URL(
        url=ioc.get("Value"),
        dbot_score=get_dbot_score(ioc.get("Risk", "")),
        description=ioc.get("Description"),
        traffic_light_protocol=ioc.get("TLP"),
    )


def generic_reputation_command(
    client: GwClient, args: dict, cmd_type: str, reliability: str
) -> List[CommandResults]:
    """Checks the reputation of a file, domain or url

    Args:
        client: Client to interact with the LIS API.
        args: Command arguments.
        cmd_type: Command type ("file", "domain" or "url")
        reliability: Integration reliability

    Return
        List of CommandResults objects.
    """
    output_prefixes = {
        "file": "LIS.File",
        "domain": "LIS.Domain",
        "url": "LIS.URL",
    }
    arg_list = argToList(args[cmd_type])
    results: List[CommandResults] = []
    indicator_type = cmd_type

    # for each IOC in request args
    for arg in arg_list:
        response = client.get_by_value(value=arg)
        ioc = list(filter(lambda x: x["Value"] == arg, response["IOCs"]))[0]

        lis_result = {
            "Value": ioc["Value"],
            "Risk": ioc["Risk"],
            "Categories": ioc["Categories"],
            "Type": ioc["Type"],
            "TLP": ioc["TLP"],
            "UsageMode": ioc["UsageMode"],
            "Vulnerabilities": ioc["Vulnerabilities"],
        }

        readable_result = tableToMarkdown("Get IoC corresponding to the value", lis_result)

        if cmd_type == "file":
            indicator = file_indicator(ioc)
        elif cmd_type == "domain":
            indicator = domain_indicator(ioc)
        else:
            indicator = url_indicator(ioc)

        indicator.dbot_score = Common.DBotScore(
            indicator=arg,
            integration_name=INTEGRATION_NAME,
            indicator_type=indicator_type,
            score=get_dbot_score(ioc["Risk"]),
            reliability=reliability,
            malicious_description="Match found in LastInfoSec",
        )

        results.append(
            CommandResults(
                indicator=indicator,
                readable_output=readable_result,
                outputs_prefix=output_prefixes[cmd_type],
                outputs_key_field="Value",
                outputs=lis_result,
                raw_response=response,
            )
        )
    return results


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


def lis_get_by_minute(client: GwClient, args: dict[Any, Any]) -> CommandResults:  # noqa: E501
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


def lis_get_by_value(client: GwClient, args: dict[Any, Any]) -> CommandResults:  # noqa: E501
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


def lis_get_leaked_email_by_domain(
    client: GwClient, args: dict[Any, Any]
) -> CommandResults:
    """Allows you to search for leaked email by domain in Gatewatcher's CTI database.

    Args:
        client: Client to interact with the LIS API.
        args: Command arguments,
            Domain: domain to search for.
            After: date to do not return results before this date.

    Returns:
        CommandResults object with the "LIS.leakedEmail.GetByDomain" prefix.
    """
    domain = args.get("Domain")
    after = args.get("After")
    response = client.get_leaked_email_by_domain(domain, after)

    emails = [res["Value"] for res in response]
    result = emails if len(emails) > 0 else None
    readable_result = tableToMarkdown("Leaked email", result, headers="Emails")

    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="LIS.LeakedEmail.GetByDomain",
        outputs=result,
        raw_response=result,
    )


def lis_is_email_leaked(client: GwClient, args: dict[Any, Any]) -> CommandResults:
    """Allows you to search if an email has leaked in Gatewatcher's CTI database.

    Args:
        client: Client to interact with the LIS API.
        args: Command arguments,
            Email: email to search for.
            After: date to do not return results before this date.

    Returns:
        CommandResults object with the "LIS.leakedEmail.getByEmail" prefix.
    """
    email = args.get("Email")
    after = args.get("After")
    response = client.get_is_email_leaked(email, after)

    result = email if len(response) > 0 else None
    readable_result = tableToMarkdown("Is email leaked", result, headers="Value")

    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="LIS.LeakedEmail.GetByEmail",
        outputs=result,
        raw_response=result,
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    token = params.get("token")
    check_cert = params.get("check_cert", False)
    proxy = params.get("proxy", False)
    reliability = params.get('integrationReliability', 'C - Fairly reliable')
    reliability = reliability if reliability else DBotScoreReliability.B

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        return_error("Please provide a valid value for the Source Reliability parameter")

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(token=token, proxy=proxy, check_cert=check_cert)
        if command == 'test-module':
            return_results(
                test_module(client=client)
            )
        elif command == "url":
            return_results(
                generic_reputation_command(client=client, args=args, cmd_type='url', reliability=reliability)
            )
        elif command == "file":
            return_results(
                generic_reputation_command(client=client, args=args, cmd_type='file', reliability=reliability)
            )
        elif command == "domain":
            return_results(
                generic_reputation_command(client=client, args=args, cmd_type='domain', reliability=reliability)
            )
        elif command == "gw-lis-get-by-minute":
            return_results(
                lis_get_by_minute(client=client, args=args)
            )
        elif command == "gw-lis-get-by-value":
            return_results(
                lis_get_by_value(client=client, args=args)
            )
        elif command == "gw-lis-leaked-email-by-domain":
            return_results(
                lis_get_leaked_email_by_domain(client=client, args=args)
            )
        elif command == "gw-lis-is-email-leaked":
            return_results(
                lis_is_email_leaked(client=client, args=args)
            )
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
