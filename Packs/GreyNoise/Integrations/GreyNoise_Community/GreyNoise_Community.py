import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" Imports """

import urllib3  # type: ignore
import traceback
import requests
import copy
from greynoise import GreyNoise, util  # type: ignore
from greynoise.exceptions import RequestFailure, RateLimitError  # type: ignore

# Disable insecure warnings
urllib3.disable_warnings()
util.LOGGER.warning = util.LOGGER.debug

""" CONSTANTS """

PRETTY_KEY = {
    "ip": "IP",
    "noise": "Noise",
    "riot": "Riot",
    "classification": "Classification",
    "name": "Name",
    "link": "Link",
    "last_seen": "Last Seen",
    "message": "Message",
}
IP_CONTEXT_HEADERS = [
    "IP",
    "Noise",
    "Riot",
    "Classification",
    "Name",
    "Link",
    "Last Seen",
]
EXCEPTION_MESSAGES = {
    "API_RATE_LIMIT": "API Rate limit hit. Try after sometime.",
    "UNAUTHENTICATED": "Unauthenticated. Check the configured API Key.",
    "COMMAND_FAIL": "Failed to execute {} command.\n Error: {}",
    "SERVER_ERROR": "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    "CONNECTION_TIMEOUT": "Connection timed out. Check your network connectivity.",
    "PROXY": "Proxy Error - cannot connect to proxy. Either try clearing the "
    "'Use system proxy' check-box or check the host, "
    "authentication details and connection details for the proxy.",
    "INVALID_RESPONSE": "Invalid response from GreyNoise. Response: {}",
    "QUERY_STATS_RESPONSE": "GreyNoise request failed. Reason: {}",
}
""" CLIENT CLASS """


class Client(GreyNoise):
    """Client class to interact with the service API"""

    def authenticate(self):
        """
        Used to authenticate GreyNoise credentials.
        """
        try:
            self.test_connection()
            return "ok"

        except RateLimitError:
            raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])

        except RequestFailure as err:
            status_code = err.args[0]
            body = str(err.args[1])

            if status_code == 401:
                raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])
            elif status_code == 429:
                raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])
            elif 400 <= status_code < 500:
                raise DemistoException(
                    EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), body)
                )
            elif status_code >= 500:
                raise DemistoException(EXCEPTION_MESSAGES["SERVER_ERROR"])
            else:
                raise DemistoException(str(err))
        except requests.exceptions.ConnectTimeout:
            raise DemistoException(EXCEPTION_MESSAGES["CONNECTION_TIMEOUT"])
        except requests.exceptions.ProxyError:
            raise DemistoException(EXCEPTION_MESSAGES["PROXY"])


""" HELPER FUNCTIONS """


def exception_handler(func: Any) -> Any:
    """
    Decorator to handle all type of errors possible with GreyNoise SDK.
    """

    def inner_func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RateLimitError:
            raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])
        except RequestFailure as err:
            status_code = err.args[0]
            body = str(err.args[1])
            if status_code == 401:
                raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])
            elif status_code == 429:
                raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])
            elif 400 <= status_code < 500:
                raise DemistoException(
                    EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), body)
                )
            elif status_code >= 500:
                raise DemistoException(EXCEPTION_MESSAGES["SERVER_ERROR"])
            else:
                raise DemistoException(str(err))
        except requests.exceptions.ConnectTimeout:
            raise DemistoException(EXCEPTION_MESSAGES["CONNECTION_TIMEOUT"])
        except requests.exceptions.ProxyError:
            raise DemistoException(EXCEPTION_MESSAGES["PROXY"])

    return inner_func


def get_ip_context_data(responses: list) -> list:
    """Parse ip context and raw data from GreyNoise SDK response.

    Returns value of ip context data.
    Returns value of ip raw data.

    :type responses: ``list``
    :param responses: list of values of ip-context or ip-query.

    :return: list of ips context data.
    :rtype: ``list``
    """

    ip_context_responses = []

    responses = remove_empty_elements(responses)
    for response in responses:
        tmp_response: dict = {}

        for key, value in response.items():
            if value != "":
                tmp_response[PRETTY_KEY.get(key, key)] = value

        ip = tmp_response["IP"]
        tmp_response["IP"] = f"[{ip}](https://viz.greynoise.io/ip/{ip})"

        ip_context_responses.append(tmp_response)

    return ip_context_responses


def get_ip_reputation_score(classification: str) -> tuple[int, str]:
    """Get DBot score and human readable of score.

    :type classification: ``str``
    :param classification: classification of ip provided from GreyNoise.

    :return: tuple of dbot score and it's readable form.
    :rtype: ``tuple``
    """
    if not classification or classification == "unknown":
        return Common.DBotScore.NONE, "Unknown"
    elif classification == "benign":
        return Common.DBotScore.GOOD, "Good"
    elif classification == "malicious":
        return Common.DBotScore.BAD, "Bad"
    else:
        return Common.DBotScore.NONE, "Unknown"


""" COMMAND FUNCTIONS """


@exception_handler
@logger
def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: Client object for interaction with GreyNoise.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    return client.authenticate()


@exception_handler
@logger
def ip_reputation_command(client: Client, args: dict, reliability: str) -> List[CommandResults]:
    """Get information about a given IP address. Returns classification (benign, malicious or unknown),
        IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags,
        and raw port scan and web request information.

    :type client: ``Client``
    :param client: Client object for interaction with GreyNoise.

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: A list of ``CommandResults`` object that is then passed to ``return_results``,
        that contains the IP information.
    :rtype: ``List[CommandResults]``

    :type reliability: ``String``
    :param reliability: string
    """
    ips = argToList(args.get("ip"), ",")
    command_results = []
    for ip in ips:

        response = client.ip(ip)

        if not isinstance(response, dict):
            raise DemistoException(
                EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response)
            )

        original_response = copy.deepcopy(response)
        tmp_response = get_ip_context_data([response])
        response = remove_empty_elements(response)

        response["address"] = response["ip"]
        del response["ip"]

        dbot_score_int, dbot_score_string = get_ip_reputation_score(
            response.get("classification")
        )

        human_readable = f"### IP: {ip} found with Reputation: {dbot_score_string}\n"
        human_readable += tableToMarkdown(
            name="GreyNoise Community IP Context",
            t=tmp_response,
            headers=IP_CONTEXT_HEADERS,
            removeNull=True,
        )

        if response["noise"]:
            malicious_description = (
                "This IP has been observed scanning the internet in the last 90 days."
            )
        else:
            malicious_description = ""

        dbot_score = Common.DBotScore(
            indicator=response.get("address"),
            indicator_type=DBotScoreType.IP,
            score=dbot_score_int,
            integration_name="GreyNoise Community",
            malicious_description=malicious_description,
            reliability=reliability
        )

        ip_standard_context = Common.IP(
            ip=response.get("address"),
            hostname=response.get("name"),
            dbot_score=dbot_score,
        )

        command_results.append(
            CommandResults(
                readable_output=human_readable,
                outputs_prefix="GreyNoise.IP",
                outputs_key_field="address",
                outputs=response,
                indicator=ip_standard_context,
                raw_response=original_response,
            )
        )

    return command_results


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # get pack version
    if is_demisto_version_ge("6.1.0"):
        response = demisto.internalHttpRequest("GET", "/contentpacks/metadata/installed")
        packs = json.loads(response["body"])
    else:
        packs = []

    pack_version = "1.4.0"
    if isinstance(packs, list):
        for pack in packs:
            if pack["name"] == "GreyNoise":
                pack_version = pack["currentVersion"]
    else:  # packs is a dict
        if packs.get("name") == "GreyNoise":
            pack_version = packs.get("currentVersion")

    api_key = demisto.params().get("api_key")
    proxy = demisto.params().get("proxy", False)
    reliability = demisto.params().get("integrationReliability", "B - Usually reliable")
    reliability = reliability if reliability else DBotScoreReliability.B
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Integration Reliability parameter.")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            api_key=api_key,
            proxy=handle_proxy("proxy", proxy).get("https", ""),
            use_cache=False,
            integration_name=f"xsoar-community-integration-v{pack_version}",
            offering="community",
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result: Any = test_module(client)
            return_results(result)

        elif demisto.command() == "ip":
            result = ip_reputation_command(client, demisto.args(), reliability)
            return_results(result)

    # Log exceptions and return errors
    except RequestFailure:
        raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), str(err))
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
