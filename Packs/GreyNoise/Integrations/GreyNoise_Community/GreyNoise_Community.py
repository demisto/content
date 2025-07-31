import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

""" Imports """

import copy
import traceback

import requests
import urllib3  # type: ignore
from greynoise.api import GreyNoise, APIConfig  # type: ignore
from greynoise import exceptions, util  # type: ignore

# Disable insecure warnings
urllib3.disable_warnings()
util.LOGGER.warning = util.LOGGER.debug

""" CONSTANTS """

PRETTY_KEY = PRETTY_KEY = {
    "ip": "IP",
    "first_seen": "First Seen",
    "last_seen": "Last Seen",
    "last_seen_timestamp": "Last Seen Timestamp",
    "seen": "Internet Scanner",
    "tags": "Tags",
    "actor": "Actor",
    "spoofable": "Spoofable",
    "classification": "Classification",
    "cve": "CVE",
    "metadata": "MetaData",
    "asn": "ASN",
    "city": "City",
    "country": "Country",
    "country_code": "Country Code",
    "destination_countries": "Destination Countries",
    "destination_country_codes": "Destination Country Codes",
    "organization": "Organization",
    "category": "Category",
    "sensor_count": "Sensor Count",
    "sensor_hits": "Sensor Hits",
    "source_country": "Source Country",
    "source_country_code": "Source Country Code",
    "tor": "Tor",
    "rdns": "rDNS",
    "os": "OS",
    "region": "Region",
    "vpn": "VPN",
    "vpn_service": "VPN Service",
    "raw_data": "Raw Data",
    "scan": "Scan",
    "port": "Port",
    "protocol": "Protocol",
    "web": "Web",
    "path": "Web Paths",
    "useragent": "User-Agents",
    "ja3": "JA3",
    "fingerprint": "Fingerprint",
    "hassh": "HASSH",
    "bot": "BOT",
    "ja4": "JA4",
    "cipher": "Cipher",
    "md5": "MD5",
    "trust_level": "Trust Level",
    "address": "Address",
    "found": "Found",
}
IP_CONTEXT_HEADERS = [
    "IP",
    "Internet Scanner",
    "Classification",
    "Actor",
    "CVE",
    "Tags",
    "Spoofable",
    "VPN",
    "BOT",
    "Tor",
    "Last Seen Timestamp",
]
RIOT_HEADERS = [
    "IP",
    "Business Service",
    "Category",
    "Name",
    "Trust Level",
    "Description",
    "Last Updated",
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

        except exceptions.RateLimitError:
            raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])

        except exceptions.RequestFailure as err:
            status_code = err.args[0]
            body = str(err.args[1])

            if status_code == 401:
                raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])
            elif status_code == 429:
                raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])
            elif 400 <= status_code < 500:
                raise DemistoException(EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), body))
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
        except exceptions.RateLimitError:
            raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])
        except exceptions.RequestFailure as err:
            status_code = err.args[0]
            body = str(err.args[1])
            if status_code == 401:
                raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])
            elif status_code == 429:
                raise DemistoException(EXCEPTION_MESSAGES["API_RATE_LIMIT"])
            elif 400 <= status_code < 500:
                raise DemistoException(EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), body))
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
        metadata_list: list = []
        tmp_response: dict = {}
        tags = get_ip_tag_names(response.get("tags", []))
        response["tags"] = tags
        for key, value in response.get("metadata", {}).items():
            if value != "":
                metadata_list.append(f"{PRETTY_KEY.get(key, key)}: {value}")
        tmp_response["MetaData"] = metadata_list

        for key, value in response.items():
            if value != "" and key not in ["metadata", "raw_data"]:
                tmp_response[PRETTY_KEY.get(key, key)] = value

        ip = tmp_response["IP"]
        tmp_response["IP"] = f"[{ip}](https://viz.greynoise.io/ip/{ip})"

        ip_context_responses.append(tmp_response)

    return ip_context_responses


def get_ip_reputation_score(classification: str) -> tuple[int, str]:
    """Get DBot score and human-readable of score.

    :type classification: ``str``
    :param classification: classification of ip provided from GreyNoise.

    :return: tuple of dbot score and it's readable form.
    :rtype: ``tuple``
    """
    if classification == "benign":
        return Common.DBotScore.GOOD, "Good"
    elif classification == "suspicious":
        return Common.DBotScore.SUSPICIOUS, "Suspicious"
    elif classification == "malicious":
        return Common.DBotScore.BAD, "Bad"
    else:
        return Common.DBotScore.NONE, "Unknown"


def get_ip_tag_names(tags: list) -> list:
    """Get tag names from tags list.

    :type tags: ``list``
    :param tags: list of tags.

    :return: list of tag names.
    :rtype: ``list``
    """
    tag_names = []
    for tag in tags:
        tag_name = tag.get("name") + " (" + tag.get("intention") + " - " + tag.get("category") + ")"
        tag_names.append(tag_name)

    return tag_names


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
        try:
            demisto.debug(f"Querying GreyNoise with ip: {ip}")
            api_response = client.ip(ip)
        except Exception as e:
            demisto.debug(f"Error in ip_reputation_command: {e}")
            raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(e))

        if "internet_scanner_intelligence" in api_response:
            response = copy.deepcopy(api_response["internet_scanner_intelligence"])
            response["seen"] = response.get("found", False)
            response["address"] = api_response["ip"]
            response["ip"] = api_response["ip"]
            riot_response = copy.deepcopy(api_response["business_service_intelligence"])
            riot_response["riot"] = riot_response.get("found", False)
            riot_response["address"] = api_response["ip"]
        else:
            response = {}
            riot_response = {}

        original_response = copy.deepcopy(api_response)
        tmp_response = get_ip_context_data([response])
        response = remove_empty_elements(response)

        riot_response = remove_empty_elements(riot_response)

        if riot_response["riot"]:
            if riot_response.get("trust_level") == "1":
                riot_response["classification"] = "benign"
                riot_response["trust_level"] = "1 - Reasonably Ignore"
            elif riot_response.get("trust_level") == "2":
                riot_response["classification"] = "unknown"
                riot_response["trust_level"] = "2 - Commonly Seen"
            if riot_response.get("logo_url", "") != "":
                del riot_response["logo_url"]
            if original_response.get("business_service_intelligence", {}).get("logo_url", "") != "":
                del original_response["business_service_intelligence"]["logo_url"]

        if response["seen"] and response.get("classification") == "malicious":
            malicious_description = "This IP has been observed scanning the internet in a malicious manner."
        else:
            malicious_description = ""

        # Prepare the output response - this should be the full API response with ip renamed to address
        # without modifying the nested objects
        output_response = copy.deepcopy(original_response)
        if "ip" in output_response:
            output_response["address"] = output_response["ip"]
            del output_response["ip"]

        if response["seen"] and not riot_response["riot"]:
            dbot_score_int, dbot_score_string = get_ip_reputation_score(response.get("classification"))

            human_readable = f"### IP: {ip} found with Reputation: {dbot_score_string}\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Internet Scanner Intelligence Lookup", t=tmp_response, headers=IP_CONTEXT_HEADERS, removeNull=True
            )

            riot_tmp_response = {"IP": riot_response.get("address"), "Business Service": riot_response.get("riot")}

            human_readable += f"### IP: {ip} Not Associated with a Business Service\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Business Service Intelligence Lookup",
                t=riot_tmp_response,
                headers=["IP", "Business Service"],
                removeNull=False,
            )

            dbot_score = Common.DBotScore(
                indicator=response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability,
            )

            city = response.get("metadata", {}).get("source_city", "")
            region = response.get("metadata", {}).get("region", "")
            country_code = response.get("metadata", {}).get("source_country_code", "")
            geo_description = (
                f"City: {city}, Region: {region}, Country Code: {country_code}" if (city or region or country_code) else ""
            )
            ip_standard_context = Common.IP(
                ip=response.get("address"),
                asn=response.get("metadata", {}).get("asn"),
                hostname=response.get("actor"),
                geo_country=response.get("metadata", {}).get("source_country"),
                geo_description=geo_description,
                dbot_score=dbot_score,
            )

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.IP",
                    outputs_key_field="address",
                    outputs=output_response,
                    indicator=ip_standard_context,
                    raw_response=original_response,
                )
            )

        if riot_response["riot"] and not response["seen"]:
            riot_tmp_response = {
                "IP": f"[{riot_response.get('address')}](https://viz.greynoise.io/ip/{riot_response.get('address')})",
                "Business Service": riot_response.get("riot"),
                "Name": riot_response.get("name"),
                "Category": riot_response.get("category"),
                "Trust Level": riot_response.get("trust_level"),
                "Description": riot_response.get("description"),
                "Last Updated": riot_response.get("last_updated"),
            }

            dbot_score_int, dbot_score_string = get_ip_reputation_score(riot_response.get("classification"))

            human_readable = f"### IP: {ip} found with Reputation: {dbot_score_string}\n"
            human_readable += f"#### Belongs to Common Business Service: {riot_response.get('name', 'Unknown')}\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Business Service Intelligence Lookup", t=riot_tmp_response, headers=RIOT_HEADERS, removeNull=False
            )
            tmp_response = [{"IP": response.get("address"), "Internet Scanner": response.get("seen")}]

            human_readable += f"### IP: {ip} No Mass-Internet Scanning Observed\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Internet Scanner Intelligence Lookup",
                t=tmp_response,
                headers=["IP", "Internet Scanner"],
                removeNull=False,
            )

            dbot_score = Common.DBotScore(
                indicator=response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability,
            )

            ip_standard_context = Common.IP(ip=response.get("address"), dbot_score=dbot_score)

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.IP",
                    outputs_key_field="address",
                    outputs=output_response,
                    indicator=ip_standard_context,
                    raw_response=original_response,
                )
            )

        if response["seen"] and riot_response["riot"]:
            combo_response = response.copy()
            combo_response.update(riot_response)
            dbot_score_int, dbot_score_string = get_ip_reputation_score(response.get("classification"))

            human_readable = f"### IP: {ip} found with Reputation: {dbot_score_string}\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Internet Scanner Intelligence Lookup", t=tmp_response, headers=IP_CONTEXT_HEADERS, removeNull=True
            )

            dbot_score = Common.DBotScore(
                indicator=response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability,
            )

            city = response.get("metadata", {}).get("source_city", "")
            region = response.get("metadata", {}).get("region", "")
            country_code = response.get("metadata", {}).get("source_country_code", "")
            geo_description = (
                f"City: {city}, Region: {region}, Country Code: {country_code}" if (city or region or country_code) else ""
            )
            ip_standard_context = Common.IP(
                ip=response.get("address"),
                asn=response.get("metadata", {}).get("asn"),
                hostname=response.get("actor"),
                geo_country=response.get("metadata", {}).get("source_country"),
                geo_description=geo_description,
                dbot_score=dbot_score,
            )

            riot_tmp_response = {
                "IP": f"[{riot_response.get('address')}](https://viz.greynoise.io/ip/{riot_response.get('address')})",
                "Business Service": riot_response.get("riot"),
                "Name": riot_response.get("name"),
                "Category": riot_response.get("category"),
                "Trust Level": riot_response.get("trust_level"),
                "Description": riot_response.get("description"),
                "Last Updated": riot_response.get("last_updated"),
            }

            human_readable += f"### IP: {ip} found with Reputation: {dbot_score_string}\n"
            human_readable += f"#### Belongs to Common Business Service: {riot_response.get('name', 'Unknown')}\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Business Service Intelligence Lookup", t=riot_tmp_response, headers=RIOT_HEADERS, removeNull=False
            )

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.IP",
                    outputs_key_field="address",
                    outputs=output_response,
                    indicator=ip_standard_context,
                    raw_response=original_response,
                )
            )

        if not response["seen"] and not riot_response["riot"]:
            combo_response = response.copy()
            combo_response.update(riot_response)
            combo_tmp_response = {
                "IP": combo_response.get("address"),
                "Business Service": combo_response.get("riot"),
                "Internet Scanner": combo_response.get("seen"),
            }

            dbot_score_int, dbot_score_string = get_ip_reputation_score(combo_response.get("classification"))

            dbot_score = Common.DBotScore(
                indicator=combo_response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability,
            )

            ip_standard_context = Common.IP(ip=response.get("address"), dbot_score=dbot_score)

            human_readable = f"### IP: {ip} No Mass-Internet Scanning Observed\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Internet Scanner Intelligence Lookup",
                t=combo_tmp_response,
                headers=["IP", "Internet Scanner"],
                removeNull=True,
            )

            human_readable += f"### IP: {ip} Not Associated with a Business Service\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Business Service Intelligence Lookup",
                t=combo_tmp_response,
                headers=["IP", "Business Service"],
                removeNull=True,
            )

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.IP",
                    outputs_key_field="address",
                    indicator=ip_standard_context,
                    outputs=output_response,
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

    pack_version = "2.0.0"
    if isinstance(packs, list):
        for pack in packs:
            if pack["name"] == "GreyNoise":
                pack_version = pack["currentVersion"]
    else:  # packs is a dict
        if packs.get("name") == "GreyNoise":
            pack_version = packs.get("currentVersion")

    api_key = demisto.params().get("credentials", {}).get("password") or demisto.params().get("api_key")
    if not api_key:
        return_error("Please provide a valid API token")
    proxy = demisto.params().get("proxy", False)
    reliability = demisto.params().get("integrationReliability", "B - Usually reliable")
    reliability = reliability if reliability else DBotScoreReliability.B
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Integration Reliability parameter.")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        api_config = APIConfig(
            api_key=api_key,
            proxy=handle_proxy("proxy", proxy).get("https", ""),
            use_cache=False,
            integration_name=f"xsoar-community-integration-v{pack_version}",
        )
        client = Client(api_config)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result: Any = test_module(client)
            return_results(result)

        elif demisto.command() == "ip":
            result = ip_reputation_command(client, demisto.args(), reliability)
            return_results(result)

    # Log exceptions and return errors
    except exceptions.RequestFailure:
        raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), str(err)))


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
