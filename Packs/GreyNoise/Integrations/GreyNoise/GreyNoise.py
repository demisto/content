from CommonServerPython import *
""" Imports """
import urllib3  # type: ignore
import traceback
import requests
import re
import copy
from typing import Any
from greynoise import GreyNoise, exceptions, util  # type: ignore

# Disable insecure warnings
urllib3.disable_warnings()
util.LOGGER.warning = util.LOGGER.debug

""" CONSTANTS """

TIMEOUT = 30
PRETTY_KEY = {
    "ip": "IP",
    "first_seen": "First Seen",
    "last_seen": "Last Seen",
    "seen": "Seen",
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
    "paths": "Paths",
    "useragents": "User-Agents",
    "ja3": "ja3",
    "fingerprint": "fingerprint",
    "hassh": "HASSH",
    "bot": "BOT",
}
IP_CONTEXT_HEADERS = [
    "IP",
    "Classification",
    "Actor",
    "CVE",
    "Tags",
    "Spoofable",
    "VPN",
    "BOT",
    "Tor",
    "First Seen",
    "Last Seen",
]
SIMILAR_HEADERS = [
    "IP",
    "Score",
    "Classification",
    "Actor",
    "Organization",
    "Source Country",
    "Last Seen",
    "Similarity Features"
]
TIMELINE_HEADERS = [
    "Date",
    "Classification",
    "Tags",
    "rDNS",
    "Organization",
    "ASN",
    "Ports",
    "Web Paths",
    "User Agents",
]
RIOT_HEADERS = ["IP", "Category", "Name", "Trust Level", "Description", "Last Updated"]
API_SERVER = util.DEFAULT_CONFIG.get("api_server")
IP_QUICK_CHECK_HEADERS = ["IP", "Noise", "RIOT", "Code", "Code Description"]
STATS_KEY = {
    "classifications": "Classifications",
    "spoofable": "Spoofable",
    "organizations": "Organizations",
    "actors": "Actors",
    "source_countries": "Source Countries",
    "destination_countries": "Destination Countries",
    "tags": "Tags",
    "operating_systems": "Operating Systems",
    "categories": "Categories",
    "asns": "ASNs",
}
STATS_H_KEY = {
    "classification": "Classification",
    "spoofable": "Spoofable",
    "organization": "Organization",
    "actor": "Actor",
    "country": "Country",
    "tag": "Tag",
    "operating_system": "Operating System",
    "category": "Category",
    "asn": "ASN",
    "count": "Count",
}
QUERY_OUTPUT_PREFIX: dict[str, str] = {
    "IP": "GreyNoise.IP(val.address && val.address == obj.address)",
    "QUERY": "GreyNoise.Query(val.query && val.query == obj.query)",
}
EXCEPTION_MESSAGES = {
    "API_RATE_LIMIT": "API Rate limit hit. Try after sometime.",
    "UNAUTHENTICATED": "Unauthenticated. Check the configured API Key.",
    "COMMAND_FAIL": "Failed to execute {} command.\n Error: {}",
    "SERVER_ERROR": "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    "CONNECTION_TIMEOUT": "Connection timed out. Check your network connectivity.",
    "PROXY": "Proxy Error - cannot connect to proxy. Either try clearing the 'Use system proxy' check-box or check "
             "the host, authentication details and connection details for the proxy.",
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
        current_date = datetime.now()
        try:
            response = self.test_connection()
            expiration_date = datetime.strptime(response["expiration"], "%Y-%m-%d")
            if current_date < expiration_date and response["offering"] != "community":
                return "ok"
            else:
                raise DemistoException(
                    f"Invalid API Offering ({response['offering']})or Expiration Date ({expiration_date})"
                )

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
            status_code, body = parse_code_and_body(str(err))
            if status_code == 401 and "forbidden" in body:
                raise DemistoException(EXCEPTION_MESSAGES["UNAUTHENTICATED"])
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


def parse_code_and_body(message: str) -> tuple[int, str]:
    """Parse status code and body

    Parses code and body from the Exception raised by GreyNoise SDK.

    :type message: ``str``
    :param message: Exception message.

    :return: response code and response body.
    :rtype: ``tuple``
    """
    re_response = re.search(r"\(([0-9]+), (.*)\)", message)  # NOSONAR
    if re_response:
        code, body = re_response.groups()
        body = body.strip("'")
    else:
        return 0, message
    return int(code), body


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
        for key, value in response.get("metadata", {}).items():
            if value != "":
                metadata_list.append(f"{PRETTY_KEY.get(key, key)}: {value}")
            # bring TOR key to top level for table view
            if key == "tor":
                tmp_response[PRETTY_KEY.get(key, key)] = value
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
    if classification == "unknown":
        return Common.DBotScore.SUSPICIOUS, "Suspicious"
    elif classification == "benign":
        return Common.DBotScore.GOOD, "Good"
    elif classification == "malicious":
        return Common.DBotScore.BAD, "Bad"
    else:
        return Common.DBotScore.NONE, "Unknown"


def generate_advanced_query(args: dict) -> str:
    """Generate advance query for GreyNoise from args.

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: advanced query.
    :rtype: ``str``
    """

    advanced_query = args.get("advanced_query", "")
    used_args: dict = {
        "actor": args.get("actor"),
        "classification": args.get("classification"),
        "spoofable": args.get("spoofable"),
        "last_seen": args.get("last_seen"),
        "organization": args.get("organization"),
        "cve": args.get("cve"),
    }

    if advanced_query:
        advanced_query = advanced_query.replace(": ", ":")
        advanced_query = advanced_query.replace(" :", ":")

    arg_list = list(used_args.keys())
    arg_list.sort()

    for each in arg_list:
        if used_args[each] and f"{each}:" not in advanced_query:
            advanced_query += f" {each}:{used_args.get(each)}"

    advanced_query = advanced_query.strip(" ")

    if not advanced_query:
        advanced_query = "spoofable:false"

    return advanced_query


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
def ip_quick_check_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Check whether a given IP address is Internet Background Noise,
    or has been observed scanning or attacking devices across the internet.
        :type client: ``Client``
        :param client: Client object for interaction with GreyNoise.

        :type args: ``Dict``
        :param args: All command arguments, usually passed from ``demisto.args()``.

        :return: A ``CommandResults`` object that is then passed to ``return_results``,
            that contains the IP information.
        :rtype: ``CommandResults``
    """

    ip_address = argToList(args.get("ip"), ",")

    response = client.quick(ip_address)
    if not isinstance(response, list):
        raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response))

    original_response = copy.deepcopy(response)
    hr_list = []
    for record in response:
        hr_record = {
            "IP": record.get("ip") or record.get("address"),
            "Noise": record.get("noise"),
            "RIOT": record.get("riot"),
            "Code": record.get("code"),
            "Code Description": record.get("code_message"),
        }
        ip = hr_record["IP"]
        hr_record["IP"] = f"[{ip}](https://viz.greynoise.io/ip/{ip})"
        hr_list.append(hr_record)

    hr = tableToMarkdown(name="IP Quick Check Details", t=hr_list, headers=IP_QUICK_CHECK_HEADERS, removeNull=True)
    for resp in response:
        if "ip" in resp:
            resp["address"] = resp["ip"]
            del resp["ip"]
        resp["code_value"] = resp["code_message"]
        del resp["code_message"]

    return CommandResults(
        outputs_prefix="GreyNoise.IP",
        outputs_key_field="address",
        outputs=remove_empty_elements(response),
        readable_output=hr,
        raw_response=original_response,
    )


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
        riot_response = client.riot(ip)

        if not isinstance(response, dict) or not isinstance(riot_response, dict):
            raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response))

        original_response = copy.deepcopy(response)
        tmp_response = get_ip_context_data([response])
        response = remove_empty_elements(response)

        response["address"] = response["ip"]
        del response["ip"]

        riot_original_response = copy.deepcopy(riot_response)
        riot_response = remove_empty_elements(riot_response)

        riot_response["address"] = riot_response["ip"]
        del riot_response["ip"]

        if riot_response["riot"]:
            if riot_response["trust_level"] == "1":
                riot_response["classification"] = "benign"
                riot_response["trust_level"] = "1 - Reasonably Ignore"
            elif riot_response["trust_level"] == "2":
                riot_response["classification"] = "unknown"
                riot_response["trust_level"] = "2 - Commonly Seen"
            if riot_response.get("logo_url", "") != "":
                del riot_response["logo_url"]

        try:
            response_quick: Any = ip_quick_check_command(client, {"ip": ip})
            malicious_description = response_quick.outputs[0].get("code_value")
        except Exception:
            malicious_description = ""

        if response["seen"] and not riot_response["riot"]:
            dbot_score_int, dbot_score_string = get_ip_reputation_score(response.get("classification"))

            human_readable = f"### IP: {ip} found with Noise Reputation: {dbot_score_string}\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Context IP Lookup", t=tmp_response, headers=IP_CONTEXT_HEADERS, removeNull=True
            )

            riot_tmp_response = {"IP": riot_response.get("address"), "RIOT": riot_response.get("riot")}

            human_readable += f"### IP: {ip} Not Associated with Common Business Service\n"
            human_readable += tableToMarkdown(
                name="GreyNoise RIOT IP Lookup", t=riot_tmp_response, headers=["IP", "RIOT"], removeNull=False
            )

            response["riot"] = False

            dbot_score = Common.DBotScore(
                indicator=response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability
            )

            city = response.get("metadata", {}).get("city", "")
            region = response.get("metadata", {}).get("region", "")
            country_code = response.get("metadata", {}).get("country_code", "")
            geo_description = (
                f"City: {city}, Region: {region}, Country Code: {country_code}"
                if (city or region or country_code)
                else ""
            )
            ip_standard_context = Common.IP(
                ip=response.get("address"),
                asn=response.get("metadata", {}).get("asn"),
                hostname=response.get("actor"),
                geo_country=response.get("metadata", {}).get("country"),
                geo_description=geo_description,
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

        if riot_response["riot"] and not response["seen"]:
            riot_tmp_response = {
                "IP": f"[{riot_response.get('address')}](https://viz.greynoise.io/ip/{riot_response.get('address')})",
                "Name": riot_response.get("name"),
                "Category": riot_response.get("category"),
                "Trust Level": riot_response.get("trust_level"),
                "Description": riot_response.get("description"),
                "Last Updated": riot_response.get("last_updated"),
            }

            dbot_score_int, dbot_score_string = get_ip_reputation_score(riot_response.get("classification"))

            human_readable = f"### IP: {ip} found with RIOT Reputation: {dbot_score_string}\n"
            human_readable += f'Belongs to Common Business Service: {riot_response["name"]}\n'
            human_readable += tableToMarkdown(
                name="GreyNoise RIOT IP Lookup", t=riot_tmp_response, headers=RIOT_HEADERS, removeNull=False
            )
            tmp_response = [{"IP": response.get("address"), "Seen": response.get("seen")}]

            human_readable += f"### IP: {ip} No Mass-Internet Scanning Noise Found\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Context IP Lookup", t=tmp_response, headers=["IP", "Seen"], removeNull=False
            )

            riot_response["seen"] = False

            dbot_score = Common.DBotScore(
                indicator=response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability
            )

            ip_standard_context = Common.IP(ip=response.get("address"), dbot_score=dbot_score)

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.Riot",
                    outputs_key_field="address",
                    outputs=riot_response,
                    indicator=ip_standard_context,
                    raw_response=riot_original_response,
                )
            )

        if response["seen"] and riot_response["riot"]:
            combo_response = response.copy()
            combo_response.update(riot_response)
            dbot_score_int, dbot_score_string = get_ip_reputation_score(response.get("classification"))

            human_readable = f"### IP: {ip} found with Noise Reputation: {dbot_score_string}\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Context IP Lookup", t=tmp_response, headers=IP_CONTEXT_HEADERS, removeNull=True
            )

            dbot_score = Common.DBotScore(
                indicator=response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability
            )

            city = response.get("metadata", {}).get("city", "")
            region = response.get("metadata", {}).get("region", "")
            country_code = response.get("metadata", {}).get("country_code", "")
            geo_description = (
                f"City: {city}, Region: {region}, Country Code: {country_code}"
                if (city or region or country_code)
                else ""
            )
            ip_standard_context = Common.IP(
                ip=response.get("address"),
                asn=response.get("metadata", {}).get("asn"),
                hostname=response.get("actor"),
                geo_country=response.get("metadata", {}).get("country"),
                geo_description=geo_description,
                dbot_score=dbot_score,
            )

            riot_tmp_response = {
                "IP": f"[{riot_response.get('address')}](https://viz.greynoise.io/ip/{riot_response.get('address')})",
                "Name": riot_response.get("name"),
                "Category": riot_response.get("category"),
                "Trust Level": riot_response.get("trust_level"),
                "Description": riot_response.get("description"),
                "Last Updated": riot_response.get("last_updated"),
            }

            human_readable += f"### IP: {ip} found with RIOT Reputation: {dbot_score_string}\n"
            human_readable += f'Belongs to Common Business Service: {riot_response["name"]}\n'
            human_readable += tableToMarkdown(
                name="GreyNoise RIOT IP Lookup", t=riot_tmp_response, headers=RIOT_HEADERS, removeNull=False
            )

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.IP",
                    outputs_key_field="address",
                    outputs=combo_response,
                    indicator=ip_standard_context,
                    raw_response=combo_response,
                )
            )

        if not response["seen"] and not riot_response["riot"]:
            combo_response = response.copy()
            combo_response.update(riot_response)
            combo_tmp_response = {
                "IP": combo_response.get("address"),
                "RIOT": combo_response.get("riot"),
                "Seen": combo_response.get("seen"),
            }

            dbot_score_int, dbot_score_string = get_ip_reputation_score(combo_response.get("classification"))

            dbot_score = Common.DBotScore(
                indicator=combo_response.get("address"),
                indicator_type=DBotScoreType.IP,
                score=dbot_score_int,
                integration_name="GreyNoise",
                malicious_description=malicious_description,
                reliability=reliability
            )

            ip_standard_context = Common.IP(ip=response.get("address"), dbot_score=dbot_score)

            human_readable = f"### IP: {ip} No Mass-Internet Scanning Noise Found\n"
            human_readable += tableToMarkdown(
                name="GreyNoise Context IP Lookup", t=combo_tmp_response, headers=["IP", "Seen"], removeNull=True
            )

            human_readable += f"### IP: {ip} Not Associated with Common Business Service\n"
            human_readable += tableToMarkdown(
                name="GreyNoise RIOT IP Lookup", t=combo_tmp_response, headers=["IP", "RIOT"], removeNull=True
            )

            command_results.append(
                CommandResults(
                    readable_output=human_readable,
                    outputs_prefix="GreyNoise.IP",
                    outputs_key_field="address",
                    indicator=ip_standard_context,
                    outputs=combo_response,
                    raw_response=combo_response,
                )
            )

    return command_results


@exception_handler
@logger
def query_command(client: Client, args: dict) -> CommandResults:
    """Get the information of IP based on the providence filters.

    :type client: ``Client``
    :param client: Client object for interaction with GreyNoise.

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: ``CommandResults`` object, that contains the IP information.
    :rtype: ``CommandResults``
    """
    advanced_query = generate_advanced_query(args)

    query_response = client.query(query=advanced_query, size=args.get("size", "10"), scroll=args.get("next_token"))
    if not isinstance(query_response, dict):
        raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(query_response))

    if query_response.get("message") not in ["ok", "no results"]:
        raise DemistoException(EXCEPTION_MESSAGES["QUERY_STATS_RESPONSE"].format(query_response.get("message")))

    original_response = copy.deepcopy(query_response)

    if query_response["message"] == "ok":

        tmp_response = []
        for each in query_response.get("data", []):
            tmp_response += get_ip_context_data([each])
            each["address"] = each["ip"]
            del each["ip"]

        human_readable = f'### Total findings: {query_response.get("count")}\n'

        human_readable += tableToMarkdown(
            name="IP Context", t=tmp_response, headers=IP_CONTEXT_HEADERS, removeNull=True
        )

        if not query_response.get("complete"):
            human_readable += f'\n### Next Page Token: \n{query_response.get("scroll")}'

        query = query_response.get("query", "").replace(" ", "+")
        query_link = f"https://viz.greynoise.io/query/?gnql={query}"
        query_link = query_link.replace("*", "&ast;")
        query_link = query_link.replace('"', "&quot;")
        human_readable += f"\n*To view the detailed query result please click [here]({query_link}).*"

        outputs = {
            QUERY_OUTPUT_PREFIX["IP"]: query_response.get("data", []),
            QUERY_OUTPUT_PREFIX["QUERY"]: {
                "complete": query_response.get("complete"),
                "count": query_response.get("count"),
                "message": query_response.get("message"),
                "query": query_response.get("query"),
                "scroll": query_response.get("scroll"),
            },
        }
    elif query_response["message"] == "no results":
        outputs = {}
        human_readable = "### GreyNoise Query returned No Results."
        query = query_response.get("query", "").replace(" ", "+")
        query_link = f"https://viz.greynoise.io/query/?gnql={query}"
        query_link = query_link.replace("*", "&ast;")
        query_link = query_link.replace('"', "&quot;")
        human_readable += f"\n*To view the detailed query result please click [here]({query_link}).*"
    else:
        outputs = {}
        human_readable = ""
        demisto.debug(f'{query_response["message"]=} do not match any condition. {outputs=} , {human_readable=}')

    return CommandResults(
        readable_output=human_readable, outputs=remove_empty_elements(outputs), raw_response=original_response
    )


@exception_handler
@logger
def stats_command(client: Client, args: dict) -> Any:
    """Get aggregate statistics for the top organizations, actors, tags, ASNs, countries,
    classifications, and operating systems of all the results of a given GNQL query.

       :type client: ``Client``
       :param client: Client object for interaction with GreyNoise.

       :type args: ``dict``
       :param args: All command arguments, usually passed from ``demisto.args()``.

       :return: A ``CommandResults`` object that is then passed to ``return_results``,
           that contains the IP information.
       :rtype: ``CommandResults``
    """
    advance_query = generate_advanced_query(args)
    response = client.stats(query=advance_query, count=args.get("size", "10"))
    if not isinstance(response, dict):
        raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response))

    if response["count"] > 0:

        human_readable = f'### Stats\n### Query: {advance_query} Count: {response.get("count", "0")}\n'

        for key, value in response.get("stats", {}).items():
            hr_list: list = []
            if value is None:
                continue
            if key == "countries":
                continue
            for rec in value:
                hr_rec: dict = {}
                header = []
                for k, v in rec.items():
                    hr_rec.update({f"{STATS_H_KEY.get(k)}": f"{v}"})
                    header.append(STATS_H_KEY.get(k))
                hr_list.append(hr_rec)
            human_readable += tableToMarkdown(
                name=f"{STATS_KEY.get(key, key)}", t=hr_list, headers=header, removeNull=True
            )
    elif response.get("count") == 0:
        human_readable = "### GreyNoise Stats Query returned No Results."

    return CommandResults(
        outputs_prefix="GreyNoise.Stats",
        outputs_key_field="query",
        outputs=remove_empty_elements(response),
        readable_output=human_readable,
    )


@exception_handler
@logger
def similarity_command(client: Client, args: dict) -> Any:
    """Get similarity information for a specified IP.

       :type client: ``Client``
       :param client: Client object for interaction with GreyNoise.

       :type args: ``dict``
       :param args: All command arguments, usually passed from ``demisto.args()``.

       :return: A ``CommandResults`` object that is then passed to ``return_results``,
           that contains the IP information.
       :rtype: ``CommandResults``
    """
    ip = args.get("ip", "")
    min_score = args.get("minimum_score", 90)
    limit = args.get("maximum_results", 50)
    if isinstance(min_score, str):
        min_score = int(min_score)
    if isinstance(limit, str):
        limit = int(limit)
    response = client.similar(ip, min_score=min_score, limit=limit)
    original_response = copy.deepcopy(response)
    response = remove_empty_elements(response)
    if not isinstance(response, dict):
        raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response))

    if response.get("similar_ips"):
        tmp_response = []
        for sim_ip in response.get("similar_ips", []):
            modified_sim_ip = copy.deepcopy(sim_ip)
            modified_sim_ip["IP"] = sim_ip.get("ip")
            modified_sim_ip["Score"] = sim_ip.get("score", "0") * 100
            modified_sim_ip["Classification"] = sim_ip.get("classification")
            modified_sim_ip["Actor"] = sim_ip.get("actor")
            modified_sim_ip["Organization"] = sim_ip.get("organization")
            modified_sim_ip["Source Country"] = sim_ip.get("source_country")
            modified_sim_ip["Last Seen"] = sim_ip.get("last_seen")
            modified_sim_ip["Similarity Features"] = sim_ip.get("features")
            tmp_response.append(modified_sim_ip)

        human_readable = f"### IP: {ip} - Similar Internet Scanners found in GreyNoise\n"
        human_readable += f'#### Total Similar IPs with Score above {min_score}%: {response.get("total")}\n'
        if response.get('total', 0) > limit:
            human_readable += f'##### Displaying {limit} results below.  To see all results, visit the GreyNoise ' \
                              f'Visualizer.\n '

        human_readable += tableToMarkdown(
            name="GreyNoise Similar IPs", t=tmp_response, headers=SIMILAR_HEADERS, removeNull=True
        )

        similarity_link = f"https://viz.greynoise.io/ip-similarity/{ip}"
        human_readable += f"\n*To view the detailed similarity result please click [here]({similarity_link}).*"

    elif response["message"] == "ip not found":
        human_readable = "### GreyNoise Similarity Lookup returned No Results."
        viz_link = f"https://viz.greynoise.io/ip/{ip}"
        human_readable += f"\n*To view this IP on the GreyNoise Visualizer please click [here]({viz_link}).*"

    return CommandResults(
        outputs_prefix="GreyNoise.Similar",
        outputs_key_field="ip",
        readable_output=human_readable, outputs=remove_empty_elements(response), raw_response=original_response
    )


@exception_handler
@logger
def timeline_command(client: Client, args: dict) -> Any:
    """Get timeline information for a specified IP.

       :type client: ``Client``
       :param client: Client object for interaction with GreyNoise.

       :type args: ``dict``
       :param args: All command arguments, usually passed from ``demisto.args()``.

       :return: A ``CommandResults`` object that is then passed to ``return_results``,
           that contains the IP information.
       :rtype: ``CommandResults``
    """
    ip = args.get("ip", "")
    days = args.get("days", 30)
    limit = args.get("maximum_results", 50)
    if isinstance(days, str):
        days = int(days)
    if isinstance(limit, str):
        limit = int(limit)
    response = client.timelinedaily(ip, days=days, limit=limit)
    original_response = copy.deepcopy(response)
    response = remove_empty_elements(response)
    if not isinstance(response, dict):
        raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response))

    if response.get("activity"):
        tmp_response = []
        for activity in response.get("activity", []):
            modified_activity = copy.deepcopy(activity)
            modified_activity["Date"] = activity.get("timestamp").split("T")[0]
            modified_activity["Classification"] = activity.get("classification")
            tag_names = [tag["name"] for tag in activity.get("tags", [])]
            modified_activity["Tags"] = tag_names
            modified_activity["rDNS"] = activity.get("rdns")
            modified_activity["Organization"] = activity.get("organization")
            modified_activity["ASN"] = activity.get("asn")
            ports = [str(item["port"]) + "/" + str(item["transport_protocol"]) for item in activity.get("protocols", [])]
            modified_activity["Ports"] = ports
            modified_activity["Web Paths"] = activity.get("http_paths")
            modified_activity["User Agents"] = activity.get("http_user_agents")
            tmp_response.append(modified_activity)

        human_readable = f"### IP: {ip} - GreyNoise IP Timeline\n"

        human_readable += tableToMarkdown(
            name="Internet Scanner Timeline Details - Daily Activity Summary", t=tmp_response, headers=TIMELINE_HEADERS,
            removeNull=True
        )

        timeline_link = f"https://viz.greynoise.io/ip/{ip}?view=timeline"
        human_readable += f"\n*To view the detailed timeline result please click [here]({timeline_link}).*"

    else:
        human_readable = "### GreyNoise IP Timeline Returned No Results."
        viz_link = f"https://viz.greynoise.io/ip/{ip}"
        human_readable += f"\n*To view this IP on the GreyNoise Visualizer please click [here]({viz_link}).*"

    return CommandResults(
        outputs_prefix="GreyNoise.Timeline",
        outputs_key_field="ip",
        readable_output=human_readable, outputs=remove_empty_elements(response), raw_response=original_response
    )


@exception_handler
@logger
def riot_command(client: Client, args: dict, reliability: str) -> CommandResults:
    """
    Returns information about IP whether it is harmful or not. RIOT (Rule It Out) means to inform the analyst about
    the harmfulness of the IP. For the harmless IP, the value of Riot is "True" which in turn returns DNS and other
    information about the IP. For the harmful IP, the value of Riot is "False".

    :type client: ``Client``
    :param client: client object

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.
    :return: A ``CommandResults`` object that is then passed to ``return_results``,
           that contains the IP information.
    :rtype: ``CommandResults``

    :type reliability: ``String``
    :param reliability: string
    """
    ip = args.get("ip", "")
    response = client.riot(ip)
    original_response = copy.deepcopy(response)
    response = remove_empty_elements(response)
    name = ""
    if response.get("riot") is False or response.get("riot") == "false":
        name = "GreyNoise RIOT IP Lookup"
        hr = {
            "IP": response.get("ip"),
            "RIOT": response.get("riot"),
        }
        human_readable = f"### IP: {ip} Not Associated with Common Business Service\n"
        human_readable += tableToMarkdown(
            name=name, t=hr, headers=["IP", "RIOT"],
            removeNull=False
        )
        dbot_score_int, dbot_score_string = get_ip_reputation_score(
            response.get("classification"))
    elif response.get("riot") is True or response.get("riot") == "true":
        if response.get("logo_url", "") != "":
            del response["logo_url"]
        if response.get("trust_level") == "1":
            response["trust_level"] = "1 - Reasonably Ignore"
            response["classification"] = "benign"
        elif response.get("trust_level") == "2":
            response["trust_level"] = "2 - Commonly Seen"
            response["classification"] = "unknown"
        dbot_score_int, dbot_score_string = get_ip_reputation_score(
            response.get("classification"))
        name = "GreyNoise RIOT IP Lookup"
        hr = {
            "IP": f"[{response.get('ip')}](https://viz.greynoise.io/ip/{response.get('ip')})",
            "Name": response.get("name"),
            "Category": response.get("category"),
            "Trust Level": response.get("trust_level"),
            "Description": response.get("description"),
            "Last Updated": response.get("last_updated"),
        }
        headers = RIOT_HEADERS

        human_readable = f"### IP: {ip} found with RIOT Reputation: {dbot_score_string}\n"
        human_readable += f'Belongs to Common Business Service: {response["name"]}\n'
        human_readable += tableToMarkdown(
            name=name, t=hr, headers=headers,
            removeNull=False
        )
    else:
        dbot_score_int = 0
        demisto.debug(f'{response.get("riot")=} -> {dbot_score_int=}')

    try:
        response_quick: Any = ip_quick_check_command(client, {"ip": ip})
        malicious_description = response_quick.outputs[0].get("code_value")
    except Exception:
        malicious_description = ""

    dbot_score = Common.DBotScore(
        indicator=response.get("address"),
        indicator_type=DBotScoreType.IP,
        score=dbot_score_int,
        integration_name="GreyNoise",
        malicious_description=malicious_description,
        reliability=reliability
    )

    ip_standard_context = Common.IP(ip=response.get("address"), dbot_score=dbot_score)

    return CommandResults(
        outputs_prefix="GreyNoise.Riot",
        outputs_key_field="address",
        outputs=response,
        readable_output=human_readable,
        indicator=ip_standard_context,
        raw_response=original_response,
    )


@exception_handler
@logger
def context_command(client: Client, args: dict, reliability: str) -> CommandResults:
    """
    Returns information about IP whether it is harmful or not. RIOT (Rule It Out) means to inform the analyst about
    the harmfulness of the IP. For the harmless IP, the value of Riot is "True" which in turn returns DNS and other
    information about the IP. For the harmful IP, the value of Riot is "False".

    :type client: ``Client``
    :param client: client object

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.
    :return: A ``CommandResults`` object that is then passed to ``return_results``,
           that contains the IP information.
    :rtype: ``CommandResults``

    :type reliability: ``String``
    :param reliability: string
    """

    ip = args.get("ip", "")
    response = client.ip(ip)

    if not isinstance(response, dict):
        raise DemistoException(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response))

    original_response = copy.deepcopy(response)
    tmp_response = get_ip_context_data([response])
    response = remove_empty_elements(response)

    response["address"] = response["ip"]
    del response["ip"]

    dbot_score_int, dbot_score_string = get_ip_reputation_score(response.get("classification"))

    if response["seen"]:
        human_readable = f"### IP: {ip} found with Noise Reputation: {dbot_score_string}\n"
        headers = IP_CONTEXT_HEADERS
    else:
        human_readable = f"### IP: {ip} No Mass-Internet Scanning Noise Found\n"
        tmp_response = [{"IP": response.get("address"), "Seen": response.get("seen")}]
        headers = ["IP", "Seen"]
    human_readable += tableToMarkdown(
        name="GreyNoise Context IP Lookup", t=tmp_response, headers=headers, removeNull=True
    )

    try:
        response_quick: Any = ip_quick_check_command(client, {"ip": ip})
        malicious_description = response_quick.outputs[0].get("code_value")
    except Exception:
        malicious_description = ""
    dbot_score = Common.DBotScore(
        indicator=response.get("address"),
        indicator_type=DBotScoreType.IP,
        score=dbot_score_int,
        integration_name="GreyNoise",
        malicious_description=malicious_description,
        reliability=reliability
    )

    city = response.get("metadata", {}).get("city", "")
    region = response.get("metadata", {}).get("region", "")
    country_code = response.get("metadata", {}).get("country_code", "")
    geo_description = (
        f"City: {city}, Region: {region}, Country Code: {country_code}" if (city or region or country_code) else ""
    )
    ip_standard_context = Common.IP(
        ip=response.get("address"),
        asn=response.get("metadata", {}).get("asn"),
        hostname=response.get("actor"),
        geo_country=response.get("metadata", {}).get("country"),
        geo_description=geo_description,
        dbot_score=dbot_score,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="GreyNoise.IP",
        outputs_key_field="address",
        outputs=response,
        indicator=ip_standard_context,
        raw_response=original_response,
    )


@exception_handler
@logger
def cve_command(client: Client, args: dict, reliability: str) -> List[CommandResults]:
    """
    Returns information about CVE.

    :type client: ``Client``
    :param client: client object

    :type reliability: ``String``
    :param reliability: string

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.
    :return: A ``CommandResults`` object that is then passed to ``return_results``,
           that contains the IP information.
    :rtype: ``CommandResults``

    """
    cve_list = argToList(args.get("cve"), ",")
    command_results = []
    reliability = reliability if reliability else DBotScoreReliability.B
    for cve_arg in cve_list:
        cvss = 0
        description = ""
        published = ""
        modified = ""
        response = client.cve(cve_arg)
        cve_raw_response = copy.deepcopy(response)
        response = remove_empty_elements(response)
        if isinstance(response, dict) and response.get("id"):
            cvss = response["details"].get("cve_cvss_score", "")
            description = response["details"].get("vulnerability_description", "")
            vendor = response["details"].get("vendor", "")
            product = response["details"].get("product", "")
            if "timeline" in response:
                published = response["timeline"].get("cve_published_date", "").split("T")[0]
                modified = response["timeline"].get("cve_last_updated_date", "").split("T")[0]
            name = "GreyNoise CVE Lookup"
            hr = {
                "CVE ID": response.get("id"),
                "CVSS": cvss,
                "Vendor": vendor,
                "Product": product,
                "Published to NVD": response["details"].get("published_to_nist_nvd", False)
            }
            human_readable = f"### CVE: {cve_arg} is found\n"
            human_readable += tableToMarkdown(
                name=name, t=hr, headers=["CVE ID", "CVSS", "Vendor", "Product", "Published to NVD"],
                removeNull=False
            )
            if "timeline" in response:
                name = "Timeline Details"
                hr = {
                    "Added to Kev": response["timeline"].get("cisa_kev_date_added", "").split("T")[0],
                    "Last Updated": modified,
                    "CVE Published": published,
                    "First Published": response["timeline"].get("first_known_published_date", "").split("T")[0],
                }
                human_readable += tableToMarkdown(
                    name=name, t=hr, headers=["Added to Kev", "Last Updated", "CVE Published", "First Published"],
                    removeNull=False
                )
            if "exploitation_details" in response:
                name = "Exploitation Details"
                hr = {
                    "Attack Vector": response["exploitation_details"].get("attack_vector", ""),
                    "EPSS Base Score": response["exploitation_details"].get("epss_score", ""),
                    "Exploit Found": response["exploitation_details"].get("exploit_found", ""),
                    "Exploit Registered in KEV": response["exploitation_details"].get("exploitation_registered_in_kev", ""),
                }
                human_readable += tableToMarkdown(
                    name=name, t=hr, headers=["Attack Vector", "EPSS Base Score", "Exploit Found", "Exploit Registered in KEV"],
                    removeNull=False
                )
            if "exploitation_stats" in response:
                name = "Exploitation Stats"
                hr = {
                    "# of Available Exploits": response["exploitation_stats"].get("number_of_available_exploits", ""),
                    "# of Botnets Exploiting": response["exploitation_stats"].get("number_of_botnets_exploiting_vulnerability",
                                                                                  ""),
                    "# of Threat Actors Exploiting": response["exploitation_stats"].get(
                        "number_of_threat_actors_exploiting_vulnerability", ""),
                }
                human_readable += tableToMarkdown(
                    name=name, t=hr,
                    headers=["# of Available Exploits", "# of Botnets Exploiting", "# of Threat Actors Exploiting"],
                    removeNull=False
                )
            if "exploitation_activity" in response:
                name = "Exploitation Activity - GreyNoise Insights"
                hr = {
                    "GreyNoise Observed Activity": response["exploitation_activity"].get("activity_seen", ""),
                    "# of Benign IPs - Last Day": response["exploitation_activity"].get("benign_ip_count_1d", ""),
                    "# of Benign IPs - Last 10 Days": response["exploitation_activity"].get("benign_ip_count_10d", ""),
                    "# of Benign IPs - Last 30 Days": response["exploitation_activity"].get("benign_ip_count_30d", ""),
                    "# of Threat IPs - Last Day": response["exploitation_activity"].get("threat_ip_count_1d", ""),
                    "# of Threat IPs - Last 10 Days": response["exploitation_activity"].get("threat_ip_count_10d", ""),
                    "# of Threat IPs - Last 30 Days": response["exploitation_activity"].get("threat_ip_count_30d", ""),
                }
                human_readable += tableToMarkdown(
                    name=name, t=hr, headers=[
                        "GreyNoise Observed Activity",
                        "# of Benign IPs - Last Day",
                        "# of Benign IPs - Last 10 Days",
                        "# of Benign IPs - Last 30 Days",
                        "# of Threat IPs - Last Day",
                        "# of Threat IPs - Last 10 Days",
                        "# of Threat IPs - Last 30 Days"
                    ],
                    removeNull=False
                )
        else:
            name = "GreyNoise CVE IP Lookup"
            hr = {
                "CVE ID": cve_arg,
            }
            human_readable = f"### CVE: {cve_arg} is not found\n"
            human_readable += tableToMarkdown(
                name=name, t=hr, headers=["CVE ID"],
                removeNull=False
            )

        dbot_score = Common.DBotScore(
            indicator=cve_arg,
            indicator_type=DBotScoreType.CVE,
            score=Common.DBotScore.NONE,
            integration_name="GreyNoise",
            reliability=reliability
        )
        cve = Common.CVE(
            id=cve_arg,
            cvss=cvss,
            description=description,
            published=published,
            modified=modified,
            dbot_score=dbot_score,
        )

        command_results.append(
            CommandResults(
                outputs_prefix='GreyNoise.CVE',
                outputs_key_field='id',
                outputs=cve_raw_response,
                indicator=cve,
                readable_output=human_readable
            )
        )

    return command_results


""" MAIN FUNCTION """


def main() -> None:
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

    api_key = demisto.params().get("credentials", {}).get("password") or demisto.params().get("apikey")
    if not api_key:
        return_error('Please provide a valid API token')
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
            api_server=API_SERVER,
            timeout=TIMEOUT,
            proxy=handle_proxy("proxy", proxy).get("https", ""),
            use_cache=False,
            integration_name=f"xsoar-integration-v{pack_version}",
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result: Any = test_module(client)
            return_results(result)

        elif demisto.command() == "greynoise-ip-quick-check":
            result = ip_quick_check_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == "ip":
            result = ip_reputation_command(client, demisto.args(), reliability)
            return_results(result)

        elif demisto.command() == "greynoise-stats":
            result = stats_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == "greynoise-similarity":
            result = similarity_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == "greynoise-timeline":
            result = timeline_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == "greynoise-query":
            result = query_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == "greynoise-riot":
            result = riot_command(client, demisto.args(), reliability)
            return_results(result)

        elif demisto.command() == "greynoise-context":
            result = context_command(client, demisto.args(), reliability)
            return_results(result)

        elif demisto.command() == "cve":
            result = cve_command(client, demisto.args(), reliability)
            return_results(result)
    # Log exceptions and return errors
    except DemistoException as err:
        return_error(str(err))

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            EXCEPTION_MESSAGES["COMMAND_FAIL"].format(demisto.command(), str(err))
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
