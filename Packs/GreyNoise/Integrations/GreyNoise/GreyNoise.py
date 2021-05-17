import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' Imports '''

import urllib3  # type: ignore
import traceback
import requests
import re
import copy
from typing import Tuple, Dict
from greynoise import GreyNoise, exceptions, util  # type: ignore

# Disable insecure warnings
urllib3.disable_warnings()
util.LOGGER.warning = util.LOGGER.debug

''' CONSTANTS '''

TIMEOUT = 10
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
    "organization": "Organization",
    "category": "Category",
    "tor": "Tor",
    "rdns": "RDNS",
    "os": "OS",
    "region": "Region",
    "vpn": "VPN",
    "vpn_service": "VPN Service",
    "raw_data": "raw_data",
    "scan": "scan",
    "port": "port",
    "protocol": "protocol",
    "web": "web",
    "paths": "paths",
    "useragents": "useragents",
    "ja3": "ja3",
    "fingerprint": "fingerprint",
    "hassh": "hassh"
}
IP_CONTEXT_HEADERS = ["IP", "Classification", "Actor", "CVE", "Spoofable", "VPN",
                      "First Seen", "Last Seen"]
API_SERVER = util.DEFAULT_CONFIG.get("api_server")
IP_QUICK_CHECK_HEADERS = ['IP', 'Noise', 'Code', 'Code Description']
STATS_KEY = {
    "classifications": "Classifications",
    "spoofable": "Spoofable",
    "organizations": "Organizations",
    "actors": "Actors",
    "countries": "Countries",
    "tags": "Tags",
    "operating_systems": "Operating Systems",
    "categories": "Categories",
    "asns": "ASNs"
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
    "count": "Count"
}
QUERY_OUTPUT_PREFIX: Dict[str, str] = {
    'IP': 'GreyNoise.IP(val.address && val.address == obj.address)',
    'QUERY': 'GreyNoise.Query(val.query && val.query == obj.query)',
}
EXCEPTION_MESSAGES = {
    'API_RATE_LIMIT': 'API Rate limit hit. Try after sometime.',
    'UNAUTHENTICATED': 'Unauthenticated. Check the configured API Key.',
    'COMMAND_FAIL': 'Failed to execute {} command.\n Error: {}',
    'SERVER_ERROR': 'The server encountered an internal error for GreyNoise and was unable to complete your request.',
    'CONNECTION_TIMEOUT': 'Connection timed out. Check your network connectivity.',
    'PROXY': "Proxy Error - cannot connect to proxy. Either try clearing the "
             "'Use system proxy' check-box or check the host, "
             "authentication details and connection details for the proxy.",
    'INVALID_RESPONSE': 'Invalid response from GreyNoise. Response: {}',
    'QUERY_STATS_RESPONSE': 'GreyNoise request failed. Reason: {}'
}


''' CLIENT CLASS '''


class Client(GreyNoise):
    """Client class to interact with the service API
    """
    def authenticate(self):
        """
        Used to authenticate GreyNoise credentials.
        """
        response = str(self.test_connection())
        if response == "Success: Access and API Key Valid":
            return 'ok'

        code, body = parse_code_and_body(response)
        if code and body:
            raise exceptions.RequestFailure(code, body)
        elif response == "":
            raise exceptions.RateLimitError()
        elif "ProxyError" in response:
            raise requests.exceptions.ProxyError()
        elif "timed out" in response:
            raise requests.exceptions.ConnectTimeout()
        else:
            raise Exception(response)


''' HELPER FUNCTIONS '''


def exception_handler(func: Any) -> Any:
    """
    Decorator to handle all type of errors possible with GreyNoise SDK.
    """

    def inner_func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except exceptions.RateLimitError:
            raise DemistoException(EXCEPTION_MESSAGES['API_RATE_LIMIT'])
        except exceptions.RequestFailure as err:
            status_code, body = parse_code_and_body(str(err))
            if status_code == 401 and "forbidden" in body:
                raise DemistoException(EXCEPTION_MESSAGES['UNAUTHENTICATED'])
            elif 400 <= status_code < 500:
                raise DemistoException(EXCEPTION_MESSAGES['COMMAND_FAIL'].format(demisto.command(), body))
            elif status_code >= 500:
                raise DemistoException(EXCEPTION_MESSAGES['SERVER_ERROR'])
            else:
                raise DemistoException(str(err))
        except requests.exceptions.ConnectTimeout:
            raise DemistoException(EXCEPTION_MESSAGES['CONNECTION_TIMEOUT'])
        except requests.exceptions.ProxyError:
            raise DemistoException(EXCEPTION_MESSAGES['PROXY'])

    return inner_func


def parse_code_and_body(message: str) -> Tuple[int, str]:
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
        tmp_response['MetaData'] = metadata_list

        for key, value in response.items():
            if value != "" and key not in ["metadata", "raw_data"]:
                tmp_response[PRETTY_KEY.get(key, key)] = value

        ip = tmp_response['IP']
        tmp_response['IP'] = f"[{ip}](https://viz.greynoise.io/ip/{ip})"

        ip_context_responses.append(tmp_response)

    return ip_context_responses


def get_ip_reputation_score(classification: str) -> Tuple[int, str]:
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


def generate_advanced_query(args: dict) -> str:
    """Generate advance query for GreyNoise from args.

    :type args: ``dict``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: advanced query.
    :rtype: ``str``
    """

    advanced_query = args.get("advanced_query", "")
    used_args: dict = {
        'actor': args.get('actor'),
        'classification': args.get('classification'),
        'spoofable': args.get('spoofable'),
        'last_seen': args.get('last_seen'),
        'organization': args.get('organization')
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
        advanced_query = 'spoofable:false'

    return advanced_query


''' COMMAND FUNCTIONS '''


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
def ip_quick_check_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
        raise DemistoException(EXCEPTION_MESSAGES['INVALID_RESPONSE'].format(response))

    original_response = copy.deepcopy(response)
    hr_list = []
    for record in response:
        hr_record = {
            'IP': record.get('ip') or record.get('address'),
            'Noise': record.get('noise'),
            'Code': record.get('code'),
            'Code Description': record.get('code_message'),
        }
        ip = hr_record['IP']
        hr_record['IP'] = f"[{ip}](https://viz.greynoise.io/ip/{ip})"
        hr_list.append(hr_record)

    hr = tableToMarkdown(
        name='IP Quick Check Details',
        t=hr_list,
        headers=IP_QUICK_CHECK_HEADERS,
        removeNull=True
    )
    for resp in response:
        if 'ip' in resp:
            resp['address'] = resp['ip']
            del resp['ip']
        resp['code_value'] = resp['code_message']
        del resp['code_message']

    return CommandResults(
        outputs_prefix='GreyNoise.IP',
        outputs_key_field='address',
        outputs=remove_empty_elements(response),
        readable_output=hr,
        raw_response=original_response
    )


@exception_handler
@logger
def ip_reputation_command(client: Client, args: dict) -> List[CommandResults]:
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
    """
    ips = argToList(args.get("ip"), ",")
    command_results = []
    for ip in ips:

        response = client.ip(ip)

        if not isinstance(response, dict):
            raise DemistoException(EXCEPTION_MESSAGES['INVALID_RESPONSE'].format(response))

        original_response = copy.deepcopy(response)
        tmp_response = get_ip_context_data([response])
        response = remove_empty_elements(response)

        response['address'] = response['ip']
        del response['ip']

        dbot_score_int, dbot_score_string = get_ip_reputation_score(response.get("classification"))

        human_readable = f'### IP: {ip} found with Reputation: {dbot_score_string}\n'
        human_readable += tableToMarkdown(
            name='IP Context',
            t=tmp_response,
            headers=IP_CONTEXT_HEADERS,
            removeNull=True
        )

        try:
            response_quick: Any = ip_quick_check_command(client, {"ip": ip})
            malicious_description = response_quick.outputs[0].get('code_value')
        except Exception:
            malicious_description = ""
        dbot_score = Common.DBotScore(
            indicator=response.get('address'),
            indicator_type=DBotScoreType.IP,
            score=dbot_score_int,
            integration_name='GreyNoise',
            malicious_description=malicious_description
        )

        city = response.get('metadata', {}).get('city', '')
        region = response.get('metadata', {}).get('region', '')
        country_code = response.get('metadata', {}).get('country_code', '')
        geo_description = f"City: {city}, Region: {region}, Country Code: {country_code}"\
            if (city or region or country_code) else ""
        ip_standard_context = Common.IP(
            ip=response.get('address'),
            asn=response.get('metadata', {}).get('asn'),
            hostname=response.get('actor'),
            geo_country=response.get('metadata', {}).get('country'),
            geo_description=geo_description,
            dbot_score=dbot_score
        )

        command_results.append(
            CommandResults(
                readable_output=human_readable,
                outputs_prefix='GreyNoise.IP',
                outputs_key_field='address',
                outputs=response,
                indicator=ip_standard_context,
                raw_response=original_response
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

    query_response = client.query(
        query=advanced_query,
        size=args.get("size", "10"),
        scroll=args.get("next_token")
    )
    if not isinstance(query_response, dict):
        raise DemistoException(EXCEPTION_MESSAGES['INVALID_RESPONSE'].format(query_response))

    if query_response.get("message") != "ok":
        raise DemistoException(EXCEPTION_MESSAGES['QUERY_STATS_RESPONSE'].format(query_response.get('message')))

    original_response = copy.deepcopy(query_response)
    tmp_response = []
    for each in query_response.get("data", []):
        tmp_response += get_ip_context_data([each])
        each['address'] = each['ip']
        del each['ip']

    human_readable = f'### Total findings: {query_response.get("count")}\n'

    human_readable += tableToMarkdown(
        name='IP Context',
        t=tmp_response,
        headers=IP_CONTEXT_HEADERS,
        removeNull=True
    )

    if not query_response.get("complete"):
        human_readable += f'\n### Next Page Token: \n{query_response.get("scroll")}'

    query = query_response.get("query", "").replace(" ", "+")
    query_link = f'https://viz.greynoise.io/query/?gnql={query}'
    query_link = query_link.replace("*", "&ast;")
    query_link = query_link.replace('"', "&quot;")
    human_readable += f'\n*To view the detailed query result please click [here]({query_link}).*'

    outputs = {
        QUERY_OUTPUT_PREFIX['IP']: query_response.get("data", []),
        QUERY_OUTPUT_PREFIX['QUERY']: {
            'complete': query_response.get('complete'),
            'count': query_response.get('count'),
            'message': query_response.get('message'),
            'query': query_response.get('query'),
            'scroll': query_response.get('scroll')
        }
    }

    return CommandResults(
        readable_output=human_readable,
        outputs=remove_empty_elements(outputs),
        raw_response=original_response
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
        raise DemistoException(EXCEPTION_MESSAGES['INVALID_RESPONSE'].format(response))

    if response.get("count") == 0:
        raise DemistoException(EXCEPTION_MESSAGES['QUERY_STATS_RESPONSE'].format('no results'))

    human_readable = f'### Stats\n### Query: {advance_query} Count: {response.get("count", "0")}\n'

    for key, value in response.get("stats", {}).items():
        hr_list: list = []
        if value is None:
            continue
        for rec in value:
            hr_rec: dict = {}
            header = []
            for k, v in rec.items():
                hr_rec.update({f"{STATS_H_KEY.get(k)}": f"{v}"})
                header.append(STATS_H_KEY.get(k))
            hr_list.append(hr_rec)
        human_readable += tableToMarkdown(
            name=f"{STATS_KEY.get(key, key)}",
            t=hr_list,
            headers=header,
            removeNull=True
        )

    return CommandResults(
        outputs_prefix='GreyNoise.Stats',
        outputs_key_field='query',
        outputs=remove_empty_elements(response),
        readable_output=human_readable
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            api_key=api_key,
            api_server=API_SERVER,
            timeout=TIMEOUT,
            proxy=handle_proxy('proxy', proxy).get('https', ''),
            use_cache=False,
            integration_name=f"xsoar-integration-v{demisto.demistoVersion()['version']}"
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result: Any = test_module(client)
            return_results(result)

        elif demisto.command() == 'greynoise-ip-quick-check':
            result = ip_quick_check_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == 'ip':
            result = ip_reputation_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == 'greynoise-stats':
            result = stats_command(client, demisto.args())
            return_results(result)

        elif demisto.command() == 'greynoise-query':
            result = query_command(client, demisto.args())
            return_results(result)

    # Log exceptions and return errors
    except DemistoException as err:
        return_error(str(err))

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(EXCEPTION_MESSAGES['COMMAND_FAIL'].format(demisto.command(), str(err)))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
