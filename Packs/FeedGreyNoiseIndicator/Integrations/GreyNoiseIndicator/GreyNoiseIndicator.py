from datetime import datetime
from typing import Dict, List

from greynoise import GreyNoise, exceptions, util  # type: ignore

from CommonServerPython import *

INTEGRATION_NAME = "GreyNoise Indicator Feed"
API_SERVER = util.DEFAULT_CONFIG.get("api_server")
TIMEOUT = 300

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


class Client(GreyNoise):
    """
    Client to use in the GreyNoise Feed integration. Overrides BaseClient.
    """

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


def get_ip_reputation_score(classification: str) -> int:
    """Get DBot score and human-readable of score.

    :type classification: ``str``
    :param classification: classification of ip provided from GreyNoise.

    :return: int for score.
    :rtype: ``int``
    """
    if classification == "unknown":
        return 2
    elif classification == "benign":
        return 1
    elif classification == "malicious":
        return 3
    else:
        return 0


def format_timestamp(date: str) -> str:
    formatted_timestamp = datetime.strptime(date, "%Y-%m-%d").isoformat() + 'Z'

    return formatted_timestamp


def format_indicator(indicator, tlp_color: str):
    tags = ",".join(indicator.get("tags", []))
    if tags == "":
        tags = "INTERNET SCANNER"
    else:
        tags = "INTERNET SCANNER," + tags
    if "metadata" in indicator:
        country_code = indicator['metadata'].get('country_code', '')
    else:
        country_code = ""
    formatted_indicator = {
        'Value': indicator["ip"],
        'Type': FeedIndicatorType.IP,
        'rawJSON': indicator,
        'score': get_ip_reputation_score(indicator.get('classification', '')),
        'fields': {
            'firstseenbysource': format_timestamp(indicator.get("first_seen", "")),
            'lastseenbysource': format_timestamp(indicator.get("last_seen", "")),
            'geocountry': country_code,
            'tags': tags,
            'trafficlightprotocol': tlp_color
        }
    }

    return formatted_indicator


def build_feed_query(query: str) -> str:
    if query == "All":
        query_string = "last_seen:1d"
    elif query == "Malicious":
        query_string = "last_seen:1d classification:malicious"
    elif query == "Benign + Malicious":
        query_string = "last_seen:1d (classification:benign OR classification:malicious)"
    elif query == "Benign":
        query_string = "last_seen:1d classification:benign"
    else:
        query_string = ""

    return query_string


def fetch_indicators(client: Client, params) -> List[Dict]:
    """Retrieves all entries from the feed.
    Returns:
        A list of objects, containing the indicators.
    """

    query = params.get('greynoiseFeedType')
    tlp_color = params.get('tlp_color')
    feed_query = build_feed_query(query)

    try:
        response = client.query(query=feed_query, exclude_raw=True)
        indicators: List = []
        complete = False
        while not complete:
            for indicator in response.get("data", []):
                indicators.append(format_indicator(indicator, tlp_color))
            complete = response.get('complete', True)
            scroll = response.get('scroll', "")
            response = client.query(query=feed_query, exclude_raw=True, scroll=scroll)

    except Exception as err:
        demisto.debug(str(err))
        raise Exception(f'{err}')

    return indicators


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


def get_indicators_command(client: Client, params) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request.
    Returns:
        CommandResults object containing the indicators retrieved.
    """

    query = params.get('greynoiseFeedType')
    tlp_color = params.get('tlp_color')
    feed_query = build_feed_query(query)

    try:
        response = client.query(query=feed_query, exclude_raw=True, size=25)
        hr_indicators: List = []
        output_list: List = []

        for indicator in response.get("data", []):
            hr = format_indicator(indicator, tlp_color)
            hr_indicators.append(hr)
            output_list.append({'Type': hr.get('Type'),
                                'Value': hr.get('Value'),
                                'Tags': hr.get('fields', {}).get('tags')})

    except Exception as err:
        demisto.debug(str(err))
        raise Exception(f'{err}')

    human_readable = tableToMarkdown("Indicators from GreyNoise:", hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON', 'fields'], removeNull=True)
    human_readable += "Note: This display is limited to the first 25 indicators returned by the feed.\n"

    return CommandResults(
        outputs=output_list,
        readable_output=human_readable,
        outputs_prefix='GreyNoiseFeed.Indicators',
        outputs_key_field='value',
        raw_response=hr_indicators,
    )


def fetch_indicators_command(client: Client, params) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request.
    Returns:
        Indicators.
    """
    indicators = fetch_indicators(client, params)
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    pack_version = "1.0.0"

    # get pack version
    if is_demisto_version_ge("6.1.0"):
        response = demisto.internalHttpRequest("GET", "/contentpacks/metadata/installed")
        packs = json.loads(response["body"])
    else:
        packs = []

    if isinstance(packs, list):
        for pack in packs:
            if pack["name"] == "FeedGreyNoiseIndicator":
                pack_version = pack["currentVersion"]
    else:  # packs is a dict
        if packs.get("name") == "FeedGreyNoiseIndicator":
            pack_version = packs.get("currentVersion")

    api_key = params.get("credentials", {}).get("password") or params.get("apikey")
    if not api_key:
        return_error('Please provide a valid API token')
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            api_key=api_key,
            api_server=API_SERVER,
            timeout=TIMEOUT,
            proxy=handle_proxy("proxy", proxy).get("https", ""),
            use_cache=False,
            integration_name=f"xsoar-feed-v{pack_version}",
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'greynoise-get-indicators':
            return_results(get_indicators_command(client, params))
        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
