import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_feed_client import SixgillFeedClient
from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_utils import is_indicator
from typing import Dict, List, Any, Callable
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
MAX_INDICATORS = 1000
SUSPICIOUS_FEED_IDS = ["darkfeed_003"]
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
VERIFY = not demisto.params().get("insecure", True)
SESSION = requests.Session()

''' HELPER FUNCTIONS '''

stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")


def strip_http(url):
    return url.split('://')[-1]


def url_to_rfc3986(url):
    if url.startswith('http://') or url.startswith('https://') or url.startswith('ftp://') or url.startswith('sftp://'):
        return url
    else:
        return f'https://{url}'


def clean_url(value):
    return value.replace("[.]", ".")


def run_pipeline(value, pipeline, log):
    for func in pipeline:
        log.debug(f"run {func.__name__} function on value: {value}")
        value = func(value)
        log.debug(f"post {func.__name__} run value: {value}")

    log.debug(f"returned value: {value}")
    return value


def to_demisto_score(feed_id: str):
    if feed_id in SUSPICIOUS_FEED_IDS:
        return 2
    return 3


def to_demisto_indicator(value, indicators_name, stix2obj):
    return {
        "value": value,
        "type": indicators_name,
        "rawJSON": stix2obj,
        "fields": {
            "source": stix2obj.get("sixgill_source"),
            "name": stix2obj.get("sixgill_feedname"),
            "actor": stix2obj.get("sixgill_actor"),
            "description":
                f'''description: {stix2obj.get("description")}
feedid: {stix2obj.get("sixgill_feedid")}
title: {stix2obj.get("sixgill_posttitle")}
post_id: {stix2obj.get("sixgill_postid")}
actor: {stix2obj.get("sixgill_actor")}
lang: {stix2obj.get("lang")}
labels: {stix2obj.get("labels")}
external_reference: {stix2obj.get("external_reference", {})}'''},
        "score": to_demisto_score(stix2obj.get("sixgill_feedid"))}


def get_limit(str_limit, default_limit):
    try:
        return int(str_limit)
    except Exception:
        return default_limit


def stix2_to_demisto_indicator(stix2obj: Dict[str, Any], log):
    indicators = []
    pattern = stix2obj.get("pattern", "")
    sixgill_feedid = stix2obj.get("sixgill_feedid", "")

    for match in stix_regex_parser.findall(pattern):
        try:
            _, sub_type, value = match
            demisto_indicator_map = demisto_mapping.get(sixgill_feedid)
            if demisto_indicator_map:
                indicators_name = demisto_indicator_map.get('name')
                value = run_pipeline(value, demisto_indicator_map.get('pipeline', []), log)
                demisto_indicator = to_demisto_indicator(value, indicators_name, stix2obj)
                indicators.append(demisto_indicator)

        except Exception as e:
            log.error(f"failed converting STIX object to Demisto indicator: {e}, STIX object: {stix2obj}")
            continue

    return indicators


demisto_mapping: Dict[str, Dict[str, Any]] = {
    'darkfeed_001': {'name': FeedIndicatorType.Domain, 'pipeline': [strip_http, clean_url]},
    'darkfeed_002': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_003': {'name': FeedIndicatorType.Domain, 'pipeline': [strip_http, clean_url]},
    'darkfeed_004': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_005': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_006': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_007': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_008': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_009': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_010': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_012': {'name': FeedIndicatorType.File, 'pipeline': []},

}


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module_command(*args):
    """
    Performs basic Auth request
    """
    response = SESSION.send(request=SixgillAuthRequest(demisto.params()['client_id'],
                                                       demisto.params()['client_secret']).prepare(), verify=VERIFY)
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")
    return 'ok', None, 'ok'


def get_indicators_command(client: SixgillFeedClient, args):
    limit = int(args.get('limit'))
    indicators = fetch_indicators_command(client, limit, True)

    human_readable = tableToMarkdown('Indicators from Sixgill Dark Feed:', indicators,
                                     headers=['value', 'type', 'rawJSON', 'score'])
    return human_readable, {}, indicators


def fetch_indicators_command(client: SixgillFeedClient, limit: int = 0, get_indicators_mode: bool = False):
    bundle = client.get_bundle()
    indicators_to_create: List = []

    for stix_indicator in bundle.get("objects"):
        if is_indicator(stix_indicator):
            demisto_indicators = stix2_to_demisto_indicator(stix_indicator, demisto)
            indicators_to_create.extend(demisto_indicators)

        if get_indicators_mode and len(indicators_to_create) == limit:
            break

    if not get_indicators_mode:
        client.commit_indicators()

    return indicators_to_create


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    max_indicators = get_limit(demisto.params().get('maxIndicators', MAX_INDICATORS), MAX_INDICATORS)

    SESSION.proxies = handle_proxy()

    client = SixgillFeedClient(demisto.params()['client_id'],
                               demisto.params()['client_secret'],
                               CHANNEL_CODE,
                               FeedStream.DARKFEED,
                               demisto, max_indicators, SESSION)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    commands: Dict[str, Callable] = {
        'test-module': test_module_command,
        'sixgill-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())

            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error failed to execute {demisto.command()}, error: [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
