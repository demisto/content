import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from functools import partial

from CommonServerUserPython import *

''' IMPORTS '''

from typing import Any
from collections.abc import Callable
from collections import OrderedDict
import traceback
import requests
import urllib3
import re

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_feed_client import SixgillFeedClient
from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_utils import is_indicator

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CHANNEL_CODE = '7698e8287dfde53dcd13082be750a85a'
MAX_INDICATORS = 1000
SUSPICIOUS_FEED_IDS = ["darkfeed_003"]
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
VERIFY = not demisto.params().get("insecure", True)
SESSION = requests.Session()
DESCRIPTION_FIELD_ORDER = OrderedDict([('Description', 'description'),
                                       ('Created On', 'created'),
                                       ('Post Title', 'sixgill_posttitle'),
                                       ('Threat Actor Name', 'sixgill_actor'),
                                       ('Source', 'sixgill_source'),
                                       ('Sixgill Feed ID', 'sixgill_feedid'),
                                       ('Sixgill Feed Name', 'sixgill_feedname'),
                                       ('Sixgill Post ID', 'sixgill_postid'),
                                       ('Sixgill Confidence', 'sixgill_confidence'),
                                       ('Language', 'lang'),
                                       ('Indicator ID', 'id'),
                                       ('External references (e.g. MITRE ATT&CK)', 'external_reference')])

HASH_MAPPING = {"hashes.md5": "md5", "hashes.\'sha-1\'": "sha1", "hashes.\'sha-256\'": "sha256",
                "hashes.\'sha-512\'": "sha512", "hashes.ssdeep": "ssdeep"}

''' HELPER FUNCTIONS '''

stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")


class ExternalReferenceSourceTypes:
    MITRE_ATTACK = 'mitre-attack'
    VIRUS_TOTAL = 'VirusTotal'


def strip_http(url):
    return url.split('://')[-1]


def url_to_rfc3986(url):
    if url.startswith(('http://', 'https://', 'ftp://', 'sftp://')):
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


def to_demisto_score(feed_id: str, revoked: bool):
    if revoked:
        return 0
    if feed_id in SUSPICIOUS_FEED_IDS:
        return 2
    return 3


def get_description(stix_obj):
    description_string = ""
    for name, sixgill_name in DESCRIPTION_FIELD_ORDER.items():
        description_string += f"{name}: {stix_obj.get(sixgill_name)}\n"

    return description_string


def extract_external_reference_field(stix2obj, source_name, field_to_extract):
    for reference in stix2obj.get("external_reference", []):
        if reference.get("source_name") == source_name:
            return reference.get(field_to_extract, None)
    return None


def post_id_to_full_url(post_id):
    return f'https://portal.cybersixgill.com/#/search?q=_id:{post_id}'


def to_demisto_indicator(value, indicators_name, stix2obj, tags: list = [], tlp_color: str | None = None):
    indicator = {
        "value": value,
        "type": indicators_name,
        "rawJSON": stix2obj,
        "fields": {
            "actor": stix2obj.get("sixgill_actor"),
            "tags": list(set(stix2obj.get("labels")).union(set(tags))),
            "firstseenbysource": stix2obj.get("created"),
            "description": get_description(stix2obj),
            "sixgillactor": stix2obj.get("sixgill_actor"),
            "sixgillfeedname": stix2obj.get("sixgill_feedname"),
            "sixgillsource": stix2obj.get("sixgill_source"),
            "sixgilllanguage": stix2obj.get("lang"),
            "sixgillposttitle": stix2obj.get("sixgill_posttitle"),
            "sixgillfeedid": stix2obj.get("sixgill_feedid"),
            "sixgillconfidence": stix2obj.get("sixgill_confidence"),
            "sixgillpostreference": post_id_to_full_url(stix2obj.get("sixgill_postid", "")),
            "sixgillindicatorid": stix2obj.get("id"),
            "sixgilldescription": stix2obj.get("description"),
            "sixgillvirustotaldetectionrate": extract_external_reference_field(stix2obj,
                                                                               ExternalReferenceSourceTypes.VIRUS_TOTAL,
                                                                               "positive_rate"),
            "sixgillvirustotalurl": extract_external_reference_field(stix2obj,
                                                                     ExternalReferenceSourceTypes.VIRUS_TOTAL,
                                                                     "url"),
            "sixgillmitreattcktactic": extract_external_reference_field(stix2obj,
                                                                        ExternalReferenceSourceTypes.MITRE_ATTACK,
                                                                        "mitre_attack_tactic"),
            "sixgillmitreattcktechnique": extract_external_reference_field(stix2obj,
                                                                           ExternalReferenceSourceTypes.MITRE_ATTACK,
                                                                           "mitre_attack_technique"),
        },
        "score": to_demisto_score(stix2obj.get("sixgill_feedid"), stix2obj.get("revoked", False))
    }

    if stix2obj.get("sixgill_feedname"):
        indicator['fields']['tags'].append(stix2obj.get("sixgill_feedname"))

    if tlp_color:
        indicator['fields']['trafficlightprotocol'] = tlp_color

    mitre_id = extract_external_reference_field(stix2obj, ExternalReferenceSourceTypes.MITRE_ATTACK,
                                                "mitre_attack_tactic_id")
    mitre_url = extract_external_reference_field(stix2obj, ExternalReferenceSourceTypes.MITRE_ATTACK,
                                                 "mitre_attack_tactic_url")
    if mitre_id and mitre_url:
        indicator['fields']['feedrelatedindicators'] = [{
            "type": "MITRE ATT&CK",
            "value": mitre_id,
            "description": mitre_url
        }]
    return indicator


def get_limit(str_limit, default_limit):
    try:
        return int(str_limit)
    except Exception:
        return default_limit


def filter_confidence(confidence: int | str, indicator_obj: dict) -> bool:
    """
        Predicate function to filter records based on confidence score.
    """
    if isinstance(confidence, str) and confidence == 'all':
        return True
    sixgill_confidence = arg_to_number(indicator_obj.get("sixgill_confidence"), "sixgill_confidence", required=False)
    return sixgill_confidence >= int(confidence) if sixgill_confidence else False


def stix2_to_demisto_indicator(stix2obj: dict[str, Any], log, tags: list = [], tlp_color: str | None = None):
    indicators = []
    pattern = stix2obj.get("pattern", "")
    sixgill_feedid = stix2obj.get("sixgill_feedid", "")
    hashes: dict[str, Any] = {"md5": None, "sha1": None, "sha256": None, "sha512": None, "ssdeep": None}

    for match in stix_regex_parser.findall(pattern):
        try:
            _, sub_type, value = match
            demisto_indicator_map = demisto_mapping.get(sixgill_feedid)
            if demisto_indicator_map:
                indicators_name = demisto_indicator_map.get('name')
                value = run_pipeline(value, demisto_indicator_map.get('pipeline', []), log)
                demisto_indicator = to_demisto_indicator(value, indicators_name, stix2obj, tags, tlp_color)

                if demisto_indicator.get("type") == FeedIndicatorType.File and \
                        HASH_MAPPING.get(sub_type.lower()) in hashes and HASH_MAPPING.get(sub_type.lower()):
                    hashes[HASH_MAPPING[sub_type.lower()]] = value
                indicators.append(demisto_indicator)

        except Exception as e:
            log.error(f"failed converting STIX object to Demisto indicator: {e}, STIX object: {stix2obj}")
            continue

    if len(indicators) > 0 and all(ioc.get("type") == FeedIndicatorType.File for ioc in indicators):
        temp_indicator = indicators[0].copy()

        if hashes["sha256"] is not None:
            temp_indicator["value"] = hashes["sha256"]

        temp_indicator["fields"].update({hash_k: hash_v for hash_k, hash_v in hashes.items() if hash_v is not None})
        indicators = [temp_indicator]

    return indicators


demisto_mapping: dict[str, dict[str, Any]] = {
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
    'darkfeed_011': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_012': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_013': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_014': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_015': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_018': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_019': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_020': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_021': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_022': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_023': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_024': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_025': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_026': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_027': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_028': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_029': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_030': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_031': {'name': FeedIndicatorType.Domain, 'pipeline': [strip_http, clean_url]},
    'darkfeed_032': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_033': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_034': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_035': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_036': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_037': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_038': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_039': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_040': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_041': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_042': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_043': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_044': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_045': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_046': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_047': {'name': FeedIndicatorType.Domain, 'pipeline': [strip_http, clean_url]},
    'darkfeed_048': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_049': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_050': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_051': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_052': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_053': {'name': FeedIndicatorType.File, 'pipeline': []},
    'darkfeed_054': {'name': FeedIndicatorType.URL, 'pipeline': [url_to_rfc3986, clean_url]},
    'darkfeed_055': {'name': FeedIndicatorType.IP, 'pipeline': []},
    'darkfeed_056': {'name': FeedIndicatorType.IP, 'pipeline': []}
}

''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module_command(*args):
    """
    Performs basic Auth request
    """
    response = SESSION.send(request=SixgillAuthRequest(demisto.params()['client_id'],
                                                       demisto.params()['client_secret'], CHANNEL_CODE).prepare(),
                            verify=VERIFY)
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")
    return 'ok', None, 'ok'


def get_indicators_command(client: SixgillFeedClient, args):
    limit = int(args.get('limit'))
    indicators = fetch_indicators_command(client, limit, True)

    human_readable = tableToMarkdown('Indicators from Sixgill Dark Feed:', indicators,
                                     headers=['value', 'type', 'rawJSON', 'score'])
    return human_readable, {}, indicators


def fetch_indicators_command(client: SixgillFeedClient, limit: int = 0, get_indicators_mode: bool = False,
                             tags: list = [], tlp_color: str | None = None, confidence: int | None = None):
    bundle = client.get_bundle()
    indicators_to_create: list = []
    indicator_values_set: set = set()
    confidence = confidence or 'all'

    for stix_indicator in filter(partial(filter_confidence, confidence), bundle.get("objects")):
        if is_indicator(stix_indicator):
            demisto_indicators = stix2_to_demisto_indicator(stix_indicator, demisto, tags, tlp_color)

            for indicator in demisto_indicators:
                if indicator.get("value") not in indicator_values_set:
                    indicator_values_set.add(indicator.get("value"))
                    indicators_to_create.append(indicator)

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
                               demisto, max_indicators, SESSION, VERIFY)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    tags = argToList(demisto.params().get('feedTags', []))
    tlp_color = demisto.params().get('tlp_color')
    commands: dict[str, Callable] = {
        'test-module': test_module_command,
        'sixgill-get-indicators': get_indicators_command
    }
    confidence = demisto.params().get("confidence")
    if confidence is None or confidence in ['', 'all']:
        confidence = 'all'
    else:
        confidence = arg_to_number(confidence, "confidence", required=False)
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, tags=tags, tlp_color=tlp_color, confidence=confidence)
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
