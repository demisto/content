import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

from typing import Dict, List, Set, Any, Callable, Optional
from collections import OrderedDict
import traceback
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_feed_client import SixgillFeedClient
from sixgill.sixgill_enrich_client import SixgillEnrichClient
from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_utils import is_indicator

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

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
                                       ('Language', 'lang'),
                                       ('Indicator ID', 'id'),
                                       ('External references (e.g. MITRE ATT&CK)', 'external_reference')])

HASH_MAPPING = {"hashes.md5": "md5", "hashes.\'sha-1\'": "sha1", "hashes.\'sha-256\'": "sha256",
                "hashes.\'sha-512\'": "sha512", "hashes.ssdeep": "ssdeep"}

''' HELPER FUNCTIONS '''

hashes: Dict[str, Any] = {}

stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")


class ExternalReferenceSourceTypes:
    MITRE_ATTACK = 'mitre-attack'
    VIRUS_TOTAL = 'VirusTotal'


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


def to_demisto_score(feed_id: str, revoked: bool):
    if revoked:
        return Common.DBotScore.NONE  # unknown
    if feed_id in SUSPICIOUS_FEED_IDS:
        return Common.DBotScore.SUSPICIOUS  # suspicious
    return Common.DBotScore.BAD  # bad


def get_description(stix_obj):
    description_string = ""
    for name, sixgill_name in DESCRIPTION_FIELD_ORDER.items():
        description_string += f"{name}: {stix_obj.get(sixgill_name)}\n"

    return description_string


def extract_external_reference_field(stix2obj, source_name, field_to_extract):
    for reference in stix2obj.get("external_reference", []):
        if reference.get("source_name") == source_name:
            return reference.get(field_to_extract, None)


def post_id_to_full_url(post_id):
    return f'https://portal.cybersixgill.com/#/search?q=_id:{post_id}'


def to_demisto_indicator(value, indicators_name, stix2obj, tags: list = [], tlp_color: Optional[str] = None):
    indicator = {
        "value": value,
        "type": indicators_name,
        "rawJSON": stix2obj,
        "fields": {
            "name": stix2obj.get("sixgill_feedname"),
            "actor": stix2obj.get("sixgill_actor"),
            "tags": list((set(stix2obj.get("labels")).union(set(tags)))),
            "firstseenbysource": stix2obj.get("created"),
            "description": get_description(stix2obj),
            "sixgillactor": stix2obj.get("sixgill_actor"),
            "sixgillfeedname": stix2obj.get("sixgill_feedname"),
            "sixgillsource": stix2obj.get("sixgill_source"),
            "sixgilllanguage": stix2obj.get("lang"),
            "sixgillposttitle": stix2obj.get("sixgill_posttitle"),
            "sixgillfeedid": stix2obj.get("sixgill_feedid"),
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


def stix2_to_demisto_indicator(stix2obj: Dict[str, Any], log, tags: list = [], tlp_color: Optional[str] = None):
    indicators = []
    pattern = stix2obj.get("pattern", "")
    sixgill_feedid = stix2obj.get("sixgill_feedid", "")
    hashes: Dict[str, Any] = {"md5": None, "sha1": None, "sha256": None, "sha512": None, "ssdeep": None}

    for match in stix_regex_parser.findall(pattern):
        try:
            _, sub_type, value = match
            demisto_indicator_map = demisto_mapping.get(sixgill_feedid)
            if demisto_indicator_map:
                indicators_name = demisto_indicator_map.get('name')
                value = run_pipeline(value, demisto_indicator_map.get('pipeline', []), log)
                demisto_indicator = to_demisto_indicator(value, indicators_name, stix2obj, tags, tlp_color)
                if demisto_indicator.get("type") == FeedIndicatorType.File and \
                        HASH_MAPPING.get(sub_type.lower()) in hashes.keys():
                    if HASH_MAPPING.get(sub_type.lower()):
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
                             tags: list = [], tlp_color: Optional[str] = None):
    bundle = client.get_bundle()
    indicators_to_create: List = []
    indicator_values_set: Set = set()

    for stix_indicator in bundle.get("objects"):
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


def get_score(indicator):
    return to_demisto_score(indicator.get('sixgill_feedid'), indicator.get('revoke', False))


def get_file_hashes(indicators: list = []):
    for indicator in indicators:
        process_file_hashes(indicator, demisto)

    return hashes


def process_file_hashes(stix2obj: Dict[str, Any], log):
    pattern = stix2obj.get("pattern", "")
    global hashes

    for match in stix_regex_parser.findall(pattern):
        try:
            # _, sub_type, value = match
            # hashes[HASH_MAPPING[sub_type.lower()]] = value

            _, sub_type, value = match
            if HASH_MAPPING[sub_type.lower()] not in hashes:
                hashes[HASH_MAPPING[sub_type.lower()]] = value

        except Exception as e:
            log.error(f"failed to get file hashes from: {e}, STIX object: {stix2obj}")
            continue


def ip_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    ips = argToList(args.get('ip'))
    skip = int(args.get('skip'))

    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    command_results: List[CommandResults] = []

    for ip in ips:
        ip_data = client.enrich_ioc('ip', ip, skip)

        score = 0
        if len(ip_data) != 0:
            score = max(list(map(get_score, ip_data)))

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='SixgillDarkfeedEnrichment',
            score=score
        )

        ip_standard_context = Common.IP(
            ip=ip,
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown('IP', ip_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sixgill.IP',
            outputs_key_field='ip',
            outputs=ip_data,
            indicator=ip_standard_context
        ))
    return command_results


def domain_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    domains = argToList(args.get('domain'))
    skip = int(args.get('skip'))

    if len(domains) == 0:
        raise ValueError('DOMAIN(s) not specified')

    command_results: List[CommandResults] = []

    for domain in domains:
        domain_data = client.enrich_ioc('domain', domain, skip)

        score = 0
        if len(domain_data) != 0:
            score = max(list(map(get_score, domain_data)))

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name='SixgillDarkfeedEnrichment',
            score=score
        )

        domain_standard_context = Common.Domain(
            domain=domain,
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown('Domain', domain_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sixgill.DOMAIN',
            outputs_key_field='domain',
            outputs=domain_data,
            indicator=domain_standard_context
        ))
    return command_results


def url_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    urls = argToList(args.get('url'))
    skip = int(args.get('skip'))

    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    command_results: List[CommandResults] = []

    for url in urls:
        url_data = client.enrich_ioc('url', url, skip)

        score = 0
        if len(url_data) != 0:
            score = max(list(map(get_score, url_data)))

        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name='SixgillDarkfeedEnrichment',
            score=score
        )

        url_standard_context = Common.URL(
            url=url,
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown('URL', url_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sixgill.URL',
            outputs_key_field='url',
            outputs=url_data,
            indicator=url_standard_context
        ))
    return command_results


def file_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    files = argToList(args.get('file'))
    skip = int(args.get('skip'))

    if len(files) == 0:
        raise ValueError('HASH(s) not specified')

    command_results: List[CommandResults] = []

    for file_hash in files:
        file_data = client.enrich_ioc('hash', file_hash, skip)

        score = 0
        if len(file_data) != 0:
            score = max(list(map(get_score, file_data)))

        file_hash_types = get_file_hashes(file_data)

        dbot_score = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name='SixgillDarkfeedEnrichment',
            score=score
        )

        file_standard_context = Common.File(
            md5=file_hash_types.get('md5'),
            sha256=file_hash_types.get('sha256'),
            sha1=file_hash_types.get('sha1'),
            sha512=file_hash_types.get('sha512'),
            ssdeep=file_hash_types.get('ssdeep'),
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown('File', file_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sixgill.File',
            outputs_key_field='file',
            outputs=file_data,
            indicator=file_standard_context
        ))
    return command_results


def actor_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    actors = argToList(args.get('actor'))
    skip = int(args.get('skip'))

    if len(actors) == 0:
        raise ValueError('ACTOR(s) not specified')

    command_results: List[CommandResults] = []

    for actor in actors:
        actor_data = client.enrich_actor(actor, skip)

        readable_output = tableToMarkdown('ACTOR', actor_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sixgill.ACTOR',
            outputs_key_field='actor',
            outputs=actor_data
        ))
    return command_results


def postid_reputation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    postids = argToList(args.get('post_id'))
    skip = int(args.get('skip'))

    if len(postids) == 0:
        raise ValueError('POSTID(s) not specified')

    command_results: List[CommandResults] = []

    for post_id in postids:
        post_id_data = client.enrich_postid(post_id, skip)

        readable_output = tableToMarkdown('POSTID', post_id_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Sixgill.POSTID',
            outputs_key_field='postid',
            outputs=post_id_data
        ))
    return command_results


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    max_indicators = get_limit(demisto.params().get('maxIndicators', MAX_INDICATORS), MAX_INDICATORS)

    SESSION.proxies = handle_proxy()

    client = SixgillFeedClient(demisto.params()['client_id'],
                               demisto.params()['client_secret'],
                               CHANNEL_CODE,
                               FeedStream.DARKFEED,
                               demisto, max_indicators, SESSION, VERIFY)

    enrich_client = SixgillEnrichClient(demisto.params()['client_id'],
                                        demisto.params()['client_secret'],
                                        CHANNEL_CODE,
                                        demisto, SESSION, VERIFY)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    tags = argToList(demisto.params().get('feedTags', []))
    tlp_color = demisto.params().get('tlp_color')
    commands: Dict[str, Callable] = {
        'test-module': test_module_command,
        'sixgill-get-indicators': get_indicators_command,
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, tags=tags, tlp_color=tlp_color)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif demisto.command() == 'ip':
            return_results(ip_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == 'domain':
            return_results(domain_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == 'url':
            return_results(url_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == 'file':
            return_results(file_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == 'actor':
            return_results(actor_reputation_command(enrich_client, demisto.args()))
        elif demisto.command() == 'post_id':
            return_results(postid_reputation_command(enrich_client, demisto.args()))
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())

            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error failed to execute {demisto.command()}, error: [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
