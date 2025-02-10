import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3

# Disable insecure warnings.
urllib3.disable_warnings()


FEED_STR = {
    'cryptominer': 'Cryptominer',
    'first-stage-delivery-vectors': 'First stage delivery vectors',
    'infostealer': 'Infostealer',
    'iot': 'IoT',
    'linux': 'Linux',
    'malicious-network-infrastructure': 'Malicious network infrastructure',
    'malware': 'Malware',
    'mobile': 'Mobile',
    'osx': 'OSX',
    'phishing': 'Phishing',
    'ransomware': 'Ransomware',
    'threat-actor': 'Threat actor',
    'trending': 'Trending',
    'vulnerability-weaponization': 'Vulnerability weaponization',
}


def _get_current_hour():
    """Gets current hour for Threat feeds."""
    time_obj = datetime.utcnow() - timedelta(hours=2)
    hour = time_obj.strftime('%Y%m%d%H')
    return hour


class DetectionRatio:
    """Class for detections."""
    malicious = 0
    total = 0

    def __init__(self, last_analysis_stats: dict):
        self.malicious = last_analysis_stats.get('malicious', 0)
        self.total = sum(last_analysis_stats.values())

    def __repr__(self):
        return f'{self.malicious}/{self.total}'


class Client(BaseClient):
    """Client for Google Threat Intelligence API."""

    def fetch_indicators(self, feed_type: str = 'malware', hour: str = None) -> dict:
        """Fetches indicators given a feed type and an hour."""
        if not hour:
            hour = _get_current_hour()
        return self._http_request(
            'GET',
            f'threat_lists/{feed_type}/{hour}',
        )

    def get_threat_feed(self, feed_type: str) -> list:
        """Retrieves matches for a given feed type."""
        last_threat_feed = demisto.getIntegrationContext().get('last_threat_feed')
        hour = _get_current_hour()

        if last_threat_feed == hour:
            return []

        response = self.fetch_indicators(feed_type, hour)
        demisto.setIntegrationContext({'last_threat_feed': hour})
        return response.get('iocs', [])


def test_module(client: Client) -> str:
    client.fetch_indicators()
    return 'ok'


def _add_gti_attributes(indicator_obj: dict, item: dict):
    """Addes GTI attributes."""

    # GTI assessment
    attributes = item.get('attributes', {})
    gti_assessment = attributes.get('gti_assessment', {})
    gti_threat_score = gti_assessment.get('threat_score', {}).get('value')
    gti_severity = gti_assessment.get('severity', {}).get('value')
    gti_verdict = gti_assessment.get('verdict', {}).get('value')

    # Relationships
    relationships = item.get('relationships', {})
    malware_families: list[str] = [
        x['attributes']['name']
        for x in relationships.get('malware_families', {}).get('data', [])
    ]
    malware_families = list(set(malware_families))
    threat_actors: list[str] = [
        x['attributes']['name']
        for x in relationships.get('threat_actors', {}).get('data', [])
    ]
    threat_actors = list(set(threat_actors))

    indicator_obj['fields'].update({
        'gtithreatscore': gti_threat_score,
        'gtiseverity': gti_severity,
        'gtiverdict': gti_verdict,
        'malwarefamily': malware_families,
        'actor': threat_actors,
    })
    indicator_obj.update({
        'gti_threat_score': gti_threat_score,
        'gti_severity': gti_severity,
        'gti_verdict': gti_verdict,
        'malware_families': malware_families,
        'threat_actors': threat_actors,
        'relationships': [
            EntityRelationship(
                name=EntityRelationship.Relationships.PART_OF,
                entity_a=indicator_obj['value'],
                entity_a_type=indicator_obj['type'],
                entity_b=malware_family.title(),
                entity_b_type=ThreatIntel.ObjectsNames.MALWARE,
                reverse_name=EntityRelationship.Relationships.CONTAINS,
            ).to_indicator() for malware_family in malware_families
        ] + [
            EntityRelationship(
                name=EntityRelationship.Relationships.ATTRIBUTED_BY,
                entity_a=indicator_obj['value'],
                entity_a_type=indicator_obj['type'],
                entity_b=threat_actor.title(),
                entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                reverse_name=EntityRelationship.Relationships.ATTRIBUTED_TO,
            ).to_indicator() for threat_actor in threat_actors
        ],
    })

    return indicator_obj


def _get_indicator_type(item: dict):
    """Gets indicator type."""
    if item['type'] == 'file':
        return FeedIndicatorType.File
    if item['type'] == 'domain':
        return FeedIndicatorType.Domain
    if item['type'] == 'url':
        return FeedIndicatorType.URL
    if item['type'] == 'ip_address':
        return FeedIndicatorType.IP
    raise ValueError(f'Unknown type: {item["type"]}. ID: {item["id"]}')


def _get_indicator_id(item: dict) -> str:
    """Gets indicator ID."""
    if item['type'] == 'url':
        return item.get('attributes', {}).get('url') or item['id']
    return item['id']


def _add_file_attributes(indicator_obj: dict, attributes: dict) -> dict:
    """Adds file attributes."""
    indicator_obj['fields'].update({
        'md5': attributes.get('md5'),
        'sha1': attributes.get('sha1'),
        'sha256': attributes.get('sha256'),
        'ssdeep': attributes.get('ssdeep'),
        'fileextension': attributes.get('type_extension'),
        'filetype': attributes.get('type_tag'),
        'imphash': attributes.get('pe_info', {}).get('imphash'),
        'displayname': attributes.get('meaningful_name'),
        'name': attributes.get('meaningful_name'),
        'size': attributes.get('size'),
        'creationdate': attributes.get('creation_date'),
        'firstseenbysource': attributes.get('first_submission_date'),
        'lastseenbysource': attributes.get('last_submission_date'),
    })

    return indicator_obj


def _add_domain_attributes(indicator_obj: dict, attributes: dict) -> dict:
    """Adds domain attributes."""
    indicator_obj['fields'].update({
        'creationdate': attributes.get('creation_date'),
        'registrarname': attributes.get('registrar'),
        'firstseenbysource': attributes.get('first_seen_itw_date'),
        'lastseenbysource': attributes.get('last_seen_itw_date'),
    })

    return indicator_obj


def _add_url_attributes(indicator_obj: dict, attributes: dict) -> dict:
    """Adds URL attributes."""
    indicator_obj['fields'].update({
        'firstseenbysource': attributes.get('first_submission_date'),
        'lastseenbysource': attributes.get('last_submission_date'),
    })

    return indicator_obj


def _add_ip_attributes(indicator_obj: dict, attributes: dict) -> dict:
    """Adds IP attributes."""
    indicator_obj['fields'].update({
        'countrycode': attributes.get('country'),
        'firstseenbysource': attributes.get('first_seen_itw_date'),
        'lastseenbysource': attributes.get('last_seen_itw_date'),
    })

    return indicator_obj


def _add_dedicated_attributes(indicator_obj: dict, attributes: dict) -> dict:
    """Adds dedicated attributes to indicator object."""
    if indicator_obj['type'] == FeedIndicatorType.File:
        return _add_file_attributes(indicator_obj, attributes)
    if indicator_obj['type'] == FeedIndicatorType.Domain:
        return _add_domain_attributes(indicator_obj, attributes)
    if indicator_obj['type'] == FeedIndicatorType.URL:
        return _add_url_attributes(indicator_obj, attributes)
    if indicator_obj['type'] == FeedIndicatorType.IP:
        return _add_ip_attributes(indicator_obj, attributes)
    raise ValueError(f'Unknown type: {indicator_obj["type"]}. ID: {indicator_obj["id"]}')


def _create_indicator(item: dict) -> dict:
    """Creates indicator object."""
    indicator_type = _get_indicator_type(item)
    indicator_id = _get_indicator_id(item)

    attributes: dict = item.get('attributes', {})

    detection_ratio = DetectionRatio(attributes.get('last_analysis_stats', {}))

    indicator_obj = {
        'type': indicator_type,
        'value': indicator_id,
        'service': 'Google Threat Intelligence',
        'fields': {
            'tags': attributes.get('tags') or None,
            'updateddate': attributes.get('last_modification_date'),
            'detectionengines': detection_ratio.total,
            'positivedetections': detection_ratio.malicious,
        },
        'rawJSON': {
            'type': indicator_type,
            'value': indicator_id,
            'attributes': attributes,
            'relationships': item.get('relationships', {}),
        },
        'id': indicator_id,
        'detections': str(detection_ratio),
    }

    indicator_obj = _add_gti_attributes(indicator_obj, item)
    indicator_obj = _add_dedicated_attributes(indicator_obj, attributes)

    return indicator_obj


def fetch_indicators_command(client: Client,
                             feed_type: str,
                             tlp_color: str = None,
                             feed_tags: list = None,
                             limit: int = None,
                             minimum_score: int = 0) -> list[dict]:
    """Retrieves indicators from the feed.
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): Tags to assign fetched indicators
        limit (int): Limit the results
    Returns:
        Indicators.
    """
    iterator = client.get_threat_feed(feed_type)
    indicators = []

    if limit:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        try:
            indicator_obj = _create_indicator(item['data'])
        except ValueError as exc:
            demisto.info(str(exc))
            continue

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        if int(indicator_obj['fields'].get('gtithreatscore') or 0) >= minimum_score:
            indicators.append(indicator_obj)
        else:
            try:
                existing_indicators = list(IndicatorsSearcher(value=indicator_obj['value']))
            except SystemExit as exc:
                demisto.debug(exc)
                existing_indicators = []
            if len(existing_indicators) > 0 and int(existing_indicators[0].get('total', 0)) > 0:
                indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: dict[str, str],
                           args: dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    feed_type = params.get('feed_type', 'apt')
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    limit = int(args.get('limit', 0))
    minimum_score = int(params.get('feedMinimumGTIScore', 80))
    indicators = fetch_indicators_command(
        client,
        feed_type,
        tlp_color,
        feed_tags,
        limit,
        minimum_score,
    )

    human_readable = tableToMarkdown(
        f'Indicators from Google Threat Intelligence {FEED_STR.get(feed_type, feed_type)} Feeds:',
        indicators,
        headers=[
            'sha256',
            'fileType',
            'gti_threat_score',
            'gti_severity',
            'gti_verdict',
            'malware_families',
            'threat_actors',
        ],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def reset_last_threat_feed():
    """Reset last threat feed from the integration context."""
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def main():
    """main function, parses params and runs command functions."""
    params = demisto.params()

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    secure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url='https://www.virustotal.com/api/v3/',
            verify=secure,
            proxy=proxy,
            headers={
                'x-apikey': params['credentials']['password'],
                'x-tool': 'CortexGTIFeeds',
            }
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'gti-feed-get-indicators':
            # This is the command that fetches a limited number of indicators
            # from the feed source and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == 'gti-feed-reset-fetch-indicators':
            return_results(reset_last_threat_feed())

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the commandthat will be executed at the specified feed fetch
            # interval.
            feed_type = params.get('feed_type', 'apt')
            tlp_color = params.get('tlp_color')
            feed_tags = argToList(params.get('feedTags'))
            indicators = fetch_indicators_command(client, feed_type, tlp_color, feed_tags)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
