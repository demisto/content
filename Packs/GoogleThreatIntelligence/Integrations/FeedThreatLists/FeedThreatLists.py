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


def _get_current_package():
    """Gets current package for Threat Lists."""
    time_obj = datetime.utcnow() - timedelta(hours=2)
    package = time_obj.strftime('%Y%m%d%H')
    return package


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

    def get_threat_list(self,
                        feed_type: str,
                        package: str,
                        filter_query: str = None,
                        limit: int = 10) -> dict:
        """Get indicators from GTI API."""
        return self._http_request(
            'GET',
            f'threat_lists/{feed_type}/{package}',
            params=assign_params(
                query=filter_query,
                limit=limit,
            )
        )

    def fetch_indicators(self,
                         feed_type: str,
                         package: str = None,
                         filter_query: str = None,
                         limit: int = 10,
                         fetch_command: bool = False) -> list:
        """Retrieves matches for a given feed type."""
        package = package or _get_current_package()
        filter_query = filter_query or ''

        if fetch_command:
            if self.get_last_run() == package:
                return []

        response = self.get_threat_list(feed_type, package, filter_query.strip(), limit)

        if fetch_command:
            self.set_last_run(package)

        return response.get('iocs', [])

    @staticmethod
    def set_last_run(package: str = None):
        """Sets last threat feed."""
        current_package = package or _get_current_package()
        demisto.setLastRun({'last_threat_feed': current_package})

    @staticmethod
    def get_last_run() -> str:
        """Gets last threat feed, or '' if no last run."""
        return (demisto.getLastRun() or {}).get('last_threat_feed', '')


def test_module(client: Client, args: dict) -> str:
    """Tests module."""
    try:
        client.fetch_indicators('malware')
    except Exception:
        raise Exception("Could not fetch Google Threat Intelligence IoC Threat Lists\n"
                        "\nCheck your API key and your connection to Google Threat Intelligence.")
    return 'ok'


def _gti_verdict_to_dbot_score(gti_verdict: str):
    """Parses GTI verdict to DBotScore."""
    return {
        'VERDICT_BENIGN': 1,
        'VERDICT_SUSPICIOUS': 2,
        'VERDICT_MALICIOUS': 3,
    }.get(gti_verdict, 0)


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
        'score': _gti_verdict_to_dbot_score(gti_verdict),
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
    whois: str = attributes.get('whois', '')

    admin_country = re.search(r'Admin Country:\s*([^\n]+)', whois)
    admin_email = re.search(r'Admin Email:\s*([^\n]+)', whois)
    admin_name = re.search(r'Admin Name:\s*([^\n]+)', whois)
    admin_phone = re.search(r'Admin Phone:\s*([^\n]+)', whois)

    registrant_country = re.search(r'Registrant Country:\s*([^\n]+)', whois)
    registrant_email = re.search(r'Registrant Email:\s*([^\n]+)', whois)
    registrant_name = re.search(r'Registrant Name:\s*([^\n]+)', whois)
    registrant_phone = re.search(r'Registrant Phone:\s*([^\n]+)', whois)

    registrar_abuse_email = re.search(r'Registrar Abuse Contact Email:\s*([^\n]+)', whois)
    registrar_abuse_phone = re.search(r'Registrar Abuse Contact Phone:\s*([^\n]+)', whois)

    indicator_obj['fields'].update({
        'creationdate': attributes.get('creation_date'),
        'admincountry': admin_country.group(1) if admin_country else None,
        'adminemail': admin_email.group(1) if admin_email else None,
        'adminname': admin_name.group(1) if admin_name else None,
        'adminphone': admin_phone.group(1) if admin_phone else None,
        'registrantcountry': registrant_country.group(1) if registrant_country else None,
        'registrantemail': registrant_email.group(1) if registrant_email else None,
        'registrantname': registrant_name.group(1) if registrant_name else None,
        'registrantphone': registrant_phone.group(1) if registrant_phone else None,
        'registrarabuseemail': registrar_abuse_email.group(1) if registrar_abuse_email else None,
        'registrarabusephone': registrar_abuse_phone.group(1) if registrar_abuse_phone else None,
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
                             package: str = None,
                             filter_query: str = None,
                             limit: int = 10,
                             tlp_color: str = None,
                             feed_tags: list = None,
                             fetch_command: bool = False) -> list[dict]:
    """Retrieves indicators from the feed.
    Args:
        client (Client): Client object with request
        feed_type (str): Feed type
        package (string): Package in '%Y%m%d%H' format
        filter_query (string): filter query
        limit (int): Limit the results
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): Tags to assign fetched indicators
        fetch_command (bool): Whether command is used as fetch command.
    Returns:
        Indicators.
    """
    indicators = []

    raw_indicators = client.fetch_indicators(feed_type,
                                             package=package,
                                             filter_query=filter_query,
                                             limit=limit,
                                             fetch_command=fetch_command)

    # extract values from iterator
    for item in raw_indicators:
        try:
            indicator_obj = _create_indicator(item['data'])
        except ValueError as exc:
            demisto.info(str(exc))
            continue

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

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
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    feed_type = args.get('feed_type', 'malware')
    package = args.get('package')
    filter_query = args.get('filter')
    limit = int(args.get('limit', 10))

    indicators = fetch_indicators_command(
        client,
        feed_type,
        package=package,
        filter_query=filter_query,
        limit=limit,
        tlp_color=tlp_color,
        feed_tags=feed_tags,
    )

    human_readable = tableToMarkdown(
        f'Indicators from Google Threat Intelligence {FEED_STR.get(feed_type, feed_type)} Threat List:',
        indicators,
        headers=[
            'id',
            'detections',
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


def main():
    """main function, parses params and runs command functions."""
    params = demisto.params()

    feed_type = params.get('feed_type', 'malware')
    filter_query = params.get('filter')
    limit = int(params.get('limit', 10))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    secure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()

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
            return_results(test_module(client, {}))

        elif command == 'gti-threatlists-get-indicators':
            # This is the command that fetches a limited number of indicators
            # from the feed source and displays them in the war room.
            return_results(get_indicators_command(client, params, demisto.args()))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the command that will be executed at the specified feed fetch
            # interval.
            indicators = fetch_indicators_command(client,
                                                  feed_type,
                                                  filter_query=filter_query,
                                                  limit=limit,
                                                  tlp_color=tlp_color,
                                                  feed_tags=feed_tags,
                                                  fetch_command=True)
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
