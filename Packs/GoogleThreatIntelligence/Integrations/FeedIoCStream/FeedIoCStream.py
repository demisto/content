"""Google Threat Intelligence IoC Stream Feed integration."""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime
import re
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class DetectionRatio:
    """Class for detections."""
    malicious = 0
    total = 0

    def __init__(self, last_analysis_stats: dict):
        self.malicious = last_analysis_stats.get('malicious', 0)
        self.total = (
            last_analysis_stats.get('harmless', 0)
            + last_analysis_stats.get('suspicious', 0)
            + last_analysis_stats.get('undetected', 0)
            + last_analysis_stats.get('malicious', 0)
        )

    def __repr__(self):
        return f'{self.malicious}/{self.total}'


class Client(BaseClient):
    """Class for GTI client."""

    def get_api_indicators(self,
                           filter_query: str = None,
                           limit: int = 10):
        """Get indicators from GTI API."""
        return self._http_request(
            'GET',
            'ioc_stream',
            params=assign_params(
                filter=filter_query,
                limit=min(limit, 40),
            )
        )

    def fetch_indicators(self,
                         limit: int = 10,
                         filter_query: str = None,
                         fetch_command: bool = False) -> list:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        filter_query = filter_query or ''

        if fetch_command:
            if last_run := self.get_last_run():
                filter_query += f' {last_run}'

        response = self.get_api_indicators(filter_query.strip(), limit)

        if fetch_command:
            self.set_last_run()

        return response.get('data', [])

    @staticmethod
    def set_last_run():
        """
        Returns: Current timestamp
        """
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        demisto.setLastRun({'last_run': timestamp})

    @staticmethod
    def get_last_run() -> str:
        """Gets last run time in timestamp
        Returns:
            last run in timestamp, or '' if no last run
        """
        if last_run := (demisto.getLastRun() or {}).get('last_run'):
            demisto.info(f'get last_run: {last_run}')
            params = f'date:{last_run}+'
        else:
            params = ''
        return params


def test_module(client: Client, args: dict) -> str:
    """Tests module."""
    try:
        client.fetch_indicators()
    except Exception:
        raise Exception("Could not fetch Google Threat Intelligence IoC Stream Feed\n"
                        "\nCheck your API key and your connection to Google Threat Intelligence.")
    return 'ok'


def _gti_verdict_to_dbot_score(gti_verdict: str):
    """Parses GTI verdict to DBotScore."""
    return {
        'VERDICT_BENIGN': 1,
        'VERDICT_SUSPICIOUS': 2,
        'VERDICT_MALICIOUS': 3,
    }.get(gti_verdict, 0)


def _add_gti_attributes(indicator_obj: dict, attributes: dict):
    """Addes GTI attributes."""

    # GTI assessment
    gti_assessment = attributes.get('gti_assessment', {})
    gti_threat_score = gti_assessment.get('threat_score', {}).get('value')
    gti_severity = gti_assessment.get('severity', {}).get('value')
    gti_verdict = gti_assessment.get('verdict', {}).get('value')

    # Attribution
    attribution = attributes.get('attribution', {})
    malware_families = [x['family'] for x in attribution.get('malware_families', [])]
    malware_families = list(set(malware_families))
    threat_actors = attribution.get('threat_actors', [])
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


def _get_indicator_id(item: dict):
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

    attributes = item.get('attributes', {})
    context_attributes = item.get('context_attributes', {})

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
        },
        'id': indicator_id,
        'detections': str(detection_ratio),
        'origin': context_attributes.get('origin'),
        'sources': ', '.join([f'[{x["type"]}] {x["label"]}'
                              for x in context_attributes.get('sources', [])]) or None,
    }

    indicator_obj = _add_gti_attributes(indicator_obj, attributes)
    indicator_obj = _add_dedicated_attributes(indicator_obj, attributes)

    return indicator_obj


def fetch_indicators_command(client: Client,
                             tlp_color: str = None,
                             feed_tags: list = [],
                             limit: int = 10,
                             filter_query: str = None,
                             minimum_score: int = 0,
                             fetch_command: bool = False) -> list[dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
        filter_query (string): filter query
    Returns:
        Indicators.
    """
    indicators = []

    raw_indicators = client.fetch_indicators(
        limit, filter_query, fetch_command=fetch_command)

    # extract values from iterator
    for item in raw_indicators:
        try:
            indicator_obj = _create_indicator(item)
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
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    limit = int(args.get('limit', 10))
    filter_query = args.get('filter')
    minimum_score = int(params.get('feedMinimumGTIScore', 80))

    indicators = fetch_indicators_command(
        client,
        tlp_color,
        feed_tags,
        limit,
        filter_query,
        minimum_score,
    )

    human_readable = tableToMarkdown(
        'Indicators from Google Threat Intelligence IoC Stream Feed:',
        indicators,
        headers=[
            'id',
            'detections',
            'origin',
            'sources',
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
    """
    Main function, parses params and runs command functions
    """
    params = demisto.params()

    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    limit = int(params.get('limit', 10))
    filter_query = params.get('filter')
    minimum_score = int(params.get('feedMinimumGTIScore', 80))

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url='https://www.virustotal.com/api/v3/',
            verify=insecure,
            proxy=proxy,
            headers={
                'x-apikey': params['credentials']['password'],
                'x-tool': 'CortexGTIIoCStreamFeed',
            }
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, {}))

        elif command == 'gti-iocstream-get-indicators':
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
                                                  tlp_color,
                                                  feed_tags,
                                                  limit,
                                                  filter_query,
                                                  minimum_score,
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
