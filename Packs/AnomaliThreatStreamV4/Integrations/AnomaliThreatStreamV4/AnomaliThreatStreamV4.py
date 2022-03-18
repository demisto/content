import datetime
import traceback
from datetime import datetime

import demistomock as demisto  # noqa: F401
import emoji
from CommonServerPython import *  # noqa: F401

register_module_line('Anomali ThreatStream v3', 'start', __line__())

REPUTATION_COMMANDS = ['ip', 'domain', 'file', 'url', 'threatstream-email-reputation']


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

THREAT_STREAM = 'ThreatStream'
NO_INDICATORS_FOUND_MSG = 'No intelligence has been found for {searchable_value}'
DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
HEADERS = {
    'Content-Type': 'application/json'
}

IOC_ARGS_TO_INDICATOR_KEY_MAP = {
    'domain': {
        'domain': 'value',
        'dns': 'ip',
        'organization': 'org',
        'traffic_light_protocol': 'tlp',
        'geo_country': 'country',
        'creation_date': 'created_ts',
        'updated_date': 'modified_ts',
        'registrant_name': 'meta.registrant_name',
        'registrant_email': 'meta.registrant_email',
        'registrant_phone': 'meta.registrant_phone'
    },
    'url': {
        'url': 'value',
        'asn': 'asn',
        'organization': 'org',
        'geo_country': 'country',
        'traffic_light_protocol': 'tlp'
    },
    'ip': {
        'ip': 'value',
        'asn': 'asn',
        'geo_latitude': 'latitude',
        'geo_longitude': 'longitude',
        'geo_country': 'country',
        'traffic_light_protocol': 'tlp'
    },
    'file': {
        'organization': 'org',
        'traffic_light_protocol': 'tlp'
    }
}

DEFAULT_INDICATOR_MAPPING = {
    'asn': 'ASN',
    'value': 'Address',
    'country': 'Country',
    'type': 'Type',
    'modified_ts': 'Modified',
    'confidence': 'Confidence',
    'status': 'Status',
    'org': 'Organization',
    'source': 'Source',
    'tags': 'Tags',
}

FILE_INDICATOR_MAPPING = {
    'modified_ts': 'Modified',
    'confidence': 'Confidence',
    'status': 'Status',
    'source': 'Source',
    'subtype': 'Type',
    'tags': 'Tags'
}


INDICATOR_EXTENDED_MAPPING = {
    'Value': 'value',
    'ID': 'id',
    'IType': 'itype',
    'Confidence': 'confidence',
    'Country': 'country',
    'Organization': 'org',
    'ASN': 'asn',
    'Status': 'status',
    'Tags': 'tags',
    'Modified': 'modified_ts',
    'Source': 'source',
    'Type': 'type',
    'Severity': 'severity'
}

RELATIONSHIPS_MAPPING = {
    'ip': [
        {
            'name': EntityRelationship.Relationships.RESOLVES_TO,
            'raw_field': 'rdns',
            'entity_b_type': FeedIndicatorType.Domain
        },
        {
            'name': EntityRelationship.Relationships.INDICATOR_OF,
            'raw_field': 'meta.maltype',
            'entity_b_type': 'Malware'
        }
    ],
    'domain': [
        {
            'name': EntityRelationship.Relationships.RESOLVED_FROM,
            'raw_field': 'ip',
            'entity_b_type': FeedIndicatorType.IP
        },
        {
            'name': EntityRelationship.Relationships.INDICATOR_OF,
            'raw_field': 'meta.maltype',
            'entity_b_type': 'Malware'
        }
    ],
    'url': [
        {
            'name': EntityRelationship.Relationships.RESOLVED_FROM,
            'raw_field': 'ip',
            'entity_b_type': FeedIndicatorType.IP
        },
        {
            'name': EntityRelationship.Relationships.INDICATOR_OF,
            'raw_field': 'meta.maltype',
            'entity_b_type': 'Malware'
        }
    ],
    'file': [
        {
            'name': EntityRelationship.Relationships.INDICATOR_OF,
            'raw_field': 'meta.maltype',
            'entity_b_type': 'Malware'
        }
    ],
    'email': [
        {
            'name': EntityRelationship.Relationships.INDICATOR_OF,
            'raw_field': 'meta.maltype',
            'entity_b_type': 'Malware'
        }
    ]
}

''' HELPER FUNCTIONS '''


class Client(BaseClient):
    def __init__(self, base_url, user_name, api_key, verify, proxy, reliability, should_create_relationships):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200, 201, 202))
        self.reliability = reliability
        self.should_create_relationships = should_create_relationships
        self.credentials = {
            'username': user_name,
            'api_key': api_key
        }

    def http_request(self, method,
                     url_suffix, params=None,
                     data=None, headers=None,
                     files=None, json=None,
                     resp_type='json'):
        """
            A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        params = params or {}
        params.update(self.credentials)
        res = super()._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            data=data,
            json_data=json,
            files=files,
            resp_type=resp_type,
            error_handler=self.error_handler,
        )
        return res

    def error_handler(self, res: requests.Response):
        """
        Error handler to call by super().http_request in case an error was occurred
        """
        # Handle error responses gracefully
        if res.status_code == 401:
            raise DemistoException(
                f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials."
            )
        elif res.status_code == 204:
            return f"Empty Response - {res}"
        elif res.status_code in {404}:
            command = demisto.command()
            if command in [
                "threatstream-get-model-description",
                "threatstream-get-indicators-by-model",
                "threatstream-get-analysis-status",
                "threatstream-analysis-report",
                "threatstream-whitelist-remove-entry",
            ]:
                # in order to prevent raising en error in case model/indicator/report was not found
                return
            else:
                raise DemistoException(f"{THREAT_STREAM} - The resource was not found.")

        raise DemistoException(
            f"{THREAT_STREAM} - Error in API call {res.status_code} - {res.text}"
        )


class DBotScoreCalculator:
    """
    Class for DBot score calculation based on thresholds and confidence
    """

    def __init__(self, params: Dict):
        self.instance_defined_thresholds = {
            DBotScoreType.IP: arg_to_number(params.get('ip_threshold')),
            DBotScoreType.URL: arg_to_number(params.get('url_threshold')),
            DBotScoreType.FILE: arg_to_number(params.get('file_threshold')),
            DBotScoreType.DOMAIN: arg_to_number(params.get('domain_threshold')),
            DBotScoreType.EMAIL: arg_to_number(params.get('email_threshold')),

        }

    def calculate_score(self, ioc_type: str, indicator, threshold=None):
        """
            Calculate the DBot score according the indicator's confidence and thresholds if exist
        """
        # in case threshold was defined in the instance or passed as argument
        # we have only two scores levels - malicious or good
        # if threshold wasn't defined we have three score levels malicious suspicious and good
        confidence = indicator.get('confidence', Common.DBotScore.NONE)
        defined_threshold = threshold or self.instance_defined_thresholds.get(ioc_type)
        if defined_threshold:
            return Common.DBotScore.BAD if confidence >= defined_threshold else Common.DBotScore.GOOD
        else:
            if confidence > DEFAULT_MALICIOUS_THRESHOLD:
                return Common.DBotScore.BAD
            if confidence > DEFAULT_SUSPICIOUS_THRESHOLD:
                return Common.DBotScore.SUSPICIOUS
            else:
                return Common.DBotScore.GOOD


def find_worst_indicator(indicators):
    """
        Sorts list of indicators by confidence score and returns one indicator with the highest confidence.
        In case the indicator has no confidence value, the indicator score is set to 0 (NONE).
    """
    indicators.sort(key=lambda ioc: ioc.get('confidence', Common.DBotScore.NONE), reverse=True)
    return indicators[0]


def prepare_args(args, command, params):
    # removing empty keys that can be passed from playbook input
    args = {k: v for (k, v) in args.items() if v}

    # special handling for ip, domain, file, url and threatstream-email-reputation commands
    if command in REPUTATION_COMMANDS:
        default_include_inactive = params.get('include_inactive', False)
        include_inactive = argToBoolean(args.pop('include_inactive', default_include_inactive))
        args['status'] = "active,inactive" if include_inactive else "active"
    if 'threshold' in args:
        args['threshold'] = arg_to_number(args['threshold'])

    # special handling for threatstream-get-indicators
    if 'indicator_severity' in args:
        args['meta.severity'] = args.pop('indicator_severity', None)
    if 'tags_name' in args:
        args['tags.name'] = args.pop('tags_name', None)
    if 'indicator_value' in args:
        args['value'] = args.pop('indicator_value', None)

    return args


def get_tags(indicator):
    """
        Return list of the indicator's tags threat_type and maltype
    """
    tags = []

    for key in ['meta.maltype', 'threat_type']:
        val = demisto.get(indicator, key)
        if val:
            tags.append(val)

    indicator_tags = indicator.get('tags', [])
    if indicator_tags:
        tags.extend([str(tag.get('name', '')) for tag in indicator_tags])

    return tags


def search_worst_indicator_by_params(client: Client, params):
    """
        Generic function that searches for indicators from ThreatStream by given query string.
        Returns indicator with the highest confidence score.
    """
    indicators_data = client.http_request("Get", "v2/intelligence/", params=params)

    if not indicators_data['objects']:
        return None

    return find_worst_indicator(indicators_data['objects'])


def get_generic_threat_context(indicator, indicator_mapping=DEFAULT_INDICATOR_MAPPING):
    """
        Receives indicator and builds new dictionary from values that were defined in
        DEFAULT_INDICATOR_MAPPING keys and adds the Severity key with indicator severity value.
    """

    context = {indicator_mapping[k]: v for (k, v) in indicator.items()
               if k in indicator_mapping.keys()}
    context['Tags'] = get_tags(indicator)
    context['Severity'] = demisto.get(indicator, 'meta.severity') or 'low'
    return context


def parse_network_elem(element_list, context_prefix):
    """
        Parses the network elements list and returns a new dictionary.
    """
    return list(map(lambda e: {
        F'{context_prefix}Source': e.get('src', ''),
        F'{context_prefix}Destination': e.get('dst', ''),
        F'{context_prefix}Port': e.get('dport', ''),
    }, element_list))


def parse_network_lists(network):
    """
        Parses the network part that was received from sandbox report json.
        In each list, only sublist of 10 elements is taken.
    """
    hosts = [{'Hosts': h} for h in network.get('hosts', [])[:10]]

    if 'packets' in network:
        network = network['packets']

    udp_list = parse_network_elem(network.get('udp', [])[:10], 'Udp')
    icmp_list = parse_network_elem(network.get('icmp', [])[:10], 'Icmp')
    tcp_list = parse_network_elem(network.get('tcp', [])[:10], 'Tcp')
    http_list = parse_network_elem(network.get('http', [])[:10], 'Http')
    https_list = parse_network_elem(network.get('https', [])[:10], 'Https')
    network_result = udp_list + icmp_list + tcp_list + http_list + https_list + hosts

    return network_result


def parse_info(info):
    """
        Parses the info part that was received from sandbox report json
    """
    info.update(info.pop('machine', {}))
    parsed_info = {
        'Category': info.get('category', '').title(),
        'Started': info.get('started', ''),
        'Completed': info.get('ended', ''),
        'Duration': info.get('duration', ''),
        'VmName': info.get('name', ''),
        'VmID': info.get('id', '')

    }
    return parsed_info


def parse_indicators_list(iocs_list):
    """
        Parses the indicator list and returns dictionary that will be set to context.
    """
    iocs_context = []
    for indicator in iocs_list:
        if indicator.get('type', '') == 'md5':
            indicator['type'] = indicator.get('subtype', '')

        indicator['severity'] = demisto.get(indicator, 'meta.severity') or 'low'

        tags = indicator.get('tags') or []
        indicator['tags'] = ",".join(tag.get('name', '') for tag in tags)

        iocs_context.append({key: indicator.get(ioc_key)
                             for (key, ioc_key) in INDICATOR_EXTENDED_MAPPING.items()})

    return iocs_context


def build_model_data(
    model,
    name,
    is_public,
    tlp,
    tags,
    intelligence,
    description,
    import_sessions,
    circles,
    s_type,
    associations,
    association_type,
    malware_types,
    execution_platforms,
    is_family,
    source,
    file_id,
    source_created,
    source_modified,
):
    """
    Builds data dictionary that is used in Threat Model creation/update request.
    """
    if model == "tipreport":
        description_field_name = "body"
    elif model == "signature":
        description_field_name = "notes"
    else:
        description_field_name = "description"
    if s_type == "Snort":
        s_type = 1
    elif s_type == "YARA":
        s_type = 2
    elif s_type == "CybOX":
        s_type = 3
    elif s_type == "OpenIOC":
        s_type = 4
    elif s_type == "ClamAV":
        s_type = 5
    elif s_type == "Suricata":
        s_type = 6
    elif s_type == "Bro":
        s_type = 7
    elif s_type == "CarbonBlackQuery":
        s_type = 8
    elif s_type == "Custom":
        s_type = 9
    else:
        s_type is None

    if malware_types:
        malware_types = malware_types.split(",")

    data = {
        k: v
        for (k, v) in (
            ("name", name),
            ("tlp", tlp),
            (description_field_name, description),
            ("s_type", s_type),
            ("source", source),
            ("malware_types", malware_types),
            ("is_family", is_family),
            ("execution_platforms", execution_platforms),
            ("source_created", source_created),
            ("source_modified", source_modified),
            ("associations", associations),
            ("association_type", association_type)
        )
        if v
    }

    if tags:
        data["tags"] = (
            tags if isinstance(tags, list) else [t.strip() for t in tags.split(",")]
        )
    if intelligence:
        data["intelligence"] = (
            intelligence
            if isinstance(intelligence, list)
            else [i.strip() for i in intelligence.split(",")]
        )
    if import_sessions:
        data["import_sessions"] = (
            import_sessions
            if isinstance(import_sessions, list)
            else [i.strip() for i in import_sessions.split(",")]
        )
    if circles:
        data["circles"] = (
            circles
            if isinstance(circles, list)
            else [i.strip() for i in circles.split(",")]
        )
    if malware_types:
        malware_types = malware_types.split(",")
    return data


def create_relationships(client: Client, indicator, ioc_type, relation_mapper):
    relationships: List[EntityRelationship] = []

    if not client.should_create_relationships:
        return relationships

    for relation in relation_mapper:
        entity_b = demisto.get(indicator, relation['raw_field'])
        if entity_b:
            relationships.append(EntityRelationship(entity_a=indicator['value'],
                                                    entity_a_type=ioc_type,
                                                    name=relation['name'],
                                                    entity_b=entity_b,
                                                    entity_b_type=relation['entity_b_type'],
                                                    source_reliability=client.reliability,
                                                    brand=THREAT_STREAM))
    return relationships


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client):
    """
    Performs basic get request to get item samples
    """
    client.http_request('GET', 'v2/intelligence/', params=dict(limit=1))
    return 'ok'


def ips_reputation_command(client: Client, score_calc: DBotScoreCalculator, ip, status, threshold=None):
    results = []  # type: ignore
    ips = argToList(ip, ',')
    for single_ip in ips:
        results.append(get_ip_reputation(client, score_calc, single_ip, status, threshold))
    return results


def get_ip_reputation(client: Client, score_calc: DBotScoreCalculator, ip, status, threshold=None):
    """
        Checks the reputation of given ip from ThreatStream and
        returns the indicator with highest confidence score.
    """
    # get the indicator
    params = {
        'value': ip,
        'type': DBotScoreType.IP,
        'status': status,
        'limit': 0,
    }
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return NO_INDICATORS_FOUND_MSG.format(searchable_value=ip)

    # Convert the tags objects into s string for the human readable.
    threat_context = get_generic_threat_context(indicator)
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'IP reputation for: {ip}', threat_context | dict(Tags=tags_csv))

    # build relationships
    relationships = create_relationships(
        client,
        indicator,
        FeedIndicatorType.IP,
        RELATIONSHIPS_MAPPING.get('ip'),
    )

    # create the IP instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('ip')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key) for (arg, key) in args_to_keys_map.items()}
    dbot_score = Common.DBotScore(
        ip,
        DBotScoreType.IP,
        THREAT_STREAM,
        score=score_calc.calculate_score(DBotScoreType.IP, indicator, threshold),
        reliability=client.reliability,
    )

    ip_indicator = Common.IP(
        dbot_score=dbot_score,
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        relationships=relationships,
        **kwargs
    )

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.IP',
        outputs_key_field='Address',
        indicator=ip_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    )


def domains_reputation_command(client: Client, score_calc: DBotScoreCalculator, domain, status, threshold=None):
    """
        Wrapper function for get_domain_reputation.
    """
    results = []  # type: ignore
    domains = argToList(domain, ',')
    for single_domain in domains:
        results.append(get_domain_reputation(client, score_calc, single_domain, status, threshold))
    return results


def get_domain_reputation(client: Client, score_calc: DBotScoreCalculator, domain, status, threshold=None):
    """
        Checks the reputation of given domain from ThreatStream and
        returns the indicator with highest confidence score.
    """
    # get the indicator
    params = dict(value=domain, type=DBotScoreType.DOMAIN, status=status, limit=0)
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return NO_INDICATORS_FOUND_MSG.format(searchable_value=domain)

    # Convert the tags objects into s string for the human readable.
    threat_context = get_generic_threat_context(indicator)
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'Domain reputation for: {domain}', threat_context | dict(Tags=tags_csv))

    # build relationships
    relationships = create_relationships(
        client,
        indicator,
        FeedIndicatorType.Domain,
        RELATIONSHIPS_MAPPING.get('domain'),
    )

    # create the Domain instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('domain')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key) for (arg, key) in args_to_keys_map.items()}
    geo_location = f"{indicator.get('latitude')},{indicator.get('longitude')}" if indicator.get('latitude') else None
    dbot_score = Common.DBotScore(
        domain,
        DBotScoreType.DOMAIN,
        THREAT_STREAM,
        reliability=client.reliability,
        score=score_calc.calculate_score(DBotScoreType.DOMAIN, indicator, threshold),
    )
    domain_indicator = Common.Domain(
        dbot_score=dbot_score,
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        geo_location=geo_location,
        relationships=relationships,
        **kwargs,
    )

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Domain',
        outputs_key_field='Address',
        indicator=domain_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    )


def files_reputation_command(client: Client, score_calc: DBotScoreCalculator, file, status, threshold=None):
    """
        Wrapper function for get_file_reputation.
    """
    results = []
    files = argToList(file, ',')
    for single_file in files:
        results.append(get_file_reputation(client, score_calc, single_file, status, threshold))
    return results


def get_file_reputation(client: Client, score_calc: DBotScoreCalculator, file, status, threshold=None):
    """
        Checks the reputation of given hash of the file from ThreatStream and
        returns the indicator with highest severity score.
    """
    # get the indicator
    params = dict(value=file, type="md5", status=status, limit=0)
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return NO_INDICATORS_FOUND_MSG.format(searchable_value=file)

    # save the hash value under the hash type key
    threat_context = get_generic_threat_context(indicator, indicator_mapping=FILE_INDICATOR_MAPPING)
    file_type: str = indicator.get('subtype')  # The real type of the hash is in subtype field.
    if file_type:
        threat_context[file_type] = indicator.get('value')

    # Convert the tags objects into s string for the human readable.
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'File reputation for: {file}', threat_context | dict(Tags=tags_csv))

    # build relationships
    relationships = create_relationships(
        client,
        indicator,
        FeedIndicatorType.File,
        RELATIONSHIPS_MAPPING.get('file'),
    )

    # create the File instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('file')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key) for (arg, key) in args_to_keys_map.items()}
    if file_type:
        kwargs[file_type.lower()] = threat_context[file_type]

    dbot_score = Common.DBotScore(
        file,
        DBotScoreType.FILE,
        THREAT_STREAM,
        reliability=client.reliability,
        score=score_calc.calculate_score(DBotScoreType.FILE, indicator, threshold),
    )

    file_indicator = Common.File(
        dbot_score=dbot_score,
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        relationships=relationships,
        **kwargs,
    )

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.{Common.File.CONTEXT_PATH}',
        indicator=file_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    )


def urls_reputation_command(client: Client, score_calc: DBotScoreCalculator, url, status, threshold=None):
    """
        Wrapper function for get_url_reputation.
    """
    results = []
    urls = argToList(url, ',')
    for single_url in urls:
        results.append(get_url_reputation(client, score_calc, single_url, status, threshold))
    return results


def get_url_reputation(client: Client, score_calc: DBotScoreCalculator, url, status, threshold=None):
    """
        Checks the reputation of given url address from ThreatStream and
        returns the indicator with highest confidence score.
    """

    # get the indicator
    params = dict(value=url, type=DBotScoreType.URL, status=status, limit=0)
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return NO_INDICATORS_FOUND_MSG.format(searchable_value=url)

    # Convert the tags objects into s string for the human readable.
    threat_context = get_generic_threat_context(indicator)
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'URL reputation for: {url}', threat_context | dict(Tags=tags_csv))

    # build relationships
    relationships = create_relationships(
        client,
        indicator,
        FeedIndicatorType.URL,
        RELATIONSHIPS_MAPPING.get('url'),
    )

    # create the URL instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('url')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key_in_indicator) for (arg, key_in_indicator) in args_to_keys_map.items()}

    dbot_score = Common.DBotScore(
        url,
        DBotScoreType.URL,
        THREAT_STREAM,
        reliability=client.reliability,
        score=score_calc.calculate_score(DBotScoreType.URL, indicator, threshold),
    )

    url_indicator = Common.URL(
        dbot_score=dbot_score,
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        relationships=relationships,
        **kwargs,
    )

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.URL',
        outputs_key_field='Address',
        indicator=url_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    )


def get_email_reputation(client: Client, score_calc: DBotScoreCalculator, email, status, threshold=None):
    """
        Checks the reputation of given email address from ThreatStream and
        returns the indicator with highest confidence score.
    """
    params = dict(value=email, type=DBotScoreType.EMAIL, status=status, limit=0)
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return NO_INDICATORS_FOUND_MSG.format(searchable_value=email)

    threat_context = get_generic_threat_context(indicator)
    threat_context['Email'] = threat_context.pop('Address')
    threat_context.pop('ASN', None)
    threat_context.pop('Organization', None)
    threat_context.pop('Country', None)

    # Convert the tags objects into s string for the human readable.
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'Email reputation for: {email}', threat_context | dict(Tags=tags_csv))

    # build relationships
    relationships = create_relationships(
        client,
        indicator,
        FeedIndicatorType.Email,
        RELATIONSHIPS_MAPPING.get('email'),
    )

    dbot_score = Common.DBotScore(
        email,
        DBotScoreType.EMAIL,
        THREAT_STREAM,
        reliability=client.reliability,
        score=score_calc.calculate_score(DBotScoreType.EMAIL, indicator, threshold),
    )

    # create the EMAIL instance
    email_indicator = Common.EMAIL(
        dbot_score=dbot_score,
        address=threat_context['Email'],
        relationships=relationships,
    )

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.EmailReputation',
        outputs_key_field='Email',
        indicator=email_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    )


def get_passive_dns(client: Client, value, type=DBotScoreType.IP, limit=50):
    """
        Receives value and type of indicator and returns
        enrichment data for domain or ip.
    """
    dns_results = client.http_request("GET", F"v1/pdns/{type}/{value}/").get('results', None)

    if not dns_results:
        return f'No Passive DNS enrichment data found for {value}'

    dns_results = dns_results[:int(limit)]
    output = camelize(dns_results, delim='_')
    human_readable = tableToMarkdown(f'Passive DNS enrichment data for: {value}', output)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.PassiveDNS',
        readable_output=human_readable,
        outputs=output,
        raw_response=dns_results,
    )


def import_ioc_with_approval(
    client: Client,
    import_type,
    import_value,
    confidence="50",
    classification="private",
    threat_type="malware",
    severity="low",
    ip_mapping=None,
    domain_mapping=None,
    url_mapping=None,
    email_mapping=None,
    md5_mapping=None,
    trustedcircles=None,
    tags=None,
    tag_type=None,
    tlp=None,
    association_info=None,
    source_created=None,
    source_modified=None,
    intelligence_source=None,
    expiration_ts=None
):
    """
    Imports indicators data to ThreatStream.
    The data can be imported using one of three import_types: data-text (plain-text),
    file-id of uploaded file to war room or URL.
    """
    tags = tags if isinstance(tags, list) else tags.split(",")

    files = None
    uploaded_file = None

    if tag_type == "red":
        data = {
            k: v
            for (k, v) in (
                ("confidence", confidence),
                ("classification", classification),
                ("threat_type", threat_type),
                ("severity", severity),
                ("tags", json.dumps([{"name": t, "tlp": "red"} for t in tags])),
                ("trustedcircles", trustedcircles),
                ("tlp", tlp),
                ("association_info", association_info),
                ("source_created", source_created),
                ("source_modified", source_modified),
                ("intelligence_source", intelligence_source),
                ("expiration_ts", expiration_ts)
            )
            if v
        }
    else:
        data = {
            k: v
            for (k, v) in (
                ("confidence", confidence),
                ("classification", classification),
                ("threat_type", threat_type),
                ("severity", severity),
                ("tags", json.dumps([{"name": t, "tlp": "white"} for t in tags])),
                ("trustedcircles", trustedcircles),
                ("tlp", tlp),
                ("association_info", association_info),
                ("source_created", source_created),
                ("source_modified", source_modified),
                ("intelligence_source", intelligence_source),
                ("expiration_ts", expiration_ts)
            )
            if v
        }
    if import_type == "file-id":
        try:
            # import_value will be entry id of uploaded file to war room
            file_info = demisto.getFilePath(import_value)
        except Exception:
            return_error(f"Entry {import_value} does not contain a file.")

        uploaded_file = open(file_info["path"], "rb")
        files = {"file": (file_info["name"], uploaded_file)}
    else:
        data[import_type] = import_value
    # in case import_type is not file-id, http_requests will receive None as files

    res = client.http_request("POST", "v1/intelligence/import/", data=data, files=files)

    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()
    # checking that response contains success key

    if res.get("success", False):
        imported_id = res.get("import_session_id", "")
        readable_output = f"The data was imported successfully. The ID of imported job is: {imported_id}"
        return CommandResults(
            outputs_prefix=f"{THREAT_STREAM}.Import.ImportID",
            outputs_key_field="ImportID",
            outputs=imported_id,
            readable_output=readable_output,
            raw_response=res,
        )
    else:
        raise DemistoException(
            "The data was not imported. Check if valid arguments were passed"
        )


def get_model_list(client: Client, model, limit="50"):
    """
        Returns list of Threat Model that was specified. By default limit is set to 50 results.
        Possible values for model are : actor, campaign, incident, signature, ttp, vulnerability, tipreport
    """
    # if limit=0 don't put to context
    params = dict(limit=limit, skip_intelligence="true", skip_associations="true")
    model_list = client.http_request("GET", F"v1/{model}/", params=params).get('objects', None)

    if not model_list:
        return f'No Threat Model {model.title()} found.'

    model_type = model.title()
    models_context = [
        {
            'Name': threat_model.get('name'),
            'ID': threat_model.get('id'),
            'CreatedTime': threat_model.get('created_ts'),
            'Type': model_type
        }
        for threat_model in model_list
    ]

    # in case that no limit was passed, the stage of set to context is skipped
    readable_output = tableToMarkdown(f"List of {model.title()}s", models_context)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.List',
        outputs_key_field='ID',
        outputs=models_context if limit != '0' else None,
        readable_output=readable_output,
        raw_response=model_list
    )


def get_model_description(client: Client, model, id):
    """
        Returns a description of Threat Model as html file to the war room.
    """
    params = dict(skip_intelligence="true", skip_associations="true")
    response = client.http_request("GET", F"v1/{model}/{id}", params=params, resp_type='response')
    if response.status_code == 404:
        return f'No description found for Threat Model {model.title()} with id {id}'

    description = response.json()
    if model == 'signature':
        description = description.get('notes', '')
    elif model == 'tipreport':
        description = description.get('body', '')
    else:
        description = description.get('description', None)

    return fileResult(F"{model}_{id}.html", description.encode(encoding='UTF-8'))


def get_model(client: Client, model, id):
    """
        Returns a description of Threat Model as html file to the war room.
    """
    params = dict(skip_intelligence="true", skip_associations="true")
    response = client.http_request("GET", F"v1/{model}/{id}", params=params)

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.ThreatModel',
        outputs_key_field=["ModelID", "ModelType"],
        outputs=response,
        readable_output=tableToMarkdown(
            f"Threat Model {model} with id {id}", response),
        raw_response=response
    )


def get_iocs_by_model(client: Client, model, id, limit="20"):
    """
    Returns list of indicators associated with specific Threat Model by model id.
    """
    params = dict(limit=limit)
    model_type = model.title()
    response = client.http_request(
        "GET", f"v1/{model}/{id}/intelligence/", params=params, resp_type="response"
    )

    if response.status_code == 404:
        return f"No indicators found for Threat Model {model_type} with id {id}"

    iocs_list = response.json().get("objects", None)
    model_type = model.title()
    iocs_context = parse_indicators_list(iocs_list)

    outputs = {"ModelType": model_type, "ModelID": id, "Indicators": iocs_context}
    readable_output = tableToMarkdown(
        f"Indicators list for Threat Model {model_type} with id {id}", iocs_context
    )
    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Model",
        outputs_key_field=["ModelID", "ModelType"],
        outputs=outputs,
        readable_output=readable_output,
        raw_response=iocs_list,
    )


def create_model(
    client: Client,
    model,
    name,
    is_public=False,
    tlp=None,
    tags=None,
    intelligence=None,
    description=None,
    import_sessions=None,
    circles=None,
    s_type=None,
    associations=None,
    association_type=None,
    malware_types=None,
    execution_platforms=None,
    is_family=True,
    source=None,
    file_id=None,
    source_created=None,
    source_modified=None,
):
    """
    Creates Threat Model with basic parameters.
    """

    if file_id:
        files = None
        try:
            file_info = demisto.getFilePath(file_id)
        except Exception:
            return_error(f"File {file_id} does not exist.")

        files = {
            "file": (
                file_info["name"],
                open(file_info["path"], "rb"),
                "application/pdf",
                {"do_import": True, "add_to_attachment": True},
            )
        }
        data = build_model_data(
            model,
            name,
            is_public,
            tlp,
            tags,
            intelligence,
            description,
            import_sessions,
            circles,
            s_type,
            associations,
            association_type,
            malware_types,
            execution_platforms,
            is_family,
            source,
            file_id,
            source_created,
            source_modified,
        )

        model_id = client.http_request(
            "POST", f"v1/{model}/", data=json.dumps(data)
        ).get("id", "")
        bulletin_id = model_id

        res = client.http_request(
            "POST", f"v1/{model}/{bulletin_id}/upload_file/", files=files
        )

        attach_file_to_bulletin(client, bulletin_id, file_id, model_type=model)
    else:
        data = build_model_data(
            model,
            name,
            is_public,
            tlp,
            tags,
            intelligence,
            description,
            import_sessions,
            circles,
            s_type,
            associations,
            association_type,
            malware_types,
            execution_platforms,
            is_family,
            source,
            file_id,
            source_created,
            source_modified,
        )

        model_id = client.http_request(
            "POST", f"v1/{model}/", data=json.dumps(data)
        ).get("id", None)

    if associations:
        add_associations(client, model_id, model, association_type, association_ids=associations)
    if model_id:
        return get_iocs_by_model(client, model, model_id, limit="50")
    else:
        raise DemistoException(
            f"{model.title()} Threat Model was not created. Check the input parameters"
        )


def update_model(
    client: Client,
    model,
    model_id,
    name=None,
    is_public=False,
    tlp=None,
    tags=None,
    intelligence=None,
    description=None,
    import_sessions=None,
    circles=None,
    s_type=None,
    associations=None,
    association_type=None,
    source=None,
    malware_types=None,
    execution_platforms=None,
    is_family=True,
    source_created=None,
    source_modified=None,
    file_id=None
):
    """
    Updates a ThreatStream model with parameters. In case one or more optional parameters are
    defined, the previous data is overridden.
    """
    data = build_model_data(
        model,
        name,
        is_public,
        tlp,
        tags,
        intelligence,
        description,
        import_sessions,
        circles,
        s_type,
        associations,
        association_type,
        source,
        malware_types,
        execution_platforms,
        is_family,
        source_created,
        source_modified,
        file_id
    )
    client.http_request("PATCH", f"v1/{model}/{model_id}/", data=json.dumps(data))
    if associations:
        add_associations(client, model_id, model, association_type, association_ids=associations)

    return get_iocs_by_model(client, model, model_id, limit="50")


def get_supported_platforms(client: Client, sandbox_type="default"):
    """
        Returns list of supported platforms for premium sandbox or default sandbox.
    """
    platform_data = client.http_request("GET", "v1/submit/parameters/")
    result_key = 'platform_choices' if sandbox_type == 'default' else 'premium_platform_choices'
    available_platforms = platform_data.get(result_key, [])

    if not available_platforms:
        return f'No supported platforms found for {sandbox_type} sandbox'

    output = camelize(available_platforms)
    outputs_prefix = 'DefaultPlatforms' if sandbox_type == 'default' else 'PremiumPlatforms'
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.{outputs_prefix}',
        outputs=output,
        readable_output=tableToMarkdown(f'Supported platforms for {sandbox_type} sandbox', output),
        raw_response=platform_data
    )


def get_submission_status(client: Client, report_id, output_as_command_result=True):
    """
        Returns the sandbox submission status. If status is not received in report_info
        then status is set to done. Receives boolean flag that indicates if result should be as command result.
        By default the output boolean is set to True.
    """
    response = client.http_request("GET", F"v1/submit/{report_id}/", resp_type='response')

    if response.status_code == 404:
        return f'No report found with id {report_id}'

    report_info = response.json()
    status = report_info.get('status', "done")
    verdict = report_info.get('verdict', '').title()
    platform = report_info.get('platform', '')

    if output_as_command_result:
        report_outputs = {'ReportID': report_id, 'Status': status, 'Platform': platform, 'Verdict': verdict}
        readable_output = tableToMarkdown(f'The analysis status for id {report_id}', report_outputs)
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Analysis',
            outputs_key_field='ReportID',
            outputs=report_outputs,
            readable_output=readable_output,
            raw_response=report_info,
        )
    else:
        return status, verdict


def file_name_to_valid_string(file_name):
    """
        Demoji the file name if it's contain emoji
    """
    if emoji.emoji_count(file_name):  # type: ignore
        return emoji.demojize(file_name)  # type: ignore
    return file_name


def submit_report(client: Client, submission_type, submission_value, submission_classification="private",
                  report_platform="WINDOWS7",
                  premium_sandbox="false", detail=None):
    """
        Detonates URL or file that was uploaded to war room to ThreatStream sandbox.
    """

    data = {
        'report_radio-classification': submission_classification,
        'report_radio-platform': report_platform,
        'use_premium_sandbox': premium_sandbox,
    }
    if detail:
        data['detail'] = detail

    uploaded_file = None
    files = None
    if submission_type == 'file':
        # submission_value should be entry id of uploaded file in war room
        try:
            file_info = demisto.getFilePath(submission_value)
        except Exception:
            raise DemistoException(f'{THREAT_STREAM} - Entry {submission_value} does not contain a file.')

        uploaded_file = open(file_info['path'], 'rb')
        file_name = file_name_to_valid_string(file_info.get('name'))
        files = {'report_radio-file': (file_name, uploaded_file)}
    else:
        data['report_radio-url'] = submission_value

    submit_res = client.http_request("POST", "v1/submit/new/", data=data, files=files)
    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()

    if argToBoolean(submit_res.get('success', 'false')):
        report_info = submit_res['reports'][report_platform]
        report_id = report_info['id']
        report_status, _ = get_submission_status(client, report_id, False)

        report_outputs = {'ReportID': report_id, 'Status': report_status, 'Platform': report_platform}
        readable_output = tableToMarkdown(f'The submission info for {submission_value}', report_outputs)
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Analysis',
            outputs=report_outputs,
            readable_output=readable_output,
            raw_response=report_info,
        )
    else:
        raise DemistoException(f'The submission of {submission_value} failed')


def get_report(client: Client, report_id):
    """
        Returns the report from ThreatStream sandbox by id.
    """
    response = client.http_request('GET', f'v1/submit/{report_id}/report', resp_type='response')
    if response.status_code == 404:
        return f'No report found with id {report_id}'

    report = response.json()
    report_results = report.get('results', {})
    if report_results:
        info = parse_info(report_results.get('info', {}))
        info['ReportID'] = report_id
        _, info['Verdict'] = get_submission_status(client, report_id, False)
        readable_output = tableToMarkdown(f'Report {report_id} analysis results', info)

        # ignore 'networks' from the readable output
        info['Network'] = parse_network_lists(report_results.get('network', {}))
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Analysis',
            outputs_key_field='ReportID',
            outputs=info,
            readable_output=readable_output,
            raw_response=report
        )


def add_tag_to_model(client: Client, model_id, tags, model="intelligence", tag_type="red"):
    """
        Adds tag to specific Threat Model. By default is set to intelligence (indicators).
    """
    tags = argToList(tags)

    data = {
        'tags': [{'name': t, 'tlp': tag_type} for t in tags]
    }

    res = client.http_request("POST", F"v1/{model}/{model_id}/tag/", data=json.dumps(data))

    if argToBoolean(res.get('success', 'false')):
        return f'Added successfully tags: {tags} to {model} with {model_id}'
    else:
        raise DemistoException(f'Failed to add {tags} to {model} with {model_id}')


def get_indicators(client: Client, **kwargs):
    """
        Returns filtered indicators by parameters from ThreatStream.
        By default the limit of indicators result is set to 20.
    """
    limit = kwargs['limit'] = int(kwargs.get('limit', 20))
    offset = kwargs['offset'] = 0
    url = "v2/intelligence/"
    if 'query' in kwargs:
        url += f"?q={kwargs.pop('query')}"
    iocs_list = client.http_request("GET", url, params=kwargs).get('objects', None)
    if not iocs_list:
        return 'No indicators found from ThreatStream'

    iocs_context = parse_indicators_list(iocs_list)
    # handle the issue that the API does not return more than 1000 indicators.
    if limit > 1000:
        while len(iocs_context) < limit:
            offset += len(iocs_list)
            kwargs['limit'] = limit
            kwargs['offset'] = offset
            iocs_list = client.http_request("GET", url, params=kwargs).get('objects', None)
            if iocs_list:
                iocs_context.extend(parse_indicators_list(iocs_list))
            else:
                break

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Indicators',
        outputs=iocs_context,
        readable_output=tableToMarkdown("The indicators results", iocs_context),
        raw_response=iocs_list
    )


def get_indicators_count(client: Client, **kwargs):
    """
        Returns filtered indicators by parameters from ThreatStream.
        By default the limit of indicators result is set to 20.
    """

    url = "v2/intelligence/"
    if 'query' in kwargs:
        url += f"?q={kwargs.pop('query')}"

    iocs_list = client.http_request("GET", url, params=kwargs).get('meta')

    count = 0
    count = int(iocs_list.get('total_count'))

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.IndicatorCount',
        outputs=count,
        readable_output=tableToMarkdown(f'Indicator count: {count}', iocs_list),
        raw_response=iocs_list
    )


def approve_import(client: Client, import_id):

    res = client.http_request("PATCH", F"v1/importsession/{import_id}/approve_all")

    status = res.get('status')

    if status == 'done' or status == 'approving':

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ApproveImportStatus',
            outputs=status,
            readable_output=tableToMarkdown(f'Import job {import_id} was successfully approved', res),
            raw_response=res
        )
    if status == 'approved':

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ApproveImportStatus',
            outputs=status,
            readable_output=tableToMarkdown(f'Import job {import_id} was previously approved', res),
            raw_response=res
        )
    else:

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ApproveImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} was NOT successfully approved', res),
            raw_response=res
        )


def get_import_status(client: Client, import_id):

    # make the call to the API
    res = client.http_request("GET", F"v1/importsession/{import_id}")

    # review the results
    status = res.get('status')

    if status == 'done':

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} is ready for review', res),
            raw_response=res
        )
    elif status == 'processing':

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} is still processing', res),
            raw_response=res
        )
    elif status == 'approved':

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} has been approved', res),
            raw_response=res
        )
    elif status == 'errors':
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} has errors', res),
            raw_response=res
        )
    elif status == 'deleted':

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} has been rejected', res),
            raw_response=res
        )
    else:

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportStatus',
            outputs=res.get('status'),
            readable_output=tableToMarkdown(f'Import job {import_id} is not yet ready for review', res),
            raw_response=res
        )


def publish_bulletin(client: Client, bulletin_id, modeltype, trustedcircles=None,):

    # This function will set a Threat Bulletin to the 'Published' state, with the 'private' visibility

    if trustedcircles is None:
        json_to_post = {'is_public': False}

    else:

        trustedcircles = trustedcircles if isinstance(trustedcircles, list) else trustedcircles.split(',')

        # this JSON object sets the visibility to Private (set to 'true' if you wish to publish to the Anomali Community)
        # NOTE: the 'json.loads' call is needed so the 'false' is properly recognized
        json_to_post = {'is_public': False, 'trustedcircles': trustedcircles}

    # make the PATCH call to the API

    res = client.http_request("PATCH", F"v1/{modeltype}/{bulletin_id}/publish/", data=json.dumps(json_to_post))

    success = res.get('success')
    if success is True:
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.PublishedSuccess',
            outputs=res.get('success'),
            readable_output=f'{modeltype} {bulletin_id} published successfully',
            raw_response=res
        )
    else:
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.PublishedSuccess',
            outputs=res.get('success'),
            readable_output=f'{modeltype} {bulletin_id} was not published',
            raw_response=res
        )


def attach_file_to_bulletin(client: Client, bulletin_id, file_id, model_type):
    """
    To attach given file to given threat bulletin
    """
    files = None
    uploaded_file = None

    try:
        file_info = demisto.getFilePath(file_id)
    except Exception:
        return_error(f"File {file_id} does not exist.")

    uploaded_file = open(file_info["path"], "rb")
    files = {"attachment": (file_info["name"], uploaded_file)}

    file_name = file_info["name"]

    if model_type == "tipreport":
        data = {"filename": file_info["name"]}
        res = client.http_request(
            "POST", f"v1/tipreport/{bulletin_id}/attachment/", data=data, files=files
        )
        url = res.get("signed_url")
    else:
        data = {
            "filename": file_info["name"],
            "title": file_info["name"],
            "r_type": "A",
        }
        res = client.http_request(
            "POST",
            f"v1/{model_type}/{bulletin_id}/external_reference/attachment/",
            data=data,
            files=files,
        )
        url = res.get("s3_url")
    if uploaded_file:
        uploaded_file.close()

    fileid = res.get("id")

    outputs = {"url": url, "fileid": fileid}

    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.FileAttachment",
        outputs_key_field=["url", "fileid"],
        outputs=outputs,
        readable_output=f"{file_name} successfully attached to {model_type} {bulletin_id}",
        raw_response=res,
    )


def attach_reference_to_bulletin(client: Client, bulletin_id, url, reference_name, model_type):
    """
    To add a reference url to bulletin
    """

    if model_type == "tipreport":
        return CommandResults(
            readable_output="URL Reference is not supported for tipreport"
        )
    else:
        data = json.dumps({"external_references": [{"url": url, "title": reference_name, "r_type": "U"}]})
        res = client.http_request(
            "PATCH",
            f"v1/{model_type}/{bulletin_id}/",
            data=data,
        )

    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.FileReference",
        outputs=res,
        readable_output=f"{url} successfully attached to {model_type} {bulletin_id}",
        raw_response=res,
    )


def change_indicator_status(client: Client, indicator_id, status):
    """
    To modify status of given observable/indicator
    """

    data = {"id": indicator_id, "status": status}

    iocs_list = client.http_request(
        "PATCH", f"v2/intelligence/{indicator_id}/", data=json.dumps(data)
    )

    if not iocs_list:
        return "Indicator {indicator_id} not found!"

    iocs_context = iocs_list
    value = iocs_list.get("value")

    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Indicators",
        outputs=iocs_context,
        readable_output=tableToMarkdown(
            f"Indicator {value} Status Change to {status} was successful", iocs_context
        ),
        raw_response=iocs_list,
    )


def edit_indicator(
    client: Client,
    indicator_id,
    itype=None,
    tlp=None,
    confidence=None,
    severity=None,
    status=None,
    expiration_date=None,
):
    """
    To edit attributes of given observable/indicator
    """

    if expiration_date == "Never":
        expiration_date = "9999-12-31T00:00:00.000Z"
    elif expiration_date is not None:
        date = ""
        date = str(datetime.now() + timedelta(days=int(expiration_date)))
        date = date[: len(date) - 3]
        date = date.replace(" ", "T")
        date += "Z"
        expiration_date = date

    data = {
        "id": indicator_id,
        "itype": itype,
        "tlp": tlp,
        "confidence": confidence,
        "severity": severity,
        "status": status,
        "expiration_ts": expiration_date,
    }

    # if false positive or inactive, expiration date option shouldn't be selected
    if (status == "falsepos" or status == "inactive") and expiration_date is not None:
        return_outputs(
            "Note: Changes to the expiration date can only be applied to active observables. Inactive Observables or False Positives will remain unchanged."
        )
        expiration_date is None

    # identify keys with None values
    empty = []
    for entry in data:
        if data.get(entry) is None:
            empty.append(entry)
    # clean data of key empty values
    for i in empty:
        data.pop(i)

    if confidence is not None:
        data["confidence"] = int(confidence)

    res = client.http_request(
        "PATCH", f"v2/intelligence/{indicator_id}/", data=json.dumps(data)
    )
    value = res.get("value")

    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Indicators",
        outputs=res,
        readable_output=tableToMarkdown(
            f"Indicator {value} was edited successfully", res
        ),
        raw_response=res,
    )


def whitelist_get_recent_entries(client: Client):
    """
        To return a list of your 10 most recently added whitelist entries
    """

    res = client.http_request("GET", "v1/orgwhitelist/", headers=HEADERS).get('objects', None)

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Whitelist',
        outputs=res,
        readable_output=tableToMarkdown('Recent Whitelist Entries', res),
        raw_response=res
    )


def whitelist_add_entry(client: Client, value_type, value, notes):
    """
        To add an entry to your import whitelist
    """

    data = {
        'whitelist': [{
            'value_type': value_type,
            'value': value,
            'notes': notes
        }]
    }

    res = client.http_request("POST", "v1/orgwhitelist/bulk/", headers=HEADERS, data=json.dumps(data))

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Whitelist',
        outputs=res,
        readable_output=tableToMarkdown('Whitelist entry added', res),
        raw_response=res
    )


def whitelist_add_entries_from_csv(client: Client, file_id):
    """
        To add entries to your import whitelist from a CSV file
    """

    files = None

    try:
        file_info = demisto.getFilePath(file_id)
    except Exception:
        filename = file_info['name']
        return_error(F"File {filename} does not exist.")

    files = {
        'file': (file_info['name'], open(file_info['path'], 'rb'), None, {'remove_existing': False})
    }

    res = client.http_request("POST", "v1/orgwhitelist/upload/", files=files)

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Whitelist',
        outputs=res,
        readable_output=tableToMarkdown('Whitelist Add Entry From CSV successful', res),
        raw_response=res
    )


def whitelist_export(client: Client, file_format):
    """
        To export whitelist in CSV or JSON format
    """

    res = client.http_request("GET", F"v1/orgwhitelist/?showNote=True&format={file_format}", resp_type='response')

    demisto.results(fileResult(F"whitelist.{file_format}", res.content))

    return CommandResults(
        readable_output='Whitelist Export successful'
    )


def whitelist_remove_entry(client: Client, entry_id):
    """
        To remove an entry from whitelist
    """

    client.http_request("DELETE", F"v1/orgwhitelist/{entry_id}/", resp_type='text')

    return CommandResults(
        readable_output='Whitelist Remove Entry successful'
    )


def whitelist_edit_entry_note(client: Client, entry_id, note):
    """
        To edit the note associated with an import whitelist entry
    """

    data = {
        'notes': note
    }

    res = client.http_request("PATCH", F"v1/orgwhitelist/{entry_id}/", data=json.dumps(data), resp_type='text')

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Whitelist',
        outputs=res,
        readable_output=tableToMarkdown('Whitelist Edit Entry Note successful', res),
        raw_response=res
    )


def comment_bulletin(client: Client, bulletin_id, title, comment, tlp, model_type):
    """
        To comment on given threat bulletin
    """

    data = {
        'title': title,
        'body': comment,
        'tlp': tlp
    }

    res = client.http_request("POST", F"v1/{model_type}/{bulletin_id}/comment/", data=json.dumps(data))

    outputs = {
        'Body': comment,
        'ModelID': bulletin_id,
        'Title': title,
        'TLP': res.get('tlp'),
        'CommentID': res.get('id'),
        'Created': res.get('created_ts'),
        'ModelType': model_type
    }

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.BulletinComment',
        outputs_key_field=['ModelID', 'ModelType'],
        outputs=outputs,
        readable_output=tableToMarkdown(f'Comment on {model_type} {bulletin_id} successful', outputs),
        raw_response=res
    )


def comment_indicator(client: Client, value, comment, tlp):
    """
        To comment on given indicator
    """

    data = {
        'comment': comment,
        'tlp': tlp
    }

    res = client.http_request("POST", F"v2/intelligence/comments/?value={value}", data=json.dumps(data))

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.IndicatorComment',
        outputs=res,
        readable_output=tableToMarkdown(f'Comment on {value} successful', res),
        raw_response=res
    )


def include_indicator(client: Client, import_id, ioc_ids=None):
    """
        Prints the excluded indicators along with their ID, then asks for indicator IDs to be included
    """
    if ioc_ids is None:

        # get list of current rejected indicators
        ioc_res = client.http_request("GET", F"v1/importsession/{import_id}/rejects/?limit=1000")

        # print relevant information about indicators in a human readable format
        colnames = ["id", "value", "itype", "confidence", "message"]

        contents = []
        table = []
        table.append(colnames)
        indicators = ioc_res.get("objects")

        for indicator in indicators:
            obj = {}
            tableRow = []
            for i in range(0, len(colnames)):
                obj[colnames[i]] = str(indicator.get(colnames[i]))
                tableRow.append(str(indicator.get(colnames[i])))
            contents.append(obj)
            table.append(tableRow)

        outputs = {
            'ContentsFormat': formats['json'],
            'Contents': contents
        }
        OutputTable = contents

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportRejectedIndicators',
            outputs=outputs,
            readable_output=tableToMarkdown(
                'Call !threatstream-include-indicator with ioc_ids argument so excluded IDs can be included (input as comma seperated)', OutputTable),
            raw_response=ioc_res
        )

    else:

        # parse user input
        ioc_list = ioc_ids.split(",")

        # build the URL to force these items into TS
        api_url = F"v1/importsession/{import_id}/add_rejects/?ids="

        # make a comma separated list of IOC IDs (as that is needed to complete the URL)
        ioc_ids = ""
        for i in ioc_list:
            ioc_ids = ioc_ids + str(i) + ", "

        # final URL is now ready to go (the [:-2} removes the final ', ' from the end of the string)
        api_url = api_url + str(ioc_ids[:-2])

        # Patch to Anomali
        response = client.http_request("PATCH", api_url)

        status = response.get('status')

        # check the response
        if status == 'done':
            return CommandResults(
                outputs_prefix=f'{THREAT_STREAM}.IncludeRejectedIndicators',
                outputs=response,
                readable_output=tableToMarkdown(f'Indicator {ioc_ids} was successfully moved to included', response),
                raw_response=response
            )
        else:
            return CommandResults(
                outputs_prefix=f'{THREAT_STREAM}.IncludeRejectedIndicators',
                outputs=response,
                readable_output=tableToMarkdown('Include Indicator unsuccessful', response),
                raw_response=response
            )


def exclude_indicator(client: Client, import_id, ioc_ids=None):
    """
        Prints the included indicators along with their ID, then asks for indicator IDs to be excluded
    """

    # get list of current included indicators
    ioc_res = client.http_request("GET", F"v1/importsession/{import_id}/intelligence/?import_session_id={import_id}&limit=1000")

    has_rejected_ids = False
    indicators = ioc_res.get("objects")
    if indicators[0].get("id") is None:
        has_rejected_ids = True

    if ioc_ids is None:

        # print relevant information about indicators in a human readable format
        if has_rejected_ids:
            colnames = ["rejected_id", "value", "itype", "confidence", "message"]
        else:
            colnames = ["id", "value", "itype", "confidence", "message"]

        contents = []
        table = []
        table.append(colnames)

        for indicator in indicators:
            obj = {}
            tableRow = []
            for i in range(0, len(colnames)):
                obj[colnames[i]] = str(indicator.get(colnames[i]))
                tableRow.append(str(indicator.get(colnames[i])))
            contents.append(obj)
            table.append(tableRow)

        outputs = {
            'ContentsFormat': formats['json'],
            'Contents': contents
        }
        OutputTable = contents

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ExcludeIndicators',
            outputs=outputs,
            readable_output=tableToMarkdown(
                'Call !threatstream-exclude-indicator with ioc_ids argument so included IDs can be excluded (input as comma seperated)', OutputTable),
            raw_response=ioc_res
        )

    else:

        # parse user input
        ioc_list = ioc_ids.split(",")

        # build the URL to exclude indicators
        api_url = ""
        if has_rejected_ids:
            api_url = F"v1/importsession/{import_id}/delete_selected/?create_rejected=true&ids=&rejected_ids="
        else:
            api_url = F"v1/importsession/{import_id}/delete_selected/?create_rejected=true&ids="

        # make a comma separated list of IOC IDs (as that is needed to complete the URL)
        ioc_ids = ""
        for i in ioc_list:
            ioc_ids = ioc_ids + str(i) + ", "

        # final URL is now ready to go (the [:-2} removes the final ', ' from the end of the string)
        if has_rejected_ids:
            api_url = api_url + str(ioc_ids[:-2])
        else:
            api_url = api_url + str(ioc_ids[:-2]) + "&rejected_ids="

        # Delete to Anomali
        response = client.http_request("DELETE", api_url)
        # check the response
        status = response.get('status')
        # check the response
        if status == 'done':
            return CommandResults(
                outputs_prefix=f'{THREAT_STREAM}.ExcludeIndicators',
                outputs=response,
                readable_output=tableToMarkdown(f'Indicator {ioc_ids} was successfully moved to excluded', response),
                raw_response=response
            )
        else:
            return CommandResults(
                outputs_prefix=f'{THREAT_STREAM}.ExcludeIndicators',
                outputs=response,
                readable_output=tableToMarkdown('Exclude Indicator unsuccessful', response),
                raw_response=response
            )


def add_tags_to_import_session(client: Client, import_id, tag_names, tlps):
    """
        To add tag(s) to an import session
    """

    data = {"tags": []}

    tagnames_list = tag_names.split(",")
    tlps_list = tlps.split(",")
    tags = []

    for i in range(len(tagnames_list)):
        tag_obj = {}
        tag_obj["name"] = tagnames_list[i]
        tag_obj["tlp"] = tlps_list[i]

        tags.append(tag_obj)

    data["tags"] = tags

    res = client.http_request("POST", F"v1/importsession/{import_id}/intelligence/tag/", data=json.dumps(data))

    if res.get('objects'):
        indicatorcount = res.get('meta').get('total_count')
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.AddTags',
            outputs=indicatorcount,
            readable_output=f'Applied {tags} to {indicatorcount} indicators in {import_id}',
            raw_response=res
        )
    else:
        return CommandResults(
            readable_output='Unable to add tags',
            raw_response=res
        )


def recent_investigations(client: Client):

    res = client.http_request("GET", "v1/investigation/?order_by=-created_ts").get('objects')

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigations',
        outputs=res,
        readable_output=tableToMarkdown('Recent Investigations', res),
        raw_response=res
    )


def get_investigation(client: Client, investigation_id):

    res = client.http_request("GET", F"v1/investigation/{investigation_id}/")

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigations',
        outputs=res,
        readable_output=tableToMarkdown(f'Investigation {investigation_id}', res),
        raw_response=res
    )


def force_apply_tags(client: Client, import_id, ioc_ids=None):
    """
        Prints the excluded indicators along with their ID, then asks for indicator IDs to force apply tags
    """
    if ioc_ids is None:

        # get list of current rejected indicators
        ioc_res = client.http_request("GET", F"v1/importsession/{import_id}/rejects/?limit=1000")

        # print relevant information about indicators in a human readable format
        colnames = ["id", "value", "itype", "confidence", "message"]

        contents = []
        table = []
        table.append(colnames)
        indicators = ioc_res.get("objects")

        for indicator in indicators:
            obj = {}
            tableRow = []
            for i in range(0, len(colnames)):
                obj[colnames[i]] = str(indicator.get(colnames[i]))
                tableRow.append(str(indicator.get(colnames[i])))
            contents.append(obj)
            table.append(tableRow)

        outputs = {
            'ContentsFormat': formats['json'],
            'Contents': contents
        }
        OutputTable = contents

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ImportRejectedIndicators',
            outputs=outputs,
            readable_output=tableToMarkdown(
                'Call !threatstream-include-indicator with ioc_ids argument so excluded IDs can have tags forced (input as comma seperated)', OutputTable),
            raw_response=ioc_res
        )

    else:

        # parse user input
        ioc_list = ioc_ids.split(",")

        # build the URL to force these items into TS
        api_url = F"v1/importsession/{import_id}/force_apply_tags/?ids="

        # make a comma separated list of IOC IDs (as that is needed to complete the URL)
        ioc_ids = ""
        for i in ioc_list:
            ioc_ids = ioc_ids + str(i) + ", "

        # final URL is now ready to go (the [:-2} removes the final ', ' from the end of the string)
        api_url = api_url + str(ioc_ids[:-2])

        # Patch to Anomali
        response = client.http_request("PATCH", api_url)

        status = response.get('status')

        # check the response
        if status == 'done':
            return CommandResults(
                outputs_prefix=f'{THREAT_STREAM}.ForceApplyTags',
                outputs=response,
                readable_output=tableToMarkdown(f'Indicator {ioc_ids} successfully forced tags ', response),
                raw_response=response
            )
        else:
            return CommandResults(
                outputs_prefix=f'{THREAT_STREAM}.IncludeRejectedIndicators',
                outputs=response,
                readable_output=tableToMarkdown(f'Indicator {ioc_ids} unsuccessfully forced tags', response),
                raw_response=response
            )


def create_investigation(
    client: Client,
    associations=None,
    assignee_id=None,
    assignee_type=None,
    description=None,
    name=None,
    priority=None,
    tlp=None,
    status=None,
    circles=None,
    tags=None,
):
    """
    To create an investigation with associations
    """

    if associations:
        associations = associations.split(",")

        # input for associations example: <r_ type>,<r_id>,<add_related_indicators>,<r_ type>,<r_id>,<add_related_indicators>,etc

        elements = []

        for i in range(0, len(associations), 3):
            obj = {}
            obj["r_type"] = associations[i]
            obj["r_id"] = associations[i + 1]
            obj["add_related_indicators"] = associations[i + 2]

            elements.append(obj)

        data = {
            'assignee_id': assignee_id,
            'assignee_type': assignee_type,
            'description': description,
            'name': name,
            'priority': priority,
            'tlp': tlp,
            'circles': circles,
            'status': status,
            'tags': tags,
            'elements': elements
        }

        if tags:
            data['tags'] = tags if isinstance(tags, list) else [t.strip() for t in tags.split(',')]

        # add associations to elements key in data

        res = client.http_request("POST", "v1/investigation/", data=json.dumps(data))

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Investigations',
            outputs=res,
            readable_output=tableToMarkdown('Create Investigation with Associations successful', res),
            raw_response=res
        )
    else:
        """
        To create an investigation without associations
    """

        data = {
            'assignee_id': assignee_id,
            'assignee_type': assignee_type,
            'description': description,
            'name': name,
            'priority': priority,
            'tlp': tlp,
            'circles': circles,
            'status': status,
            'tags': tags
        }

        if tags:
            data['tags'] = tags if isinstance(tags, list) else [t.strip() for t in tags.split(',')]

        res = client.http_request("POST", "v1/investigation/", data=json.dumps(data))

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Investigations',
            outputs=res,
            readable_output=tableToMarkdown('Create Investigation without Associations successful', res),
            raw_response=res
        )


def update_investigation(
    client: Client,
    investigation_id,
    associations=None,
    assignee_id=None,
    assignee_type=None,
    description=None,
    name=None,
    priority=None,
    tlp=None,
    status=None,
    circles=None,
    tags=None,
):

    data = {}

    if associations:
        associations = associations.split(",")

        # input for associations example: <r_ type>,<r_id>,<add_related_indicators>,<r_ type>,<r_id>,<add_related_indicators>,etc

        elements = []

        for i in range(0, len(associations), 3):
            obj = {}
            obj["r_type"] = associations[i]
            obj["r_id"] = associations[i + 1]
            obj["add_related_indicators"] = associations[i + 2]

            elements.append(obj)

        args = [assignee_id, assignee_type, description, name, priority, tlp, circles, status, tags, elements]

        arg_names = [
            "assignee_id",
            "assignee_type",
            "description",
            "name",
            "priority",
            "tlp",
            "circles",
            "status",
            "tags",
            "elements",
        ]

        for i in range(len(args)):
            if str(args[i]) != "None":
                if "," in str(args[i]):
                    args[i] = args[i].split(",")
                elif str(args[i]).lower() == "true":
                    args[i] = True
                elif str(args[i]).lower() == "false":
                    args[i] = False
                data[arg_names[i]] = args[i]
        if tags:
            data['tags'] = tags if isinstance(tags, list) else [t.strip() for t in tags.split(',')]

        res = client.http_request("PATCH", F"v1/investigation/{investigation_id}/", data=json.dumps(data))
    else:

        args = [assignee_id, assignee_type, description, name, priority, tlp, circles, status, tags]

        arg_names = ["assignee_id", "assignee_type", "description", "name", "priority", "tlp", "circles", "status", "tags"]

        for i in range(len(args)):
            if str(args[i]) != "None":
                if "," in str(args[i]):
                    args[i] = args[i].split(",")
                elif str(args[i]).lower() == "true":
                    args[i] = True
                elif str(args[i]).lower() == "false":
                    args[i] = False
                data[arg_names[i]] = args[i]
        if tags:
            data['tags'] = tags if isinstance(tags, list) else [t.strip() for t in tags.split(',')]

        res = client.http_request("PATCH", F"v1/investigation/{investigation_id}/", data=json.dumps(data))

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigations',
        outputs=res,
        readable_output=tableToMarkdown('Update Investigation Description successful', res),
        raw_response=res
    )


def delete_investigation(client: Client, investigation_id):

    res = client.http_request("DELETE", F"v1/investigation/{investigation_id}/", resp_type='text')

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigations',
        outputs=res,
        readable_output=tableToMarkdown(f'{investigation_id} deleted successfully!', res),
        raw_response=res
    )


def get_ioc_sightings(client: Client, ioc_value, limit=25, offset=0, ioc_type=None):
    """
        To get myattacks/sightings data for given ioc
    """
    if ioc_type == 'domain':
        # make the API call
        res = client.http_request(
            "GET", F"v1/myattacks/?attacker_hostname={ioc_value}&limit={limit}&offset={offset}&order_by=-modified_ts")
    elif ioc_type == 'ip':
        res = client.http_request(
            "GET", F"v1/myattacks/?attacker_address={ioc_value}&limit={limit}&offset={offset}&order_by=-modified_ts")
    elif ioc_type == 'email':
        res = client.http_request(
            "GET", F"v1/myattacks/?source_email={ioc_value}&limit={limit}&offset={offset}&order_by=-modified_ts")
    else:
        return CommandResults(
            readable_output='IOC Type not found'
        )

    if res.get('meta').get('total_count') == 0:
        return CommandResults(
            readable_output=f'No sightings found for {ioc_value}',
            raw_response=res
        )
    else:
        # process the results

        outputs = res.get('objects')

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.MyAttacks',
            outputs=outputs,
            readable_output=tableToMarkdown(f'{ioc_value} sightings retrieved', outputs),
            raw_response=res
        )


def add_myattacks_sighting(
    client: Client,
    reported_ts=None,
    count=None,
    attack_type=None,
    attacker_address=None,
    attacker_countrycode=None,
    attacker_hostname=None,
    device_source=None,
    outcome=None,
    request_url=None,
    source_email=None,
    tags=None,
    target_address=None,
    target_hostname=None,
    target_port=None,
    transport_protocol=None,
):
    """
    To add a sighting to given ioc
    """

    data = {
        "count": int(count),
        "reported_ts": reported_ts,
        "transport_protocol": transport_protocol,
        "attack_type": attack_type,
        "attacker_address": attacker_address,
        "attacker_countrycode": attacker_countrycode,
        "attacker_hostname": attacker_hostname,
        "device_source": device_source,
        "outcome": outcome,
        "request_url": request_url,
        "source_email": source_email,
        "tags": tags,
        "target_address": target_address,
        "target_hostname": target_hostname,
        "target_port": target_port,
        "transport_protocol": transport_protocol
    }

    # make the API call
    res = client.http_request(
        "POST", "v1/myattacks/", data=json.dumps(data), resp_type="text"
    )

    return_outputs("Add MyAttacks Sighting successful")
    return CommandResults(
        readable_output='sighting added successfully',
    )


def report_false_positive(client: Client, ioc_id, comment, reason):
    """
        To report an observable as false positive
    """

    data = {
        'intelligence': ioc_id,
        'reason': reason,
        'comment': comment
    }

    res = client.http_request("POST", "v1/falsepositive/report/", data=json.dumps(data))

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.FalsePositiveReport',
        outputs=res,
        readable_output=tableToMarkdown(f'{ioc_id} reported successfully!', res),
        raw_response=res
    )


def create_rule(
    client: Client,
    name,
    keywords,
    match_observables=False,
    match_reportedfiles=False,
    match_signatures=False,
    match_tips=False,
    match_vulnerabilities=False,
    actors=None,
    campaigns=None,
    create_investigation=None,
    exclude_impacts=None,
    exclude_notify_org_whitelisted=False,
    exclude_notify_owner_org=False,
    incidents=None,
    malware=None,
    match_impacts=None,
    signatures=None,
    tags=None,
    tips=None,
    ttps=None,
    vulnerabilities=None,
    tlp="red",
    org_id=None,
    notify_me=False
):
    """
    To create a rule
    """

    keywords = keywords.split(",")
    tags = tags if isinstance(tags, list) else tags.split(",")

    data = {
        "name": name,
        "keywords": keywords,
        "keyword": keywords[0]
    }

    args = [
        argToBoolean(match_observables),
        argToBoolean(match_reportedfiles),
        argToBoolean(match_signatures),
        argToBoolean(match_tips),
        argToBoolean(match_vulnerabilities),
        actors,
        campaigns,
        argToBoolean(create_investigation),
        exclude_impacts,
        argToBoolean(exclude_notify_org_whitelisted),
        argToBoolean(exclude_notify_owner_org),
        incidents,
        malware,
        match_impacts,
        signatures,
        tips,
        ttps,
        vulnerabilities,
        argToBoolean(notify_me)
    ]

    arg_names = [
        "match_observables",
        "match_reportedfiles",
        "match_signatures",
        "match_tips",
        "match_vulnerabilities",
        "actors",
        "campaigns",
        "create_investigation",
        "exclude_impacts",
        "exclude_notify_org_whitelisted",
        "exclude_notify_owner_org",
        "incidents",
        "malware",
        "match_impacts",
        "signatures",
        "tips",
        "ttps",
        "vulnerabilities",
        "notify_me",
    ]

    # NOTE: any arg that takes a boolean must be of type boolean, not string

    for i in range(len(args)):
        if args[i] is not None and args[i] is not False:
            if "," in str(args[i]):
                args[i] = args[i].split(",")
            elif str(args[i]).lower() == "true":
                args[i] = True
            data[arg_names[i]] = args[i]

    if tags is not None:
        data["tags"] = [{"name": t, "tlp": tlp, "org_id": org_id} for t in tags]

    res = client.http_request("POST", "v1/rule/", json=data)

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Rule',
        outputs=res,
        readable_output=tableToMarkdown(f'{name} rule created successfully!', res),
        raw_response=res
    )


def get_rules(client: Client):
    """
        To get list of 20 most recently configured rules
    """

    res = client.http_request("GET", "v1/rule/").get('objects')

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Rule',
        outputs=res,
        readable_output=tableToMarkdown('The latest 20 rules', res),
        raw_response=res
    )


def update_rule(
    client: Client,
    rule_id,
    name=None,
    keywords=None,
    match_observables=None,
    match_reportedfiles=None,
    match_signatures=None,
    match_tips=None,
    match_vulnerabilities=None,
    actors=None,
    campaigns=None,
    create_investigation=None,
    exclude_impacts=None,
    exclude_notify_org_whitelisted=None,
    exclude_notify_owner_org=None,
    incidents=None,
    malware=None,
    match_impacts=None,
    signatures=None,
    tags=None,
    tips=None,
    ttps=None,
    vulnerabilities=None,
    tlp=None,
    org_id=None,
    notify_me=None
):
    """
    To update an existing rule
    """

    data = {
    }

    args = [
        name,
        keywords,
        match_observables,
        match_reportedfiles,
        match_signatures,
        match_tips,
        match_vulnerabilities,
        actors,
        campaigns,
        create_investigation,
        exclude_impacts,
        exclude_notify_org_whitelisted,
        exclude_notify_owner_org,
        incidents,
        malware,
        match_impacts,
        signatures,
        tips,
        ttps,
        vulnerabilities,
        tlp,
        org_id,
        notify_me
    ]

    arg_names = [
        "name",
        "keywords",
        "match_observables",
        "match_reportedfiles",
        "match_signatures",
        "match_tips",
        "match_vulnerabilities",
        "actors",
        "campaigns",
        "create_investigation",
        "exclude_impacts",
        "exclude_notify_org_whitelisted",
        "exclude_notify_owner_org",
        "incidents",
        "malware",
        "match_impacts",
        "signatures",
        "tips",
        "ttps",
        "vulnerabilities",
        "tlp",
        "org_id",
        "notify_me"
    ]

    for i in range(len(args)):
        if args[i] is not None:
            if "," in str(args[i]):
                args[i] = args[i].split(",")
            elif str(args[i]).lower() == "true":
                args[i] = True
            elif str(args[i]).lower() == "false":
                args[i] = False
            data[arg_names[i]] = args[i]

    if tags is not None:
        tags = tags if isinstance(tags, list) else tags.split(",")
        data["tags"] = [{"name": t, "tlp": tlp, "org_id": org_id} for t in tags]

    res = client.http_request("PATCH", F"v1/rule/{rule_id}/", data=json.dumps(data))

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Rule',
        outputs=res,
        readable_output=tableToMarkdown(f'{rule_id} rule updated successfully!', res),
        raw_response=res
    )


def delete_rule(client: Client, rule_id):
    """
    To delete a rule given the rule ID
    """
    res = client.http_request("DELETE", F"v1/rule/?id__in={rule_id}", resp_type='text')

    return CommandResults(
        readable_output=f'{rule_id} rule deleted successfully'
    )


def threat_model_search(
    client: Client,
    limit=50,
    offset=0,
    value=None,
    model_type=None,
    general_options=None,
    tlp=None,
    date_last_updated=None,
    tags=None,
    publication_status=None,
    visibility=None,
    streams_id=None,
    source_id=None,
    assignee_id=None,
    owner_id=None,
    org_id=None
):
    """
    To search
    for actors, campaigns, incidents,
    signatures, ttps, and vulnerabilities
    """

    data = {
        "limit": limit,
        "offset": offset,
        "order_by": "-modified_ts",
        "model_type": "actor,campaign,incident,signature,tipreport,ttp,malware,attackpattern,courseofaction,identity,infrastructure,intrusionset,tool,vulnerability",
    }

    args = [
        value,
        model_type,
        tlp,
        tags,
        publication_status,
        streams_id,
        source_id,
        assignee_id,
        owner_id,
    ]
    arg_names = [
        "value",
        "model_type",
        "tlp",
        "tags",
        "publication_status",
        "feed_id",
        "trusted_circle_ids",
        "assignee_user_id",
        "owner_user_id",
    ]

    # no options specified will get the 50 most recently modified threat models
    if all([arg is None for arg in args]):

        res = client.http_request("GET", "v1/threat_model_search/", data=json.dumps(data)).get('objects')

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ThreatModelSearch',
            outputs=res,
            readable_output=tableToMarkdown('Search completed successfully!', res),
            raw_response=res
        )

    else:  # else some options are specified

        # decode and format data for api call
        if general_options == "Show Only My Organization" and org_id is not None:
            data['organization_id'] = org_id
        elif general_options == "Show Only Open Source Threat Models":
            data['trusted_circle_ids'] = 146
        elif general_options == "Show Only My Organization" and org_id is None:
            return 'Organization ID required, please re-run command with org_id value'

        if date_last_updated == "Last 30 Days":
            date = str(datetime.now() - timedelta(days=30))
            date = date[:len(date) - 3]
            date = date.replace(" ", "T")
            date += "Z"
            date_last_updated = date
            data['modified_ts__gte'] = date_last_updated
        elif date_last_updated == "Last 90 Days":
            date = str(datetime.now() - timedelta(days=90))
            date = date[:len(date) - 3]
            date = date.replace(" ", "T")
            date += "Z"
            date_last_updated = date
            data['modified_ts__gte'] = date_last_updated
        elif date_last_updated == "This year":
            date = str(datetime.now().year)
            date = date + "-01-01T04:00:00Z"
            date_last_updated = date
            data['modified_ts__gte'] = date_last_updated
        elif date_last_updated is not None:
            data['modified_ts__gte'] = date_last_updated

        if visibility == "Anomali Community":
            data['is_public'] = True
        elif visibility == "My Organization":
            data['is_public'] = False
        elif visibility == "Anomali Community,My Organization" or visibility == "My Organization,Anomali Community":
            data['is_public'] = 'true, false'

        for i in range(len(args)):
            if args[i] is not None:
                data[arg_names[i]] = args[i]

        res = client.http_request("GET", "v1/threat_model_search/", data=json.dumps(data)).get('objects')

        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.ThreatModelSearch',
            outputs=res,
            readable_output=tableToMarkdown('Search completed successfully!', res),
            raw_response=res
        )


def get_import_sessions(client: Client, limit=1000, status=None):
    """
    To get a list of import sessions in ready to review status
    """

    # default limit of 1000, gets the first 1000 ready to reveiw import sessions

    res = client.http_request("GET", F"v1/importsession/?limit={limit}&status__in={status}").get('objects')

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.ImportSession',
        outputs=res,
        readable_output=tableToMarkdown('Import search completed successfully!', res),
        raw_response=res
    )


def get_rule_by_id(client: Client, rule_id=None):
    """
    To get rule by id
    """

    res = client.http_request("GET", F"v1/rule/{rule_id}/")

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Rule',
        outputs=res,
        readable_output=tableToMarkdown(f'Rule {rule_id}', res),
        raw_response=res
    )


def get_rule_matches(client: Client, rule_id=None, limit=50):
    """
        To get rule by id
    """

    res = client.http_request(
        "GET", F"v1/rulematch/?limit={limit}&offset=0&order_by=-created_ts&rule_id={rule_id}&status__in=0,1")

    if res.get('meta').get('total_count') == 0:
        return CommandResults(
            readable_output=f'No Matches for {rule_id}!',
            raw_response=res
        )
    else:
        outputs = res.get('objects')
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Rule',
            outputs=outputs,
            readable_output=tableToMarkdown(f'Rule {rule_id} Matches', outputs),
            raw_response=res
        )


def get_trusted_circle_requests(client: Client):
    """
        To get Trusted Circle Requests to your Circles
    """

    res = client.http_request("GET", "v1/trustedcircleinvite/?limit=0&status__in=0,30")

    if res.get('meta').get('total_count') == 0:
        return CommandResults(
            readable_output='No Pending Trusted Circle Requests!',
            raw_response=res
        )
    else:
        outputs = res.get('objects')
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.TrustedCirclesRequest',
            outputs=outputs,
            readable_output=tableToMarkdown('Pending Trusted Circle Requests', outputs),
            raw_response=res
        )


def accept_trusted_circle_requests(client: Client, invite_id=None):
    """
        To get rule by id
    """

    res = client.http_request("PUT", F"v1/trustedcircleinvite/{invite_id}/accept/")

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.TrustedCirclesRequest',
        outputs=res,
        readable_output=tableToMarkdown(f'Trusted Circle Request {invite_id} approved', res),
        raw_response=res
    )


def get_trusted_circle_members(client: Client, trusted_circle_id):
    """
        To get Trusted Circle Requests to your Circles
    """

    res = client.http_request("GET", f"v1/trustedcircle/{trusted_circle_id}/members/")
    outputs = res
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.TrustedCircleMembers',
        outputs=outputs,
        readable_output=tableToMarkdown('Trusted Circle Members', outputs),
        raw_response=res
    )


def fetch_incidents(client: Client):
    """
    To get rule matches by id
    """
    fetch_time = "7 days"
    fetch_trusted_circle_requests = demisto.getParam('fetch_trusted_circle_requests')
    rule_id = demisto.getParam('rule_id')
    if fetch_trusted_circle_requests is True:
        # demisto.getLastRun() will returns an obj with the previous run in it.
        last_run = demisto.getLastRun()
        timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        if not last_run:  # if first time running
            new_last_run = {'time': parse_date_range(fetch_time, date_format=timestamp_format)[0]}
        else:
            new_last_run = last_run

        res = client.http_request("GET", "v1/trustedcircleinvite/?limit=0&status__in=0,30")

        if res.get('meta').get('total_count') == 0:
            # returning an empty list will keep the status as ok but no new incidents are created.
            dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            demisto.setLastRun({'time': dtnow})
            demisto.incidents([])
        else:
            invites = res.get('objects')
            incidents = []
            last_incident_time = datetime.strptime(new_last_run.get('time', '0'), '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
            for invite in invites:
                incident_time = datetime.strptime(invite.get('invite_timestamp'), '%Y-%m-%dT%H:%M:%S.%f').timestamp()
                if incident_time > last_incident_time:
                    orgname = invite.get("invitee_org").get("name")
                    circlename = invite.get("circle").get("name")
                    incident = {
                        "name": f'{orgname} has requested access to {circlename}',
                        "occurred": datetime.strptime(
                            invite.get("invite_timestamp"), "%Y-%m-%dT%H:%M:%S.%f"
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "rawJSON": json.dumps(invite),
                    }

                    incidents.append(incident)
            if incidents:
                dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                demisto.setLastRun({'time': dtnow})
                return demisto.incidents(incidents)
            else:
                dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                demisto.setLastRun({'time': dtnow})
                return demisto.incidents([])
    elif rule_id:
        limit = '50'
        last_run = demisto.getLastRun()
        timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        if not last_run:  # if first time running
            new_last_run = {'time': parse_date_range(fetch_time, date_format=timestamp_format)[0]}
        else:
            new_last_run = last_run

        res = client.http_request(
            "GET", F"v1/rulematch/?limit={limit}&offset=0&order_by=-created_ts&rule_id={rule_id}&status__in=0,1")

        if res.get('meta').get('total_count') == 0:
            return demisto.incidents([])
        else:
            matches = res.get('objects')
            incidents = []
            last_incident_time = datetime.strptime(new_last_run.get('time', '0'), '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
            for match in matches:
                incident_time = datetime.strptime(match.get('created_ts'), '%Y-%m-%dT%H:%M:%S.%f').timestamp()
                if incident_time > last_incident_time:
                    incident = {
                        "name": match.get("hint"),
                        "occurred": datetime.strptime(
                            match.get("created_ts"), "%Y-%m-%dT%H:%M:%S.%f"
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "rawJSON": json.dumps(match),
                    }

                    incidents.append(incident)
            if incidents:
                dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                demisto.setLastRun({'time': dtnow})
                return demisto.incidents(incidents)
            else:
                dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                demisto.setLastRun({'time': dtnow})
                return demisto.incidents([])
    else:
        dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')
        demisto.setLastRun({'time': dtnow})
        return demisto.incidents([])


def add_associations(client: Client, model_id, model, association_type, association_ids):
    """
        To create associations between threat model entities
    """
    association_ids = association_ids.split(",")

    data = {
        "ids": association_ids
    }

    res = client.http_request("POST", F"v2/{model}/{model_id}/{association_type}/bulk_add/", data=json.dumps(data))

    demisto.results(F"Added associations of type {association_type} with IDs: {association_ids}")


def delete_threat_model(client: Client, model_id, model_type):

    res = client.http_request("DELETE", F"v2/{model_type}/{model_id}/", resp_type='text')

    return CommandResults(
        readable_output=f'{model_type} with  ID: {model_id} deleted successfully!'
    )


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    LOG(f'Command being called is {command}')

    params = demisto.params()

    # init credentials
    user_name = params.get('credentials', {}).get('identifier')
    api_key = params.get('credentials', {}).get('password')
    server_url = params.get('url', '').strip('/')
    reliability = params.get('integrationReliability', DBotScoreReliability.B)

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Source Reliability parameter.")

    commands = {
        # reputation commands
        'ip': ips_reputation_command,
        'domain': domains_reputation_command,
        'file': files_reputation_command,
        'url': urls_reputation_command,
        'threatstream-email-reputation': get_email_reputation,
        'threatstream-import-indicator-with-approval': import_ioc_with_approval,
        'threatstream-get-analysis-status': get_submission_status,
        'threatstream-get-passive-dns': get_passive_dns,
        'threatstream-get-model-list': get_model_list,
        'threatstream-get-model-description': get_model_description,
        'threatstream-get-indicators-by-model': get_iocs_by_model,
        'threatstream-get-indicators': get_indicators,
        'threatstream-supported-platforms': get_supported_platforms,
        'threatstream-analysis-report': get_report,
        'threatstream-create-model': create_model,
        'threatstream-update-model': update_model,
        'threatstream-submit-to-sandbox': submit_report,
        'threatstream-add-tag-to-model': add_tag_to_model,
        'threatstream-get-indicators-count': get_indicators_count,
        'threatstream-approve-import': approve_import,
        'threatstream-get-import-status': get_import_status,
        'threatstream-publish-bulletin': publish_bulletin,
        'threatstream-attach-file-to-bulletin': attach_file_to_bulletin,
        'threatstream-change-indicator-status': change_indicator_status,
        'threatstream-edit-indicator': edit_indicator,
        'threatstream-whitelist-get-recent-entries': whitelist_get_recent_entries,
        'threatstream-whitelist-add-entry': whitelist_add_entry,
        'threatstream-whitelist-add-entries-from-csv': whitelist_add_entries_from_csv,
        'threatstream-whitelist-export': whitelist_export,
        'threatstream-whitelist-remove-entry': whitelist_remove_entry,
        'threatstream-whitelist-edit-entry-note': whitelist_edit_entry_note,
        'threatstream-comment-bulletin': comment_bulletin,
        'threatstream-comment-indicator': comment_indicator,
        'threatstream-include-indicator': include_indicator,
        'threatstream-exclude-indicator': exclude_indicator,
        'threatstream-add-tags-to-import': add_tags_to_import_session,
        'threatstream-recent-investigations': recent_investigations,
        'threatstream-get-investigation': get_investigation,
        'threatstream-force-apply-tags': force_apply_tags,
        'threatstream-create-investigation': create_investigation,
        'threatstream-update-investigation': update_investigation,
        'threatstream-delete-investigation': delete_investigation,
        'threatstream-get-ioc-sightings': get_ioc_sightings,
        'threatstream-add-myattacks-sighting': add_myattacks_sighting,
        'threatstream-report-false-positive': report_false_positive,
        'threatstream-create-rule': create_rule,
        'threatstream-get-rules': get_rules,
        'threatstream-update-rule': update_rule,
        'threatstream-delete-rule': delete_rule,
        'threatstream-threat-model-search': threat_model_search,
        'threatstream-get-import-sessions': get_import_sessions,
        'threatstream-get-rule-by-id': get_rule_by_id,
        'threatstream-get-rule-matches': get_rule_matches,
        'threatstream-get-trusted-circle-requests': get_trusted_circle_requests,
        'threatstream-accept-trusted-circle-requests': accept_trusted_circle_requests,
        'fetch-incidents': fetch_incidents,
        'threatstream-get-model': get_model,
        'threatstream-attach-reference-to-bulletin': attach_reference_to_bulletin,
        'threatstream-add-associations': add_associations,
        'threatstream-get-trusted-circle-members': get_trusted_circle_members,
        'threatstream-delete-threat-model': delete_threat_model
    }
    try:

        client = Client(
            base_url=f'{server_url}/api/',
            user_name=user_name,
            api_key=api_key,
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            reliability=reliability,
            should_create_relationships=params.get('create_relationships', True),
        )
        args = prepare_args(demisto.args(), command, params)
        if command == 'test-module':
            result = test_module(client)
        elif command in REPUTATION_COMMANDS:
            result = commands[command](client, DBotScoreCalculator(params), **args)  # type: ignore
        elif command == 'fetch-incidents':
            result = fetch_incidents(client)
        else:
            result = commands[command](client, **args)  # type: ignore

        return_results(result)

    except Exception as err:
        return_error(f'{str(err)}, traceback {traceback.format_exc()}')


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("builtins", "__builtin__", "__main__"):
    main()

register_module_line('Anomali ThreatStream v3', 'end', __line__())
