import emoji

import demistomock as demisto
from CommonServerPython import *
import traceback

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
            raise DemistoException(f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials.")
        elif res.status_code in {404}:
            command = demisto.command()
            if command in ['threatstream-get-model-description', 'threatstream-get-indicators-by-model',
                           'threatstream-get-analysis-status', 'threatstream-analysis-report']:
                # in order to prevent raising en error in case model/indicator/report was not found
                return
            else:
                raise DemistoException(f"{THREAT_STREAM} - The resource was not found.")

        raise DemistoException(F"{THREAT_STREAM} - Error in API call {res.status_code} - {res.text}")


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


def build_model_data(model, name, is_public, tlp, tags, intelligence, description):
    """
        Builds data dictionary that is used in Threat Model creation/update request.
    """
    if model == 'tipreport':
        description_field_name = 'body'
    else:
        description_field_name = 'description'
    data = {k: v for (k, v) in (('name', name), ('is_public', is_public), ('tlp', tlp),
                                (description_field_name, description)) if v}
    if tags:
        data['tags'] = tags if isinstance(tags, list) else [t.strip() for t in tags.split(',')]
    if intelligence:
        data['intelligence'] = intelligence if isinstance(intelligence, list) else [i.strip() for i in
                                                                                    intelligence.split(',')]
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


def import_ioc_with_approval(client: Client, import_type, import_value, confidence="50", classification="Private",
                             threat_type="exploit", severity="low", ip_mapping=None, domain_mapping=None,
                             url_mapping=None, email_mapping=None, md5_mapping=None):
    """
        Imports indicators data to ThreatStream.
        The data can be imported using one of three import_types: data-text (plain-text),
        file-id of uploaded file to war room or URL.
    """
    # prepare
    data = assign_params(
        classification=classification,
        confidence=int(confidence),
        ip_mapping=ip_mapping,
        domain_mapping=domain_mapping,
        url_mapping=url_mapping,
        email_mapping=email_mapping,
        md5_mapping=md5_mapping,
        threat_type=threat_type,
        severity=severity,
    )

    files = None
    uploaded_file = None
    if import_type == 'file-id':
        try:
            # import_value should be entry id of uploaded file in war room
            file_info = demisto.getFilePath(import_value)
        except Exception:
            raise DemistoException(f'{THREAT_STREAM} - Entry {import_value} does not contain a file.')

        uploaded_file = open(file_info['path'], 'rb')
        files = {'file': (file_info['name'], uploaded_file)}
    else:
        data[import_type] = import_value

    # request
    res = client.http_request("POST", "v1/intelligence/import/", data=data, files=files)

    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()

    # checking that response contains success key
    if res.get('success', False):
        imported_id = res.get('import_session_id', '')
        readable_output = f'The data was imported successfully. The ID of imported job is: {imported_id}'
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Import.ImportID',
            outputs_key_field='ImportID',
            outputs=imported_id,
            readable_output=readable_output,
            raw_response=res,
        )
    else:
        raise DemistoException('The data was not imported. Check if valid arguments were passed')


def import_ioc_without_approval(client: Client, file_id, classification, confidence=None, allow_unresolved='no',
                                source_confidence_weight=None, expiration_ts=None, severity=None,
                                tags=None, trustedcircles=None):
    """
        Imports indicators data to ThreatStream.
        file_id of uploaded file to war room.
    """
    if tags:
        tags = argToList(tags)
    if trustedcircles:
        trustedcircles = argToList(trustedcircles)
    try:
        # entry id of uploaded file to war room
        file_info = demisto.getFilePath(file_id)
        with open(file_info['path'], 'rb') as uploaded_file:
            ioc_to_import = json.load(uploaded_file)
    except json.JSONDecodeError:
        raise DemistoException(f'{THREAT_STREAM} - Entry {file_id} does not contain a valid json file.')
    except Exception:
        raise DemistoException(f'{THREAT_STREAM} - Entry {file_id} does not contain a file.')
    ioc_to_import.update({'meta': assign_params(
        classification=classification,
        confidence=confidence,
        allow_unresolved=argToBoolean(allow_unresolved),
        source_confidence_weight=source_confidence_weight,
        expiration_ts=expiration_ts,
        severity=severity,
        tags=tags,
        trustedcircles=trustedcircles
    )})

    client.http_request("PATCH", "v1/intelligence/", json=ioc_to_import, resp_type='text')
    return "The data was imported successfully."


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


def get_iocs_by_model(client: Client, model, id, limit="20"):
    """
        Returns list of indicators associated with specific Threat Model by model id.
    """
    params = dict(limit=limit)
    model_type = model.title()
    response = client.http_request("GET", F"v1/{model}/{id}/intelligence/", params=params, resp_type='response')

    if response.status_code == 404:
        return f'No indicators found for Threat Model {model_type} with id {id}'

    iocs_list = response.json().get('objects', None)
    model_type = model.title()
    iocs_context = parse_indicators_list(iocs_list)

    outputs = {
        'ModelType': model_type,
        'ModelID': id,
        'Indicators': iocs_context
    }
    readable_output = tableToMarkdown(f'Indicators list for Threat Model {model_type} with id {id}',
                                      iocs_context)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Model',
        outputs_key_field=['ModelID', 'ModelType'],
        outputs=outputs,
        readable_output=readable_output,
        raw_response=iocs_list
    )


def create_model(client: Client, model, name, is_public="false", tlp=None, tags=None, intelligence=None, description=None):
    """
        Creates Threat Model with basic parameters.
    """
    data = build_model_data(model, name, is_public, tlp, tags, intelligence, description)
    model_id = client.http_request("POST", F"v1/{model}/", data=json.dumps(data)).get('id', None)

    if model_id:
        return get_iocs_by_model(client, model, model_id, limit="50")
    else:
        raise DemistoException(f'{model.title()} Threat Model was not created. Check the input parameters')


def update_model(client: Client, model, model_id, name=None, is_public="false", tlp=None, tags=None, intelligence=None,
                 description=None):
    """
        Updates a ThreatStream model with parameters. In case one or more optional parameters are
        defined, the previous data is overridden.
    """
    data = build_model_data(model, name, is_public, tlp, tags, intelligence, description)
    client.http_request("PATCH", F"v1/{model}/{model_id}/", data=json.dumps(data))
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


def add_tag_to_model(client: Client, model_id, tags, model="intelligence"):
    """
        Adds tag to specific Threat Model. By default is set to intelligence (indicators).
    """
    tags = argToList(tags)

    data = {
        'tags': [{'name': t, 'tlp': 'red'} for t in tags]
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
        url += f"?{kwargs.pop('query')}"
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
            iocs_list = client.http_request("GET", "v2/intelligence/", params=kwargs).get('objects', None)
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
        'threatstream-import-indicator-without-approval': import_ioc_without_approval,

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
        else:
            result = commands[command](client, **args)  # type: ignore

        return_results(result)

    except Exception as err:
        return_error(f'{str(err)}, traceback {traceback.format_exc()}')


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
