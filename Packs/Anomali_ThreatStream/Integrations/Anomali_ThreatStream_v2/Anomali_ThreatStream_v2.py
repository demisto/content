from requests.exceptions import MissingSchema, ConnectionError
import demistomock as demisto
from CommonServerPython import *

REPUTATION_COMANDS = ['ip', 'domain', 'file', 'url', 'threatstream-email-reputation']


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

THREAT_STREAM = 'ThreatStream'
DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
HEADERS = {
    'Content-Type': 'application/json'
}

CREDENTIALS: dict = {}

DBOT_SCORE = {
    'low': 2,
    'medium': 2,
    'high': 3,
    'very-high': 3
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
    'value': 'Value',
    'id': 'ID',
    'itype': 'IType',
    'meta': 'Meta',
    'confidence': 'Confidence',
    'country': 'Country',
    'org': 'Organization',
    'asn': 'ASN',
    'status': 'Status',
    'tags': 'Tags',
    'modified_ts': 'Modified',
    'source': 'Source',
    'type': 'Type',
}

THREAT_MODEL_MAPPING = {
    'name': 'Name',
    'id': 'ID',
    'created_ts': 'CreatedTime',
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

THRESHOLDS_FROM_PARAM: Dict = {}

''' HELPER FUNCTIONS '''


class Client:
    def __init__(self, base_url, use_ssl, default_threshold, reliability):
        self.base_url = base_url
        self.use_ssl = use_ssl
        self.default_threshold = default_threshold
        self.reliability = reliability

    def http_request(self, method, url_suffix, params=None, data=None, headers=None, files=None, json=None, text_response=None):
        """
            A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        res = requests.request(
            method,
            self.base_url + url_suffix,
            verify=self.use_ssl,
            params=params,
            data=data,
            headers=headers,
            files=files,
            json=json
        )
        # Handle error responses gracefully
        if res.status_code in {401}:
            raise Exception(f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials.")
        elif res.status_code in {404}:
            command = demisto.command()
            if command in ['threatstream-get-model-description', 'threatstream-get-indicators-by-model',
                           'threatstream-get-analysis-status', 'threatstream-analysis-report']:
                # in order to prevent raising en error in case model/indicator/report was not found
                return {}
            else:
                raise Exception(f"{THREAT_STREAM} - The resource not found. Check the endpoint.")
        elif res.status_code not in {200, 201, 202}:
            raise Exception(F"{THREAT_STREAM} - Error in API call to ThreatStream {res.status_code} - {res.text}")

        if text_response:
            return res.text
        return res.json()


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
    if command in REPUTATION_COMANDS:
        default_include_inactive = params.get('include_inactive', False)
        include_inactive = argToBoolean(args.pop('include_inactive', default_include_inactive))
        args['status'] = "active,inactive" if include_inactive else "active"
    if 'indicator_severity' in args:
        # special handling for threatstream-get-indicators
        args['meta.severity'] = args.pop('indicator_severity', None)
    if 'tags_name' in args:
        # special handling for threatstream-get-indicators
        args['tags.name'] = args.pop('tags_name', None)
    if 'indicator_value' in args:
        # special handling for threatstream-get-indicators
        args['value'] = args.pop('indicator_value', None)
    if 'threshold' in args:
        args['threshold'] = arg_to_number(args['threshold'])

    return args


def build_params(**params):
    """
        Builds query string from key word arguments and appends to it username and api key.
    """
    params.update(CREDENTIALS)
    return params


def calculate_score(indicator, threshold=None):
    """
        Calculate the DBot score according the indicator's confidence and threshold
    """
    confidence = indicator.get('confidence', Common.DBotScore.NONE)
    # in case threshold was defined in the instance or passed as argument
    # we have only two scores levels - malicious or good
    # if threshold wasn't defined we have three score levels malicious suspicious and good
    defined_threshold = threshold or THRESHOLDS_FROM_PARAM.get(demisto.command())
    if defined_threshold:
        return Common.DBotScore.BAD if confidence >= defined_threshold else Common.DBotScore.GOOD
    else:
        if confidence > DEFAULT_MALICIOUS_THRESHOLD:
            return Common.DBotScore.BAD
        if confidence > DEFAULT_SUSPICIOUS_THRESHOLD:
            return Common.DBotScore.SUSPICIOUS
        else:
            return Common.DBotScore.GOOD


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


def mark_as_malicious(indicator, threshold, context):
    """
        Marks indicator as malicious if confidence of indicator is greater to threshold and
        adds Malicious key to returned dictionary (context) in such case.
    """
    confidence = indicator.get('confidence', Common.DBotScore.NONE)
    threshold = threshold or THRESHOLDS_FROM_PARAM.get(demisto.command()) or DEFAULT_MALICIOUS_THRESHOLD
    if confidence > threshold:
        context['Malicious'] = {
            'Vendor': THREAT_STREAM
        }


def search_indicator_by_params(client: Client, params, searchable_value):
    """
        Generic function that searches for indicators from ThreatStream by given query string.
        Returns indicator with the highest confidence score.
    """
    indicators_data = client.http_request("Get", "v2/intelligence/", params=params, headers=HEADERS)

    if not indicators_data['objects']:
        demisto.results(F"No intelligence has been found for {searchable_value}")
        return None

    return find_worst_indicator(indicators_data['objects'])


def get_threat_generic_context(indicator, indicator_mapping=DEFAULT_INDICATOR_MAPPING):
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


def get_report_outputs(report, report_id):
    """
        Returns human readable and entry context of the sandbox report
    """
    info = parse_info(report.get('info', {}))
    info['ReportID'] = report_id
    _, info['Verdict'] = get_submission_status(report_id, False)
    network = parse_network_lists(report.get('network', {}))

    hm = tableToMarkdown(F"Report {report_id} analysis results", info)
    ec = {
        'ThreatStream.Analysis': info,
        'ThreatStream.Analysis.Network': network
    }

    return hm, ec


def parse_indicators_list(iocs_list):
    """
        Parses the indicator list and returns dictionary that will be set to context.
    """
    for indicator in iocs_list:
        if indicator.get('type', '') == 'md5':
            indicator['type'] = indicator.get('subtype', '')

    iocs_context = list(map(lambda i: {INDICATOR_EXTENDED_MAPPING[k]: v for (k, v) in i.items() if
                                       k in INDICATOR_EXTENDED_MAPPING.keys()}, iocs_list))

    for indicator in iocs_context:
        meta = indicator.pop('Meta', None)
        if meta:
            indicator['Severity'] = meta.get('severity', 'low')
        tags = indicator.get('Tags', [])
        if isinstance(tags, list):
            indicator['Tags'] = ",".join(list(map(lambda t: t.get('name', ''), tags)))

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


def create_relationships(indicator, ioc_type, relation_mapper):
    relationships = []
    for relation in relation_mapper:
        relationships.append(EntityRelationship(entity_a=indicator['value'],
                                                entity_a_type=ioc_type,
                                                name=relation['name'],
                                                entity_b=demisto.get(indicator, relation['raw_field']),
                                                entity_b_type=relation['entity_b_type'],
                                                brand=THREAT_STREAM))
    return relationships


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client):
    """
    Performs basic get request to get item samples
    """
    params = build_params(limit=1)
    client.http_request('GET', 'v2/intelligence/', params=params)
    demisto.results('ok')


def ips_reputation_command(client: Client, ip, status, threshold=None):
    ips = argToList(ip, ',')
    for single_ip in ips:
        get_ip_reputation(client, single_ip, status, threshold)


def get_ip_reputation(client: Client, ip, status, threshold=None):
    """
        Checks the reputation of given ip from ThreatStream and
        returns the indicator with highest confidence score.
    """
    # get the indicator
    params = build_params(value=ip, type="ip", status=status, limit=0)
    indicator = search_indicator_by_params(client, params, ip)
    if not indicator:
        return

    # Convert the tags objects into s string for the human readable and then override it with the original objects
    # for the context.
    threat_context = get_threat_generic_context(indicator)
    tags = threat_context.pop('Tags', [])
    if tags:
        threat_context['Tags'] = ', '.join(tags)
    human_readable = tableToMarkdown(f'IP reputation for: {ip}', threat_context)
    threat_context['Tags'] = tags

    # build relationships
    relationships = create_relationships(indicator, FeedIndicatorType.IP, RELATIONSHIPS_MAPPING.get('ip'))

    # create the IP instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('ip')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key) for (arg, key) in args_to_keys_map.items()}
    ip_indicator = Common.IP(
        dbot_score=Common.DBotScore(ip, DBotScoreType.IP,
                                    THREAT_STREAM, score=calculate_score(indicator, threshold),
                                    reliability=client.reliability),
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        relationships=relationships,
        **kwargs
    )

    return_results(CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.IP',
        outputs_key_field='Address',
        indicator=ip_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    ))


def domains_reputation_command(client: Client, domain, status, threshold=None):
    """
        Wrapper function for get_domain_reputation.
    """
    domains = argToList(domain, ',')
    for single_domain in domains:
        get_domain_reputation(client, single_domain, status, threshold)


def get_domain_reputation(client: Client, domain, status, threshold=None):
    """
        Checks the reputation of given domain from ThreatStream and
        returns the indicator with highest confidence score.
    """
    # get the indicator
    params = build_params(value=domain, type='domain', status=status, limit=0)
    indicator = search_indicator_by_params(client, params, domain)
    if not indicator:
        return

    # Convert the tags objects into s string for the human readable and then override it with the original objects
    # for the context.
    threat_context = get_threat_generic_context(indicator)
    tags = threat_context.pop('Tags', [])
    if tags:
        threat_context['Tags'] = ', '.join(tags)
    human_readable = tableToMarkdown(f'Domain reputation for: {domain}', threat_context)
    threat_context['Tags'] = tags

    # build relationships
    relationships = create_relationships(indicator, FeedIndicatorType.Domain, RELATIONSHIPS_MAPPING.get('domain'))

    # create the Domain instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('domain')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key) for (arg, key) in args_to_keys_map.items()}
    geo_location = f"{indicator.get('latitude')},{indicator.get('longitude')}" if indicator.get('latitude') else None
    domain_indicator = Common.Domain(
        dbot_score=Common.DBotScore(domain, DBotScoreType.DOMAIN,
                                    THREAT_STREAM, reliability=client.reliability,
                                    score=calculate_score(indicator, threshold)),
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        geo_location=geo_location,
        relationships=relationships,
        **kwargs,
    )

    return_results(CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Domain',
        outputs_key_field='Address',
        indicator=domain_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    ))


def files_reputation_command(client: Client, file, status, threshold=None):
    """
        Wrapper function for get_file_reputation.
    """
    files = argToList(file, ',')
    for single_file in files:
        get_file_reputation(client, single_file, status, threshold)


def get_file_reputation(client: Client, file, status, threshold=None):
    """
        Checks the reputation of given hash of the file from ThreatStream and
        returns the indicator with highest severity score.
    """
    # get the indicator
    params = build_params(value=file, type="md5", status=status, limit=0)
    indicator = search_indicator_by_params(client, params, file)
    if not indicator:
        return

    # save the hash value under the hash type key
    threat_context = get_threat_generic_context(indicator, indicator_mapping=FILE_INDICATOR_MAPPING)
    file_type: str = indicator.get('subtype')  # The real type of the hash is in subtype field.
    if file_type:
        threat_context[file_type] = indicator.get('value')

    # Convert the tags objects into s string for the human readable and then override it with the original objects
    # for the context.
    tags = threat_context.pop('Tags', [])
    if tags:
        threat_context['Tags'] = ', '.join(tags)
    human_readable = tableToMarkdown(f'File reputation for: {file}', threat_context)
    threat_context['Tags'] = tags

    # build relationships
    relationships = create_relationships(indicator, FeedIndicatorType.File, RELATIONSHIPS_MAPPING.get('file'))

    # create the File instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('file')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key) for (arg, key) in args_to_keys_map.items()}
    if file_type:
        kwargs[file_type.lower()] = threat_context[file_type]
    file_indicator = Common.File(
        dbot_score=Common.DBotScore(file, DBotScoreType.FILE,
                                    THREAT_STREAM, reliability=client.reliability,
                                    score=calculate_score(indicator, threshold)),
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        relationships=relationships,
        **kwargs,
    )

    return_results(CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.{Common.File.CONTEXT_PATH}',
        indicator=file_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    ))


def urls_reputation_command(client: Client, url, status, threshold=None):
    """
        Wrapper function for get_url_reputation.
    """
    urls = argToList(url, ',')
    for single_url in urls:
        get_url_reputation(client, single_url, status, threshold)


def get_url_reputation(client: Client, url, status, threshold=None):
    """
        Checks the reputation of given url address from ThreatStream and
        returns the indicator with highest confidence score.
    """

    # get the indicator
    params = build_params(value=url, type="url", status=status, limit=0)
    indicator = search_indicator_by_params(client, params, url)
    if not indicator:
        return

    # Convert the tags objects into s string for the human readable and then override it with the original objects
    # for the context.
    threat_context = get_threat_generic_context(indicator)
    tags = threat_context.pop('Tags', [])
    if tags:
        threat_context['Tags'] = ', '.join(tags)
    human_readable = tableToMarkdown(f'URL reputation for: {url}', threat_context)
    threat_context['Tags'] = tags

    # build relationships
    relationships = create_relationships(indicator, FeedIndicatorType.URL, RELATIONSHIPS_MAPPING.get('url'))

    # create the URL instance
    args_to_keys_map: Dict[str, str] = IOC_ARGS_TO_INDICATOR_KEY_MAP.get('url')  # type: ignore
    kwargs = {arg: demisto.get(indicator, key_in_indicator) for (arg, key_in_indicator) in args_to_keys_map.items()}
    url_indicator = Common.URL(
        dbot_score=Common.DBotScore(url, DBotScoreType.URL,
                                    THREAT_STREAM, reliability=client.reliability,
                                    score=calculate_score(indicator, threshold)),
        tags=get_tags(indicator),
        threat_types=[Common.ThreatTypes(indicator.get('threat_type'))],
        relationships=relationships,
        **kwargs,
    )

    return_results(CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.URL',
        outputs_key_field='Address',
        indicator=url_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    ))


def get_email_reputation(client: Client, email, status, threshold=None):
    """
        Checks the reputation of given email address from ThreatStream and
        returns the indicator with highest confidence score.
    """
    params = build_params(value=email, type="email", status=status, limit=0)
    indicator = search_indicator_by_params(client, params, email)
    if not indicator:
        return

    threat_context = get_threat_generic_context(indicator)
    threat_context['Email'] = threat_context.pop('Address')
    threat_context.pop('ASN', None)
    threat_context.pop('Organization', None)
    threat_context.pop('Country', None)

    # Convert the tags objects into s string for the human readable and then override it with the original objects
    # for the context.
    tags = threat_context.pop('Tags', [])
    if tags:
        threat_context['Tags'] = ', '.join(tags)
    human_readable = tableToMarkdown(f'Email reputation for: {email}', threat_context)
    threat_context['Tags'] = tags

    # build relationships
    relationships = create_relationships(indicator, FeedIndicatorType.Email, RELATIONSHIPS_MAPPING.get('email'))

    # create the EMAIL instance
    email_indicator = Common.EMAIL(
        dbot_score=Common.DBotScore(email, DBotScoreType.EMAIL,
                                    THREAT_STREAM, reliability=client.reliability,
                                    score=calculate_score(indicator, threshold)),
        address=threat_context['Email'],
        relationships=relationships,
    )

    return_results(CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.EmailReputation',
        outputs_key_field='Email',
        indicator=email_indicator,
        readable_output=human_readable,
        outputs=threat_context,
        raw_response=indicator,
        relationships=relationships
    ))


def get_passive_dns(client: Client, value, type="ip", limit=50):
    """
        Receives value and type of indicator and returns
        enrichment data for domain or ip.
    """
    dns_results = client.http_request("GET", F"v1/pdns/{type}/{value}/", params=CREDENTIALS).get('results', None)

    if not dns_results:
        demisto.results(F"No Passive DNS enrichment data found for {value}")
        sys.exit()

    dns_results = dns_results[:int(limit)]
    output = camelize(dns_results, delim='_')

    ec = ({
        'ThreatStream.PassiveDNS': output
    })
    human_readable = tableToMarkdown(F"Passive DNS enrichment data for: {value}", output)

    return_outputs(human_readable, ec, dns_results)


def import_ioc_with_approval(client: Client, import_type, import_value, confidence="50", classification="Private",
                             threat_type="exploit", severity="low", ip_mapping=None, domain_mapping=None,
                             url_mapping=None, email_mapping=None, md5_mapping=None):
    """
        Imports indicators data to ThreatStream.
        The data can be imported using one of three import_types: data-text (plain-text),
        file-id of uploaded file to war room or URL.
    """
    files = None
    uploaded_file = None
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

    if import_type == 'file-id':
        try:
            # import_value will be entry id of uploaded file to war room
            file_info = demisto.getFilePath(import_value)
        except Exception:
            raise DemistoException(f"Entry {import_value} does not contain a file.")

        uploaded_file = open(file_info['path'], 'rb')
        files = {'file': (file_info['name'], uploaded_file)}
    elif import_type == 'url':
        data['url'] = import_value
    else:
        data['datatext'] = import_value

    params = build_params()
    # in case import_type is not file-id, http_requests will receive None as files
    res = client.http_request("POST", "v1/intelligence/import/", params=params, data=data, files=files)
    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()
    # checking that response contains success key
    if res.get('success', False):
        imported_id = res.get('import_session_id', '')
        ec = {'ThreatStream.Import.ImportID': imported_id}
        return_outputs(F"The data was imported successfully. The ID of imported job is: {imported_id}", ec, res)
    else:
        return_outputs("The data was not imported. Check if valid arguments were passed", None)


def import_ioc_without_approval(client: Client, file_id, classification, confidence=None, allow_unresolved=None,
                                source_confidence_weight=None, expiration_ts=None, severity=None,
                                tags=None, trustedcircles=None):
    """
        Imports indicators data to ThreatStream.
        file_id of uploaded file to war room or URL. Other fields are
    """
    if allow_unresolved:
        allow_unresolved = allow_unresolved == 'yes'
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
        raise DemistoException(F"Entry {file_id} does not contain a valid json file.")
    except Exception:
        raise DemistoException(F"Entry {file_id} does not contain a file.")
    ioc_to_import.update({'meta': assign_params(
        classification=classification,
        confidence=confidence,
        allow_unresolved=allow_unresolved,
        source_confidence_weight=source_confidence_weight,
        expiration_ts=expiration_ts,
        severity=severity,
        tags=tags,
        trustedcircles=trustedcircles
    )})

    params = build_params()
    res = client.http_request("PATCH", "v1/intelligence/", params=params, json=ioc_to_import, text_response=True)
    return_outputs("The data was imported successfully.", {}, res)


def get_model_list(client: Client, model, limit="50"):
    """
        Returns list of Threat Model that was specified. By default limit is set to 50 results.
        Possible values for model are : actor, campaign, incident, signature, ttp, vulnerability, tipreport
    """
    # if limit=0 don't put to context
    params = build_params(limit=limit, skip_intelligence="true", skip_associations="true")
    model_list = client.http_request("GET", F"v1/{model}/", params=params).get('objects', None)

    if not model_list:
        demisto.results(F"No Threat Model {model.title()} found.")
        sys.exit()

    threat_list_context = list(map(lambda m: {THREAT_MODEL_MAPPING[k]: v for (k, v) in m.items() if
                                              k in THREAT_MODEL_MAPPING.keys()}, model_list))
    for m in threat_list_context:
        m['Type'] = model.title()
    # in case that no limit was passed, the stage of set to context is skipped
    ec = {'ThreatStream.List': threat_list_context} if limit != '0' else None
    human_readable = tableToMarkdown(F"List of {model.title()}s", threat_list_context)

    return_outputs(human_readable, ec, model_list)


def get_model_description(client: Client, model, id):
    """
        Returns a description of Threat Model as html file to the war room.
    """
    params = build_params(skip_intelligence="true", skip_associations="true")
    description = client.http_request("GET", F"v1/{model}/{id}", params=params)

    if model == 'signature':
        description = description.get('notes', None)
    elif model == 'tipreport':
        description = description.get('body', None)
    else:
        description = description.get('description', None)

    if not description:
        demisto.results(F"No description found for Threat Model {model.title()} with id {id}")
        sys.exit()

    demisto.results(fileResult(F"{model}_{id}.html", description.encode(encoding='UTF-8')))


def get_iocs_by_model(client: Client, model, id, limit="20"):
    """
        Returns list of indicators associated with specific Threat Model by model id.
    """
    params = build_params(limit=limit)
    iocs_list = client.http_request("GET", F"v1/{model}/{id}/intelligence/", params=params).get('objects', None)

    if not iocs_list:
        demisto.results(F"No indicators found for Threat Model {model.title()} with id {id}")
        sys.exit()

    iocs_context = parse_indicators_list(iocs_list)

    ec = {
        'ThreatStream.Model(val.ModelID == obj.ModelID && val.ModelType == obj.ModelType)': {'ModelType': model.title(),
                                                                                             'ModelID': id,
                                                                                             'Indicators': iocs_context},
    }
    human_readable = tableToMarkdown(F"Indicators list for Threat Model {model.title()} with id {id}", iocs_context)

    return_outputs(human_readable, ec, iocs_list)


def create_model(client: Client, model, name, is_public="false", tlp=None, tags=None, intelligence=None, description=None):
    """
        Creates Threat Model with basic parameters.
    """
    data = build_model_data(model, name, is_public, tlp, tags, intelligence, description)
    model_id = client.http_request("POST", F"v1/{model}/", data=json.dumps(data), params=CREDENTIALS).get('id', None)

    if model_id:
        get_iocs_by_model(client, model, model_id, limit="50")
    else:
        demisto.results(F"{model.title()} Threat Model was not created. Check the input parameters")


def update_model(client: Client, model, model_id, name=None, is_public="false", tlp=None, tags=None, intelligence=None,
                 description=None):
    """
        Updates a ThreatStream model with parameters. In case one or more optional parameters are
        defined, the previous data is overridden.
    """
    data = build_model_data(model, name, is_public, tlp, tags, intelligence, description)
    client.http_request("PATCH", F"v1/{model}/{model_id}/", data=json.dumps(data), params=CREDENTIALS)
    get_iocs_by_model(client, model, model_id, limit="50")


def supported_platforms(client: Client, sandbox_type="default"):
    """
        Returns list of supported platforms for premium sandbox or default sandbox.
    """
    platform_data = client.http_request("GET", "v1/submit/parameters/", params=CREDENTIALS)
    available_platforms = platform_data.get('platform_choices', []) if sandbox_type == 'default' else platform_data.get(
        'premium_platform_choices',
        [])

    if available_platforms:
        supported_output = camelize(available_platforms)
        context_path = "ThreatStream.DefaultPlatforms" if sandbox_type == 'default' else "ThreatStream.PremiumPlatforms"

        return_outputs(tableToMarkdown(F"Supported platforms for {sandbox_type} sandbox", supported_output),
                       {context_path: supported_output}, platform_data)
    else:
        demisto.results(F"No supported platforms found for {sandbox_type} sandbox")


def get_submission_status(client: Client, report_id, output=True):
    """
        Returns the sandbox submission status. If status is not received in report_info
        then status is set to done. Receives output boolean that prints the result to the war room.
        By default the output boolean is set to True.
    """
    report_info = client.http_request("GET", F"v1/submit/{report_id}/", params=CREDENTIALS, headers=HEADERS)

    if not report_info:
        demisto.results(F"No report found with id {report_id}")
        sys.exit()

    status = report_info.get('status', "done")
    verdict = report_info.get('verdict', '').title()
    platform = report_info.get('platform', '')

    if output:
        report_outputs = {'ReportID': report_id, 'Status': status, 'Platform': platform, 'Verdict': verdict}
        ec = {'ThreatStream.Analysis(val.ReportID == obj.ReportID)': report_outputs}
        return_outputs(tableToMarkdown(F"The analysis status for id {report_id}", report_outputs), ec, report_info)
    return status, verdict


def file_name_to_valid_string(file_name):
    try:
        # In case the user uses Cortex XSOAR version < 5.0 and the new docker image will not be automatically changed
        import emoji

        if emoji.emoji_count(file_name):  # type: ignore
            return emoji.demojize(file_name)  # type: ignore
    except Exception:
        pass

    return file_name


def submit_report(client: Client, submission_type, submission_value, submission_classification="private",
                  report_platform="WINDOWS7",
                  premium_sandbox="false", detail=None):
    """
        Detonates URL or file that was uploaded to war room to ThreatStream sandbox.
    """
    uploaded_file = None
    files = None

    data = {
        'report_radio-classification': submission_classification,
        'report_radio-platform': report_platform,
        'use_premium_sandbox': premium_sandbox,
    }
    if detail:
        data['detail'] = detail

    if submission_type == 'file':
        try:
            # submission_value will be entry id of uploaded file to war room
            file_info = demisto.getFilePath(submission_value)
        except Exception:
            raise Exception(F"{THREAT_STREAM} - Entry {submission_value} does not contain a file.")

        uploaded_file = open(file_info['path'], 'rb')
        file_name = file_name_to_valid_string(file_info.get('name'))
        files = {'report_radio-file': (file_name, uploaded_file)}
    else:
        data['report_radio-url'] = submission_value

    res = client.http_request("POST", "v1/submit/new/", params=CREDENTIALS, data=data, files=files)
    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()

    if str(res.get('success', '')).lower() == 'true':
        report_info = res['reports'][report_platform]
        report_id = report_info['id']
        report_status, _ = get_submission_status(report_id, False)

        report_outputs = {'ReportID': report_id, 'Status': report_status, 'Platform': report_platform}
        ec = {'ThreatStream.Analysis': report_outputs}
        return_outputs(tableToMarkdown(F"The submission info for {submission_value}", report_outputs), ec, report_info)
    else:
        demisto.results(F"The submission of {submission_value} failed")


def get_report(client: Client, report_id):
    """
        Returns the report from ThreatStream sandbox by id.
    """
    report = client.http_request("GET", F"v1/submit/{report_id}/report", params=CREDENTIALS, headers=HEADERS)
    if not report:
        demisto.results(F"No report found with id {report_id}")
        sys.exit()
    hm, ec = get_report_outputs(report.get('results', {}), report_id)

    return_outputs(hm, ec, report)


def add_tag_to_model(client: Client, model_id, tags, model="intelligence"):
    """
        Adds tag to specific Threat Model. By default is set to intelligence (indicators).
    """
    tags = tags if isinstance(tags, list) else tags.split(',')

    data = {
        'tags': [{'name': t, 'tlp': 'red'} for t in tags]
    }

    res = client.http_request("POST", F"v1/{model}/{model_id}/tag/", params=CREDENTIALS, data=json.dumps(data))

    if str(res.get('success', '')).lower() == 'true':
        return_outputs(F"Added successfully tags: {tags} to {model} with {model_id}", None, res)
    else:
        return_outputs(F"Failed to add {tags} to {model} with {model_id}", None, res)


def get_indicators(client: Client, **kwargs):
    """
        Returns filtered indicators by parameters from ThreatStream.
        By default the limit of indicators result is set to 20.
    """
    limit = kwargs['limit'] = int(kwargs.get('limit', 20))
    offset = kwargs['offset'] = 0
    if 'query' in kwargs:
        kwargs['q'] = kwargs['query']
        kwargs.pop('query', None)
    params = build_params(**kwargs)
    iocs_list = client.http_request("GET", "v2/intelligence/", params=params).get('objects', None)
    if not iocs_list:
        demisto.results('No indicators found from ThreatStream')
        sys.exit()
    iocs_context = parse_indicators_list(iocs_list)

    # handle the issue that the API does not return more than 1000 indicators.
    if limit > 1000:
        while len(iocs_context) < limit:
            offset += len(iocs_list)
            limit -= len(iocs_list)
            kwargs['limit'] = limit
            kwargs['offset'] = offset
            params = build_params(**kwargs)
            iocs_list = client.http_request("GET", "v2/intelligence/", params=params).get('objects', None)
            if iocs_list:
                iocs_context.extend(parse_indicators_list(iocs_list))
            else:
                break
    ec = {'ThreatStream.Indicators': iocs_context}
    return_outputs(tableToMarkdown("The indicators results", iocs_context), ec, iocs_list)


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    LOG(f'Command being called is {command}')

    params = demisto.params()

    # init credentials
    user_name = params.get('username')
    api_key = params.get('apikey')
    server_url = params.get('url', '').strip('/')
    CREDENTIALS['username'] = user_name
    CREDENTIALS['api_key'] = api_key

    # init threshold from params
    THRESHOLDS_FROM_PARAM['url'] = arg_to_number(params.get('url_threshold'))
    THRESHOLDS_FROM_PARAM['ip'] = arg_to_number(params.get('ip_threshold'))
    THRESHOLDS_FROM_PARAM['file'] = arg_to_number(params.get('file_threshold'))
    THRESHOLDS_FROM_PARAM['domain'] = arg_to_number(params.get('domain_threshold'))
    THRESHOLDS_FROM_PARAM['threatstream-email-reputation'] = arg_to_number(params.get('email_threshold'))

    reliability = params.get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Source Reliability parameter.")

    try:

        client = Client(
            base_url=f'{server_url}/api/',
            use_ssl=not params.get('insecure', False),
            default_threshold=params.get('default_threshold', 'high'),
            reliability=reliability
        )

        handle_proxy()
        args = prepare_args(demisto.args(), command, params)
        if command == 'test-module':
            test_module(client)
        elif command == 'ip':
            ips_reputation_command(client, **args)
        elif command == 'domain':
            domains_reputation_command(client, **args)
        elif command == 'file':
            files_reputation_command(client, **args)
        elif command == 'url':
            urls_reputation_command(client, **args)
        elif command == 'threatstream-email-reputation':
            get_email_reputation(client, **args)
        elif command == 'threatstream-get-passive-dns':
            get_passive_dns(client, **args)
        elif command == 'threatstream-import-indicator-with-approval':
            import_ioc_with_approval(client, **args)
        elif command == 'threatstream-import-indicator-without-approval':
            import_ioc_without_approval(client, **args)
        elif command == 'threatstream-get-model-list':
            get_model_list(client, **args)
        elif command == 'threatstream-get-model-description':
            get_model_description(client, **args)
        elif command == 'threatstream-get-indicators-by-model':
            get_iocs_by_model(client, **args)
        elif command == 'threatstream-create-model':
            create_model(client, **args)
        elif command == 'threatstream-update-model':
            update_model(client, **args)
        elif command == 'threatstream-submit-to-sandbox':
            submit_report(client, **args)
        elif command == 'threatstream-get-analysis-status':
            get_submission_status(client, **args)
        elif command == 'threatstream-analysis-report':
            get_report(client, **args)
        elif command == 'threatstream-supported-platforms':
            supported_platforms(client, **args)
        elif command == 'threatstream-get-indicators':
            get_indicators(client, **args)
        elif command == 'threatstream-add-tag-to-model':
            add_tag_to_model(client, **args)

    except Exception as err:
        if isinstance(err, MissingSchema):
            return_error("Not valid server url. Check url format")
        elif isinstance(err, ConnectionError):
            return_error("The server is not reachable.")
        else:
            return_error(err)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
