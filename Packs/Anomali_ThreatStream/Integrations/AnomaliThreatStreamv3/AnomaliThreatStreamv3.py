import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import emoji

import traceback
import urllib3
from datetime import date


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
DEFAULT_LIMIT_PAGE_SIZE = 50
REPUTATION_COMMANDS = ['ip', 'domain', 'file', 'url', 'threatstream-email-reputation']

MODEL_TYPE_LIST = ['actor', 'attackpattern', 'campaign', 'courseofaction', 'incident',
                   'identity', 'infrastructure', 'intrusionset',
                   'malware', 'signature', 'tipreport', 'ttp', 'tool', 'vulnerability']
PUBLICATION_STATUS_LIST = ['new', 'pending_review', 'review_requested', 'reviewed', 'published']
SIGNATURE_TYPE_LIST = ['Bro', 'Carbon Black Query', 'ClamAV', 'Custom', 'CybOX',
                       'OpenIOC', 'RSA NetWitness',
                       'Snort', 'Splunk Query', 'Suricata', 'YARA']

THREAT_STREAM = 'ThreatStream'
NO_INDICATORS_FOUND_MSG = 'No intelligence has been found for {searchable_value}'
DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
HEADERS = {
    'Content-Type': 'application/json'
}
RETRY_COUNT = 2

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
    'itype': 'IType',
}

FILE_INDICATOR_MAPPING = {
    'modified_ts': 'Modified',
    'confidence': 'Confidence',
    'status': 'Status',
    'source': 'Source',
    'subtype': 'Type',
    'tags': 'Tags',
    'itype': 'IType',
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

INTELLIGENCE_TYPES = ['actor', 'signature', 'tipreport', 'ttp', 'vulnerability', 'campaign']

INTELLIGENCE_TYPE_TO_ENTITY_TYPE = {'actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                    'signature': 'Signature',
                                    'vulnerability': FeedIndicatorType.CVE,
                                    'ttp': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                                    'tipreport': 'Publication',
                                    'campaign': ThreatIntel.ObjectsNames.CAMPAIGN}

INTELLIGENCE_TYPE_TO_CONTEXT = {'actor': 'Actor',
                                'signature': 'Signature',
                                'vulnerability': 'Vulnerability',
                                'ttp': 'TTP',
                                'tipreport': 'ThreatBulletin',
                                'campaign': 'Campaign'}
''' HELPER FUNCTIONS '''


class Client(BaseClient):
    def __init__(self, base_url, user_name, api_key, verify, proxy, reliability, should_create_relationships, remote_api):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200, 201, 202))
        self.reliability = reliability
        self.should_create_relationships = should_create_relationships
        self.credentials = {
            'Authorization': f"apikey {user_name}:{api_key}",
        }
        self.remote_api = remote_api

    def http_request(self, method,
                     url_suffix, params=None,
                     data=None, headers=None,
                     files=None, json=None,
                     without_credentials=False,
                     resp_type='json'):
        """
            A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        headers = headers or {}
        if not without_credentials:
            headers.update(self.credentials)
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
            retries=RETRY_COUNT,
        )
        return res

    def error_handler(self, res: requests.Response):  # pragma: no cover
        """
        Error handler to call by super().http_request in case an error was occurred
        """
        # Handle error responses gracefully
        command = demisto.command()
        if res.status_code == 401:
            if command == 'threatstream-add-threat-model-association':
                raise DemistoException(f'{THREAT_STREAM} - Got unauthorized from the server.'
                                       'Make sure that the threat models belongs to your organization.')
            if command == 'threatstream-list-import-job':
                raise DemistoException(f'{THREAT_STREAM} - Got unauthorized from the server.'
                                       'Make sure that the import job belongs to your organization.')
            elif command == 'threatstream-approve-import-job':
                raise DemistoException(f'{THREAT_STREAM} - Got unauthorized from the server.'
                                       'Please ensure that you have the necessary Intel user permission and that'
                                       ' the import job belongs to your organization.')
            else:
                raise DemistoException(f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials.")
        elif res.status_code == 204:
            return
        elif res.status_code in {404}:
            if command in ['threatstream-get-model-description', 'threatstream-get-indicators-by-model',
                           'threatstream-get-analysis-status', 'threatstream-analysis-report']:
                # in order to prevent raising en error in case model/indicator/report was not found
                return
            else:
                raise DemistoException(f"{THREAT_STREAM} - The resource was not found.")
        raise DemistoException(F"{THREAT_STREAM} - Error in API call {res.status_code} - {res.text}")

    def list_rule_request(self, rule_id: Optional[str], params: dict) -> dict:
        """ Gets a list of all the rules in ThreatStream.
            If a specific rule_id is given, it will return the information about this rule.
        Args:
            rule_id (int):  Unique ID assigned to the rule.
            params (dict): The required parameters for the request.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = 'v1/rule/'
        if rule_id:
            url_suffix += f'{rule_id}/'
            return self.http_request('GET', url_suffix, params=params)
        params['order_by'] = '-created_ts'
        return self.http_request('GET', url_suffix, params=params)

    def create_rule_request(self, request_body: dict) -> dict:
        """ Creates a rule in ThreatStream.
        Args:
            request_body (dict): The request body.
        Returns:
            A response object in a form of a dictionary.
        """
        return self.http_request('POST', 'v1/rule/', json=request_body)

    def update_rule_request(self, rule_id: Optional[str], request_body: dict) -> dict:
        """ Updates a rule in ThreatStream.
        Args:
            rule_id (dict): The rule ID.
            request_body (dict): The request body.
        Returns:
            A response object in a form of a dictionary.
        """
        return self.http_request('PATCH', f'v1/rule/{rule_id}/', json=request_body)

    def delete_rule_request(self, rule_id: Optional[str]):
        """ Deletes a rule in ThreatStream.
        Args:
            rule_id (dict): The rule ID.
        Returns:
            None.
        """
        self.http_request('DELETE', f'v1/rule/{rule_id}/', resp_type='text')

    def list_users_request(self, user_id: Optional[str], params: dict):
        """ Gets a list of all the users in ThreatStream.
            If a specific user_id is given, it will return the information about this user.
        Args:
            user_id (int):  Unique ID assigned to the user.
            params (dict): The request params.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = 'v1/orgadmin/'
        if user_id:
            url_suffix += f'{user_id}/'
            return self.http_request('GET', url_suffix)
        return self.http_request('GET', url_suffix, params=params)

    def list_investigation_request(self, investigation_id: Optional[str], params: dict):
        """ Gets a list of all the investigations in ThreatStream.
            If a specific investigation_id is given, it will return the information about this investigation.
        Args:
            user_id (int): Unique ID assigned to the investigation.
            params (dict): The request params.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = 'v1/investigation/'
        if investigation_id:
            url_suffix += f'{investigation_id}/'
            return self.http_request('GET', url_suffix)
        params['order_by'] = '-created_ts'
        return self.http_request('GET', url_suffix, params=params)

    def create_investigation_request(self, request_body: dict) -> dict:
        """ Creats an investigation in ThreatStream.
        Args:
            request_body (dict): The request body.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = 'v1/investigation/'
        return self.http_request('POST', url_suffix, json=request_body)

    def delete_investigation_request(self, investigation_id: Optional[str]):
        """ Deletes an investigation in ThreatStream.
        Args:
            investigation_id (dict): The investigation ID.
        Returns:
            None.
        """
        url_suffix = f'v1/investigation/{investigation_id}/'
        self.http_request('DELETE', url_suffix, resp_type='text')

    def update_investigation_request(self, investigation_id: Optional[str], request_body: dict) -> dict:
        """ Updates an investigation in ThreatStream.
        Args:
            investigation_id (dict): The investigation ID.
            request_body (dict): The request body.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'v1/investigation/{investigation_id}/'
        return self.http_request('PATCH', url_suffix, json=request_body)

    def add_investigation_element_request(self, investigation_id: Optional[int], request_body: dict) -> dict:
        """ Adds investigation elements to investigation.
        Args:
            investigation_id (dict): The rule ID.
            request_body (dict): The request body.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = 'v1/investigationelement/'
        return self.http_request('POST', url_suffix, json=request_body, params={'investigation_id': investigation_id})

    def list_whitelist_entry_request(self, format: str, params: dict) -> dict:
        """ Gets a list of all whitelist entry in ThreatStream.
        Args:
            format (str):  A URL parameter to define the format of the response CSV or JSON.
            params (dict): The request params.
        Returns:
            A response object in a form of a dictionary.
        """
        params['format'] = format.lower() if format else 'json'
        params['showNote'] = 'true'
        params['order_by'] = '-created_ts'
        if format and format.lower() == 'json':
            return self.http_request('GET', 'v1/orgwhitelist/', params=params)
        return self.http_request('GET', 'v1/orgwhitelist/', params=params, resp_type='text')

    def create_whitelist_entry_with_file_request(self, file_data: dict) -> dict:
        """ Creates a whitelist entries in ThreatStream according to file data.
        Args:
            file_path (str): The path of the file.
        Returns:
            A response object in a form of a dictionary.
        """
        return self.http_request('POST', 'v1/orgwhitelist/upload/', params={'remove_existing': 'false'},
                                 files=file_data)

    def create_whitelist_entry_without_file_request(self, whitelist: list) -> dict:
        """ Creates a whitelist entries in ThreatStream according to arguments data.
        Args:
            whitelist (str): List of indicators.
        Returns:
            A response object in a form of a dictionary.
        """
        return self.http_request('POST', 'v1/orgwhitelist/bulk/', json=assign_params(whitelist=whitelist))

    def update_whitelist_entry_note_request(self, entry_id: Optional[str], note: Optional[str]):
        """ Updates a whitelist entry note in ThreatStream.
        Args:
            entry_id (str): Unique ID assigned to the entry.
        """
        url_suffix = f'v1/orgwhitelist/{entry_id}/'
        self.http_request('PATCH', url_suffix, data=json.dumps(assign_params(notes=note)), resp_type='text')

    def delete_whitelist_entry_request(self, entry_id: Optional[str]):
        """ Deletes a whitelist entry in ThreatStream.
        Args:
            entry_id (str): Unique ID assigned to the entry.
        """
        self.http_request('DELETE', f'v1/orgwhitelist/{entry_id}/', resp_type='text')

    def list_import_job_request(self, import_id: Optional[str], params: dict) -> dict:
        """ Gets a list of all the import job in ThreatStream.
            If a specific import_id is given, it will return the information about this import.
        Args:
            import_id (int): Unique ID assigned to the import.
            params (dict): The request params.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = 'v1/importsession/'
        if import_id:
            url_suffix = f'v1/importsession/{import_id}/'
        return self.http_request('GET', url_suffix, params=params)

    def approve_import_job_request(self, import_id: Optional[str]) -> dict:
        """
        Approving all observables in an import job
        Args:
            import_id (Str):  The id of a specific import entry.
        Returns:
                A response object in a form of a dictionary.
        """
        url_suffix = f'v1/importsession/{import_id}/approve_all/'
        return self.http_request('PATCH', url_suffix)

    def edit_classification_job_request(self, import_id: str = None, data: str = None) -> dict:
        """
        Edit observables in an import job
        Args:
            import_id (Str):  The id of a specific import entry.
            data (Str): The json array of edits to make to cloned observable
        Returns:
                A response object in a form of a dictionary.
        """
        url_suffix = f'v1/importsession/{import_id}/edit_classification/'
        return self.http_request('PATCH', url_suffix, data=data)

    def search_threat_model_request(self, params: dict) -> dict:
        """
        Gets list of threat model according to search parameters
        Args:
            params (dict): The request params.
        Returns:
                A response object in a form of a dictionary.
        """
        return self.http_request('GET', 'v1/threat_model_search/', params=params)

    def add_threat_model_association_request(self, entity_type_url: Optional[str], entity_id: Optional[str],
                                             associated_entity_type_url: Optional[str],
                                             associated_entity_ids_list: Optional[list]) -> dict:
        """
        Addes association between threat models
        Args:
            entity_type (Str): The type of threat model entity on which you are adding the association.
            entity_id (Str): The ID of the threat model entity on which you are adding the association.
            associated_entity_type (Str): The type of threat model entity on which you are adding the association.
            associated_entity_ids (Str): The entity id we want to associate with the primary entity.
        Returns:
                A response object in a form of a dictionary.
        """
        url_suffix = f'v1/{entity_type_url}/{entity_id}/{associated_entity_type_url}/bulk_add/'
        return self.http_request("POST", url_suffix,
                                 json={'ids': associated_entity_ids_list})

    def add_indicator_tag(self, indicator_ids: list[str], tags: list[str]):
        data_request = {
            "ids": indicator_ids,
            "tags": [{"name": tag, "tlp": "red"} for tag in tags],
        }
        self.http_request(
            method="POST",
            url_suffix="v2/intelligence/bulk_tagging/",
            data=json.dumps(data_request))

    def remove_indicator_tag(self, indicator_ids: list[str], tags: list[str]):
        data_request = {
            "ids": indicator_ids,
            "tags": [{"name": tags}],
        }

        self.http_request(
            method="PATCH",
            url_suffix="v2/intelligence/bulk_remove_tags/",
            data=json.dumps(data_request))


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

        indicator_default_score = params.get('indicator_default_score')
        if indicator_default_score and indicator_default_score == 'Unknown':
            self.default_score = Common.DBotScore.NONE
        else:
            self.default_score = Common.DBotScore.GOOD

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
            return Common.DBotScore.BAD if confidence >= defined_threshold else self.default_score
        else:
            if confidence > DEFAULT_MALICIOUS_THRESHOLD:
                return Common.DBotScore.BAD
            if confidence > DEFAULT_SUSPICIOUS_THRESHOLD:
                return Common.DBotScore.SUSPICIOUS
            else:
                return self.default_score


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
    if 'threat_model_association' in args:
        args['threat_model_association'] = argToBoolean(args.pop('threat_model_association', False))

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
               if k in indicator_mapping}
    context['Tags'] = get_tags(indicator)
    context['Severity'] = demisto.get(indicator, 'meta.severity') or 'low'
    return context


def parse_network_elem(element_list, context_prefix):
    """
        Parses the network elements list and returns a new dictionary.
    """
    return [{
        F'{context_prefix}Source': e.get('src', ''),
        F'{context_prefix}Destination': e.get('dst', ''),
        F'{context_prefix}Port': e.get('dport', ''),
    } for e in element_list]


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


def create_intelligence_relationship(client: Client, indicator, ioc_type, entity_b, entity_b_type):
    relationship = None
    if not client.should_create_relationships:
        return relationship

    if entity_b:
        relationship = EntityRelationship(entity_a=indicator['value'],
                                          entity_a_type=ioc_type,
                                          name=EntityRelationship.Relationships.RELATED_TO,
                                          entity_b=entity_b,
                                          entity_b_type=entity_b_type,
                                          source_reliability=client.reliability,
                                          brand=THREAT_STREAM,
                                          reverse_name=EntityRelationship.Relationships.RELATED_TO)
    return relationship


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client):
    """
    Performs basic get request to get item samples
    """
    client.http_request('GET', 'v2/intelligence/', params={'limit': 1})
    return 'ok'


def ips_reputation_command(client: Client, score_calc: DBotScoreCalculator, ip, status, threshold=None,
                           threat_model_association=False):
    results = []  # type: ignore
    ips = argToList(ip, ',')
    for single_ip in ips:
        results.append(get_ip_reputation(client, score_calc, single_ip, status, threshold, threat_model_association))
    return results


def get_ip_reputation(client: Client, score_calc: DBotScoreCalculator, ip, status, threshold=None,
                      threat_model_association=False):
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
        return create_indicator_result_with_dbotscore_unknown(indicator=ip,
                                                              indicator_type=DBotScoreType.IP,
                                                              reliability=client.reliability)

    # Convert the tags objects into s string for the human readable.
    threat_context = get_generic_threat_context(indicator)
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'IP reputation for: {ip}', threat_context | {'Tags': tags_csv})

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

    if threat_model_association:
        intelligence_relationships, outputs = get_intelligence(client,
                                                               indicator,
                                                               FeedIndicatorType.IP
                                                               )
        if intelligence_relationships:
            relationships.extend(intelligence_relationships)
        threat_context.update(outputs)
        human_readable += create_human_readable(outputs)

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


def return_params_of_pagination_or_limit(page: int = None, page_size: int = None, limit: int = None):
    """
    Returns request params accroding to page, page_size and limit arguments.
    Args:
        page: page.
        page_size: page size.
        limit: limit.
    Returns:
        params (dict).
    """
    params = {}
    if (page_size and not page) or (not page_size and page):
        raise DemistoException('Please specify page and page_size')
    elif page and isinstance(page, int) and isinstance(page_size, int):
        params['offset'] = (page * page_size) - (page_size)
        params['limit'] = page_size
    else:
        params['limit'] = limit or DEFAULT_LIMIT_PAGE_SIZE
    return params


def header_transformer(header: str) -> str:
    """
    Returns a correct header.
    Args:
        header (Str): header.
    Returns:
        header (Str).
    """
    if header == 'notify_me':
        return 'Is Notify Me'
    if header == 'modified_ts':
        return 'Modified At'
    if header == 'created_ts':
        return 'Created At'
    if header == 'email':
        return 'Submitted By'
    if header == 'numRejected':
        return 'Excluded'
    if header == 'numIndicators':
        return 'Included'
    if header == 'approved_by':
        return 'Reviewed By'
    if header == 'model_type':
        return 'Type'
    return string_to_table_header(header)


def list_rule_command(client: Client, rule_id: str = None, limit: str = '50', page: str = None,
                      page_size: str = None) -> CommandResults:
    """
    Returns a list rules.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        rule_id: Unique ID assigned to the rule.
        limit: The maximum number of results to return.
        page: The page number of the results to retrieve.
        page_size: The maximum number of objects to retrieve per page.
    Returns:
        (CommandResults).
    """
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    res = client.list_rule_request(rule_id, params)
    data = res if rule_id else res.get('objects', [])
    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Rule",
        outputs_key_field="id",
        outputs=data,
        readable_output=tableToMarkdown("Rules", data, removeNull=True,
                                        headerTransform=header_transformer,
                                        headers=["name", "id", "matches", "intelligence_initiatives",
                                                 "created_ts", "modified_ts", "notify_me", "is_enabled"]),
        raw_response=res,
    )


def create_request_body_rule(rule_id: str = None, rule_name: str = None, keywords: str = None, match_include: str = None,
                             actor_ids: str = None, campaign_ids: str = None, investigation_action: str = None,
                             new_investigation_name: str = None, existing_investigation_id: str = None,
                             exclude_indicator: str = None, include_indicator: str = None,
                             exclude_notify_org_whitelisted: str = None, exclude_notify_owner_org: str = None,
                             incident_ids: str = None, malware_ids: str = None, signature_ids: str = None,
                             threat_bulletin_ids: str = None,
                             ttp_ids: str = None, vulnerability_ids: str = None, tags: str = None) -> dict:
    """
    Creates a request body for create and update rule command.
    Args:
        client (Client): Client to perform calls to Anomali ThreatStream service.
        rule_id: The rule id.
        rule_name: Rule name.
        keywords: A comma-separated list of keywords.
        match_include: Possible values: observables, sandbox reports, threat bulletins, signatures, vulnerabilities.
        actor_ids: A comma-separated list of actor IDs.
        campaign_ids: A comma-separated list of campaign IDs.
        investigation_action: Possible values: Create New, Add To Existing, No Action.
        new_investigation_name: Name of investigation.
        existing_investigation_id: An id of existing investigation.
        exclude_indicator: A comma-separated list of indicator type.
        include_indicator: A comma-separated list of indicator type.
        exclude_notify_org_whitelisted: 'true' or 'false' value.
        exclude_notify_owner_org: 'true' or 'false' value.
        incident_ids: A comma-separated list of incident IDs.
        malware_ids: A comma-separated list of malwares IDs.
        signature_ids: A comma-separated list of signatures IDs.
        threat_bulletin_ids: A comma-separated list of threat bulletin IDs.
        ttp_ids: A comma-separated list of ttp IDs.
        vulnerability_ids: A comma-separated list of vulnerabilities IDs.
        tags: A comma-separated list of tags.
    Returns:
        (CommandResults).
    """
    match_include_list = argToList(match_include.lower()) if match_include else []
    tag_list = argToList(tags) or []
    request_body = assign_params(
        name=rule_name,
        keywords=argToList(keywords),
        actors=argToList(actor_ids),
        match_observables='observables' in match_include_list,
        match_reportedfiles='sandbox reports' in match_include_list,
        match_tips='threat bulletins' in match_include_list,
        match_signatures='signatures' in match_include_list,
        match_vulnerabilities='vulnerabilities' in match_include_list,
        campaigns=argToList(campaign_ids),
        exclude_impacts=argToList(exclude_indicator),
        match_impacts=argToList(include_indicator),
        exclude_notify_org_whitelisted=argToBoolean(exclude_notify_org_whitelisted) if exclude_notify_org_whitelisted else None,
        exclude_notify_owner_org=argToBoolean(exclude_notify_owner_org) if exclude_notify_owner_org else None,
        incidents=argToList(incident_ids),
        malware=argToList(malware_ids),
        signatures=argToList(signature_ids),
        tips=argToList(threat_bulletin_ids),
        ttps=argToList(ttp_ids),
        vulnerabilities=argToList(vulnerability_ids),
        tags=[{'name': tag} for tag in tag_list] if tag_list else None
    )
    if new_investigation_name:
        request_body['create_investigation'] = True
        request_body['investigation_config'] = {'name': new_investigation_name}
    if existing_investigation_id:
        request_body['create_investigation'] = True
        request_body['investigation'] = existing_investigation_id
    return request_body


def create_rule_command(client: Client, **kwargs) -> CommandResults:
    """
    Creates a new rule in ThreatStream.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        rule_name: Rule name.
        keywords: A comma-separated list of keywords.
        match_include: Possible values: observables, sandbox reports, threat bulletins, signatures, vulnerabilities.
        actor_ids: A comma-separated list of actor IDs.
        campaign_ids: A comma-separated list of campaign IDs.
        investigation_action: Possible values: Create New, Add To Existing, No Action.
        new_investigation_name: Name of investigation.
        existing_investigation_id: An id of existing investigation.
        exclude_indicator: A comma-separated list of indicator type.
        include_indicator: A comma-separated list of indicator type.
        exclude_notify_org_whitelisted: 'true' or 'false' value.
        exclude_notify_owner_org: 'true' or 'false' value.
        incident_ids: A comma-separated list of incident IDs.
        malware_ids: A comma-separated list of malwares IDs.
        signature_ids: A comma-separated list of signatures IDs.
        threat_bulletin_ids: A comma-separated list of threat bulletin IDs.
        ttp_ids: A comma-separated list of ttp IDs.
        vulnerability_ids: A comma-separated list of vulnerabilities IDs.
        tags: A comma-separated list of tags.
    Returns:
        (CommandResults).
    """
    investigation_action: Optional[str] = kwargs.get('investigation_action')
    new_investigation_name: Optional[str] = kwargs.get('investigation_action')
    existing_investigation_id: Optional[str] = kwargs.get('existing_investigation_id')
    validate_investigation_action(investigation_action, new_investigation_name, existing_investigation_id)
    request_body = create_request_body_rule(**kwargs)
    res = client.create_rule_request(request_body)
    demisto.debug("create rule command request body", request_body)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Rule',
        outputs_key_field="id",
        outputs=res,
        readable_output=f'The rule was created successfully with id: {res.get("id")}.',
        raw_response=res,
    )


def validate_investigation_action(investigation_action: Optional[str], new_investigation_name: Optional[str],
                                  existing_investigation_id: Optional[str]):
    """
        Validate the arguments new_investigation_name and existing_investigation_id
        according to the investigation_action arguments
    """
    if investigation_action == 'Create New' and (not new_investigation_name):
        raise DemistoException("Please ensure to provide the 'new_investigation_name'"
                               " argument when selecting the 'Create New' option for the 'investigation_action' argument.")
    if investigation_action == 'Add To Existing' and (not existing_investigation_id):
        raise DemistoException("Please ensure to provide the 'existing_investigation_id'"
                               " argument when selecting the 'Add To Existing' option for the 'investigation_action' argument.")


def update_rule_command(client: Client, **kwargs) -> CommandResults:
    """
    Updates exists rule from ThreatStream.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        rule_id: Rule ID.
        rule_name: Rule name.
        keywords: A comma-separated list of keywords.
        match_include: Possible values: observables, sandbox reports, threat bulletins, signatures, vulnerabilities.
        actor_ids: A comma-separated list of actor IDs.
        campaign_ids: A comma-separated list of campaign IDs.
        investigation_action: Possible values: Create New, Add To Existing, No Action.
        new_investigation_name: Name of investigation.
        existing_investigation_id: An id of existing investigation.
        exclude_indicator: A comma-separated list of indicator type.
        include_indicator: A comma-separated list of indicator type.
        exclude_notify_org_whitelisted: 'true' or 'false' value.
        exclude_notify_owner_org: 'true' or 'false' value.
        incident_ids: A comma-separated list of incident IDs.
        malware_ids: A comma-separated list of malwares IDs.
        signature_ids: A comma-separated list of signatures IDs.
        threat_bulletin_ids: A comma-separated list of threat bulletin IDs.
        ttp_ids: A comma-separated list of ttp IDs.
        vulnerability_ids: A comma-separated list of vulnerabilities IDs.
        tags: A comma-separated list of tags.
    Returns:
        (CommandResults).
    """
    investigation_action: Optional[str] = kwargs.get('investigation_action')
    new_investigation_name: Optional[str] = kwargs.get('investigation_action')
    existing_investigation_id: Optional[str] = kwargs.get('existing_investigation_id')
    rule_id: Optional[str] = kwargs.get('rule_id')
    validate_investigation_action(investigation_action, new_investigation_name, existing_investigation_id)
    request_body = create_request_body_rule(**kwargs)
    res = client.update_rule_request(rule_id, request_body)
    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Rule",
        outputs_key_field="id",
        outputs=res,
        readable_output=tableToMarkdown("Rules", res, removeNull=True, headerTransform=header_transformer,
                                        headers=["name", "id", "matches", "intelligence_initiatives", "created_ts",
                                                 "modified_ts", "notify_me", "is_enabled"]),
        raw_response=res,
    )


def delete_rule_command(client: Client, rule_id=None) -> CommandResults:
    """
    Deletes a rules.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        rule_id: Unique ID assigned to the rule.
    Returns:
        (CommandResults).
    """
    client.delete_rule_request(rule_id)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Rule',
        readable_output='The rule was deleted successfully.',
    )


def list_user_command(client: Client, user_id: str = None, limit: str = '50',
                      page: str = None, page_size: str = None) -> CommandResults:
    """
    Returns a list of users.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        user_id: Unique ID assigned to the user.
        limit: The maximum number of results to return.
        page: The page number of the results to retrieve.
        page_size: The maximum number of objects to retrieve per page.
    Returns:
        (CommandResults).
    """
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    res = client.list_users_request(user_id, params)
    data = res if user_id else res.get('objects', [])
    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.User",
        outputs_key_field="id",
        outputs=data,
        readable_output=tableToMarkdown(
            "Users", data, removeNull=True,
            headerTransform=string_to_table_header,
            headers=["name", "user_id", "email", "is_active", "last_login"],
        ),
        raw_response=res,
    )


def list_investigation_command(client: Client, investigation_id: str = None, limit: str = '50', page: str = None,
                               page_size: str = None) -> CommandResults:
    """
    Returns a list of investigations.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        investigation_id:  Unique ID assigned to the investigation.
        limit: The maximum number of results to return.
        page: The page number of the results to retrieve.
        page_size: The maximum number of objects to retrieve per page.
    Returns:
        (CommandResults).
    """

    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    res = client.list_investigation_request(investigation_id, params)
    data = res if investigation_id else res.get('objects', [])
    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Investigation",
        outputs_key_field="id",
        outputs=data,
        readable_output=tableToMarkdown('Investigations', data, removeNull=True,
                                        headerTransform=header_transformer,
                                        headers=['name', 'id', 'created_ts', 'status', 'source_type', 'assignee', 'reporter'],
                                        json_transform_mapping={'assignee': JsonTransformer(keys=['email'],
                                                                                            func=lambda hdr: hdr.get('email', '')
                                                                                            ),
                                                                'reporter': JsonTransformer(keys=['email'],
                                                                                            func=lambda hdr: hdr.get('email', ''))
                                                                }),
        raw_response=res,
    )


def create_investigation_command(client: Client, name: str = None, description: str = None, priority: str = None,
                                 status: str = None, tags: str = None, tlp: str = None,
                                 assignee_id: str = None, connect_related_indicators: str = None,
                                 associated_signature_ids: str = None, associated_threat_bulletin_ids: str = None,
                                 associated_ttp_ids: str = None, associated_vulnerability_ids: str = None,
                                 associated_actor_ids: str = None, associated_campaign_ids: str = None,
                                 associated_incident_ids: str = None,
                                 associated_observable_ids: str = None) -> CommandResults:
    """
    Creates an investigation on Anomali ThreatStream.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        name: Unique name the user want to assigned to the investigation.
        description: Investigation description.
        priority: Investigation priority. Possible values are: 'Very Low', 'Low', 'Medium', 'High', 'Very High'.
        status: Investigation status. Possible values are: 'Completed', 'In-Progress', 'Pending', 'Unassigned'.
        tags: A comma-separated list of tags. For example, tag1,tag2.
        tlp: The TLP of the investigation.
        assignee_id: user id to assignee for the investigation.
        connect_related_indicators: When enabled, observables related to the entity
        you are associating with the investigation are also added.
        associated_signature_ids: A comma-separated list of signature ids.
        associated_threat_bulletin_ids: A comma-separated list of threat bulletin ids.
        associated_ttp_ids: A comma-separated list of ttp ids.
        associated_vulnerability_ids: A comma-separated list of vulnerability ids.
        associated_actor_ids: A comma-separated list of actor ids.
        associated_campaign_ids: A comma-separated list of campaign ids.
        associated_incident_ids: A comma-separated list of incident ids.
        associated_observable_ids: A comma-separated list of observable ids.
    Returns:
        (CommandResults).
    """
    add_related_indicators = 1 if connect_related_indicators and argToBoolean(connect_related_indicators) else 0
    elements_list, associated_list = create_element_list({
        'vulnerability': argToList(associated_vulnerability_ids),
        'actor': argToList(associated_actor_ids),
        'intelligence2': argToList(associated_observable_ids),
        'incident': argToList(associated_incident_ids),
        'signature': argToList(associated_signature_ids),
        'tipreport': argToList(associated_threat_bulletin_ids),
        'ttp': argToList(associated_ttp_ids),
        'campaign': argToList(associated_campaign_ids),
        'add_related_indicators': add_related_indicators,
        'is_update': False,
        'investigation_id': 0,
    })
    demisto.debug('elements_list_create_investigation', elements_list)
    tag_list = argToList(tags) or []
    request_body = assign_params(
        name=name,
        description=description,
        priority=priority.lower().replace(' ', '') if priority else None,
        status=status.lower() if status else None,
        tags=tag_list or None,
        tlp=tlp.lower() if tlp else None,
        assignee_id=arg_to_number(assignee_id),
        assignee_type='user' if assignee_id else None,
        add_related_indicators=add_related_indicators,
        elements=elements_list,
    )
    res = client.create_investigation_request(request_body)
    readable_output = f'Investigation was created successfully with ID: {res.get("id")}.\n'
    if res.get('all_added') is False:
        data = res.get('elements', [])
        successful_ids = [
            str(entity.get('r_id'))
            for entity in data
            if str(entity.get('r_id')) in associated_list
        ]
        readable_output = f'Investigation was created successfully with ID: {res.get("id")}.\n' \
                          f' Elements with IDs {", ".join(map(str, successful_ids))} was added successfully' \
                          ' to the investigation.ֿ\n'
    elif res.get('all_added') is True:
        readable_output = f'Investigation was created successfully with ID: {res.get("id")}.\n' \
            'All Elements was added successfully to the investigation.'
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigation',
        outputs_key_field='id',
        readable_output=readable_output,
        raw_response=res,
        outputs=res)


def update_investigation_command(client: Client, investigation_id: str = None, description: str = None, priority: str = None,
                                 status: str = None, tags: str = None, tlp: str = None,
                                 assignee_id: str = None) -> CommandResults:
    """
    Updates an investigation on Anomali ThreatStream.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        investigation_id: Unique ID of the investigation.
        description: Investigation description.
        priority: Investigation priority. Possible values are: 'Very Low', 'Low', 'Medium', 'High', 'Very High'.
        status: Investigation status. Possible values are: 'Completed', 'In-Progress', 'Pending', 'Unassigned'.
        tags: A comma-separated list of tags. For example, tag1,tag2.
        assignee_id: User id to assignee for the investigation.
    Returns:
        (CommandResults).
    """
    tag_list = argToList(tags) or []
    request_body = assign_params(
        description=description,
        priority=priority.lower().replace(' ', '') if priority else None,
        status=status.lower() if status else None,
        tags=tag_list or None,
        tlp=tlp.lower() if tlp else None,
        assignee_id=arg_to_number(assignee_id),
        assignee_type='user' if assignee_id else None,
    )
    demisto.debug("update investigation request body", request_body)
    res = client.update_investigation_request(investigation_id, request_body)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigation',
        outputs_key_field='id',
        outputs=res,
        readable_output=f'Investigation was updated successfully with ID: {res.get("id")}',
        raw_response=res,
    )


def delete_investigation_command(client: Client, investigation_id: str = None) -> CommandResults:
    """
    Deletes an investigation on Anomali ThreatStream.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        investigation_id: Unique ID of the investigation.
    Returns:
        (CommandResults).
    """
    client.delete_investigation_request(investigation_id)
    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Investigation',
        readable_output='Investigation was deleted successfully.',
    )


def add_investigation_element_command(client: Client, investigation_id: str = None, connect_related_indicators: str = None,
                                      associated_signature_ids: str = None, associated_threat_bulletin_ids: str = None,
                                      associated_ttp_ids: str = None, associated_vulnerability_ids: str = None,
                                      associated_actor_ids: str = None, associated_campaign_ids: str = None,
                                      associated_incident_ids: str = None,
                                      associated_observable_ids: str = None) -> CommandResults:
    """
    Addes an elements to an investigation.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        investigation_id: Unique name the user want to assigned to the investigation.
        connect_related_indicators: When enabled, observables related to the entity you are associating with the
        investigation are also added.
        associated_signature_ids: A comma-separated list of signature ids.
        associated_threat_bulletin_ids: A comma-separated list of threat bulletin ids.
        associated_ttp_ids: A comma-separated list of ttp ids.
        associated_vulnerability_ids: A comma-separated list of vulnerability ids.
        associated_actor_ids: A comma-separated list of actor ids.
        associated_campaign_ids: A comma-separated list of campaign ids.
        associated_incident_ids: A comma-separated list of incident ids.
        associated_observable_ids: A comma-separated list of observable ids.
    Returns:
        (CommandResults).
    """
    add_related_indicators = 1 if connect_related_indicators and argToBoolean(connect_related_indicators) else 0
    elements_list, associated_list = create_element_list({
        'vulnerability': argToList(associated_vulnerability_ids),
        'actor': argToList(associated_actor_ids),
        'intelligence2': argToList(associated_observable_ids),
        'incident': argToList(associated_incident_ids),
        'signature': argToList(associated_signature_ids),
        'tipreport': argToList(associated_threat_bulletin_ids),
        'ttp': argToList(associated_ttp_ids),
        'campaign': argToList(associated_campaign_ids),
        'add_related_indicators': add_related_indicators,
        'is_update': True,
        'investigation_id': arg_to_number(investigation_id),
    })
    demisto.debug('add investigation elements', elements_list)
    request_body = assign_params(objects=elements_list)
    res = client.add_investigation_element_request(arg_to_number(investigation_id), request_body)
    if not res.get('objects'):
        raise DemistoException('The addition of elements to the investigation has failed. '
                               'Please verify the accuracy of the investigation_id argument.')
    if res.get('all_added') is False:
        exists_elements = res.get('already_exists_elements_count')
        if isinstance(exists_elements, int) and exists_elements >= len(associated_list) and \
                res.get('added_elements_count') == 0:
            readable_output = 'All the requested elements already exist in the investigation.'
        else:
            data = res.get('objects', [])
            unsuccessful_ids = []
            successful_ids: list[int] = []
            for id in associated_list:
                successful_ids.extend(id for entity in data if str(id) == str(entity.get('r_id')))
                if id not in successful_ids:
                    unsuccessful_ids.append(id)
            if unsuccessful_ids:
                readable_output = f'The following elements with IDs were successfully added: ' \
                                  f'{", ".join(map(str, successful_ids))}.' \
                                  ' However, attempts to add elements with IDs: ' \
                                  f'{", ".join(map(str, unsuccessful_ids))} were unsuccessful.'
            else:
                readable_output = 'The following elements with IDs were successfully added:' \
                                  f' {", ".join(map(str, successful_ids))}.'
    else:
        readable_output = f'All The elements was added successfully to investigation ID: {investigation_id}'
    return CommandResults(
        readable_output=readable_output,
        raw_response=res,
    )


def list_whitelist_entry_command(client: Client, format: str = 'json', limit: str = '50',
                                 page: str = None, page_size: str = None) -> CommandResults:
    """
    Get a list of whitelist entries.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        format:  A URL parameter to define the format of the response CSV or JSON.
        limit: The maximum number of results to return.
        page: The page number of the results to retrieve.
        page_size:  The maximum number of objects to retrieve per page.
    Returns:
        (CommandResults).
    """
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    res = client.list_whitelist_entry_request(format, params)
    if format and format.lower() == 'json':
        data = res.get('objects', [])
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.WhitelistEntry',
            outputs_key_field='id',
            outputs=data,
            readable_output=tableToMarkdown('Whitelist entries', data, removeNull=True,
                                            headerTransform=header_transformer,
                                            headers=['id', 'value', 'resource_uri', 'created_ts',
                                                     'modified_ts', 'value_type', 'notes']),
            raw_response=res,
        )
    else:
        return fileResult(filename=f'whitelist-entries-{date.today().strftime("%b-%d-%Y")}.csv',
                          data=res, file_type=EntryType.ENTRY_INFO_FILE)


def create_indicators_list(names_and_indicators_list: list[tuple[str, list]], notes: Optional[str]) -> list:
    """
    Creates an elements list.
    Args:
        names_and_indicators_list (Str):  a list of tuples each tuple
                                          include an indicator type and list of indicators with the same type.
        notes: Notes for all the indicators.

    Returns:
        A list of dict.
    """
    indicators_list_to_return: list = []
    for name_and_indicators_list in names_and_indicators_list:
        if indicators_list := name_and_indicators_list[0] and name_and_indicators_list[1]:
            if notes:
                indicators_list_to_return.extend([{'value_type': name_and_indicators_list[0], 'value': indicator,
                                                 'notes': notes}
                                                  for indicator in indicators_list])
            else:
                indicators_list_to_return.extend([{'value_type': name_and_indicators_list[0], 'value': indicator}
                                                 for indicator in indicators_list])
    return indicators_list_to_return


def create_whitelist_entry_command(client: Client, entry_id: str = None, cidr: str = None,
                                   domains: str = None, emails: str = None,
                                   ips: str = None, md5: str = None,
                                   urls: str = None, user_agents: str = None,
                                   note: str = None) -> CommandResults:
    """
    "Creates a new whitelist entry.
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        entry_id: The file entry id.
        domains: A comma-separated list of domains.
        emails: A comma-separated list of emails.
        ips: A comma-separated list of ips.
        md5: A comma-separated list of md5.
        urls: A comma-separated list of urls.
        user_agents : A comma-separated list of user agents.
        note: A note string.
    Returns:
        (CommandResults).
    """
    if entry_id:
        get_file_path_res = demisto.getFilePath(entry_id)
        file_path = get_file_path_res["path"]
        file_data = {'file': open(file_path, 'rb')}
        res = client.create_whitelist_entry_with_file_request(file_data)
        if res.get('success'):
            return CommandResults(readable_output=res.get('message'),
                                  raw_response=res)
        else:
            return CommandResults(readable_output=f'ERROR: {res.get("message")}',
                                  raw_response=res)
    else:
        whitelist = create_indicators_list([('domain', argToList(domains)),
                                            ('email', argToList(emails)),
                                            ('ip', argToList(ips)),
                                            ('md5', argToList(md5)),
                                            ('url', argToList(urls)),
                                            ('user-agent', argToList(user_agents)),
                                            ('cidr', argToList(cidr))],
                                           note)
        demisto.debug('whitelist - create_whitelist_entry_command', whitelist)
        res = client.create_whitelist_entry_without_file_request(whitelist)
        return CommandResults(readable_output=res.get("message"),
                              raw_response=res)


def update_whitelist_entry_note_command(client: Client, entry_id: str = None,
                                        note: str = None) -> CommandResults:
    """
    "Modify contextual notes associated with existing whitelist entries
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        entry_id: The id of a specific whitelist entry.
        note: A note string.
    Returns:
        (CommandResults).
    """
    client.update_whitelist_entry_note_request(entry_id, note)
    return CommandResults(readable_output='The note was updated successfully.')


def delete_whitelist_entry_command(client: Client, entry_id: str = None) -> CommandResults:
    """
    Delete a whitelist entry
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        entry_id:  The id of a specific whitelist entry.
    Returns:
        (CommandResults).
    """
    client.delete_whitelist_entry_request(entry_id)
    return CommandResults(readable_output='The entity was deleted successfully')


def list_import_job_command(client: Client, import_id: str = None, status_in: str = None,
                            limit: str = '50', page: str = None,
                            page_size: str = None) -> CommandResults:
    """
    Gets a list of import job
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        import_id:  The id of a specific import entry.
        status_in:  The status of the entry.
        limit: The maximum number of results to return.
        page: The page number of the results to retrieve.
        page_size:  The maximum number of objects to retrieve per page.
    Returns:
        (CommandResults).
    """
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    if status_in == 'Ready To Review':
        params['status'] = 'done'
    elif status_in == 'Rejected':
        params['status'] = 'deleted'
    elif status_in:
        params['status'] = status_in.lower()

    res = client.list_import_job_request(import_id, params)
    outputs = res if import_id else res.get("objects", [])
    readable_output = tableToMarkdown("Import entries", outputs, removeNull=True, headerTransform=header_transformer,
                                      headers=["id", "date", "status", "approved_by", "email", "intelligence_initiatives",
                                               "numIndicators", "numRejected", "tags"],
                                      json_transform_mapping={
                                          'approved_by': JsonTransformer(keys=['email'], func=lambda hdr: hdr.get('email', '')),
                                          'tags': JsonTransformer(func=lambda hdr: ", ".join([item.get('name') for item in hdr])),
                                          'intelligence_initiatives': JsonTransformer(func=lambda hdr:
                                                                                      ", ".join([item.get('type')
                                                                                                for item in hdr]))})
    if not import_id:
        for item in outputs:
            item['ImportID'] = item.pop('id')
            item['JobID'] = item.pop('jobID')
    else:
        outputs['ImportID'] = outputs.pop('id')
        outputs['JobID'] = outputs.pop('jobID')
    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.Import",
        outputs_key_field="ImportID",
        ignore_auto_extract=True,
        outputs=outputs,
        readable_output=readable_output,
        raw_response=res,
    )


def approve_import_job_command(client: Client, import_id: str = None) -> CommandResults:
    """
    Approving all observables in an import job
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        import_id:  The id of a specific import entry.
    Returns:
        (CommandResults).
    """
    res = client.approve_import_job_request(import_id)
    if res.get("approved_by_id"):
        readable_output = 'The import session was successfully approved.'
    else:
        raise DemistoException('Import Session Approval Failed.')
    return CommandResults(
        readable_output=readable_output,
        raw_response=res,
    )


def validate_values_search_threat_model(model_type: str = None, publication_status: str = None,
                                        signature_type: str = None):
    """
    Validates arguments values in search-threat-model command.
    Args:
        model_type (Str): A comma-separated list of model types. Supported values are: actor, attackpattern , campaign,
        courseofaction, incident,identity, infrastructure, intrusionset, malware,signature, tipreport, ttp, tool, vulnerability.
        publication_status (Str): A comma-separated list of publication status. Supported values are: new, pending_review,
        review_requested, reviewed, published statuses.
        signature_type (Str): A comma-separated list of signature type. Supported values are: Bro, Carbon Black Query,
        ClamAV, Custom, CybOX, OpenIOC, RSA NetWitness, Snort, Splunk Query, Suricata, YARA.
    Returns:
        (DemistoException).
    """
    model_type_list = argToList(model_type)
    publication_status_list = argToList(publication_status)
    signature_type_list = argToList(signature_type)
    raise_exception_model_type = False
    invalid_model_type = []
    raise_exception_publication_status = False
    invalid_publication_status = []
    raise_exception_signature_type = False
    invalid_signature_type = []
    for model_type_item in model_type_list:
        if model_type_item.lower() not in MODEL_TYPE_LIST:
            raise_exception_model_type = True
            invalid_model_type.append(model_type_item)
    if raise_exception_model_type:
        raise DemistoException(f'The model_type argument contains the following invalid values: '
                               f'{", ".join(map(str, invalid_model_type))}')
    for publication_status_item in publication_status_list:
        if publication_status_item.lower() not in PUBLICATION_STATUS_LIST:
            raise_exception_publication_status = True
            invalid_publication_status.append(publication_status_item)
    if raise_exception_publication_status:
        raise DemistoException(f'The publication_status argument contains the following invalid values: '
                               f'{", ".join(map(str, invalid_publication_status))}')
    for signature_type_item in signature_type_list:
        if signature_type_item not in SIGNATURE_TYPE_LIST:
            raise_exception_signature_type = True
            invalid_signature_type.append(signature_type_item)
    if raise_exception_signature_type:
        raise DemistoException('The signature_type argument contains the following invalid values: '
                               f'{", ".join(map(str, invalid_signature_type))}')


def search_threat_model_command(client: Client, model_type: str = None, name: str = None,
                                keyword_search: str = None, alias: str = None,
                                feed_id: str = None, is_email: str = None,
                                is_public: str = None, publication_status: str = None,
                                signature_type: str = None, tags: str = None,
                                trusted_circle_id: str = None,
                                limit: str = '50', page: str = None, page_size: str = None) -> CommandResults:
    """
    Retrieve threat model entities from ThreatStream
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        model_type: A comma-separated list of model types. Supported values are: actor, attackpattern , campaign,
        courseofaction, incident, identity, infrastructure, intrusionset, malware, signature, tipreport, ttp, tool, vulnerability.
        name: The name of the threat model.
        alias: Other names by which the actors are known.
        keyword_search: Free text to search string in the fields: Aliases, Description, Name, Tags.
        feed_id: Numeric ID of the threat feed that provided the Threat Model entity.
        is_email: Whether the threat bulletin was created as a result of an email import.
        is_public: Whether the entity is public or private. True—if the Campaign is public, False—if the Campaign
        is private or belongs to a Trusted Circle.
        publication_status: A comma-separated list of publication status. Supported values are: new, pending_review,
        review_requested, reviewed, published statuses..
        signature_type: A comma-separated list of signature type. Supported values are: Bro, Carbon Black Query,
        ClamAV, Custom, CybOX, OpenIOC, RSA+NetWitness, Snort, Splunk+Query, Suricata, YARA.
        tags: A comma-spareated list of Additional comments and context associated with the observable when it
        was imported from its original threat feed.
        trusted_circle_ids: Used for querying entities associated with specified trusted circles..
        limit: The maximum number of results to return.
        page: The page number of the results to retrieve.
        page_size:  The maximum number of objects to retrieve per page.
    Returns:
        (CommandResults).
    """
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    validate_values_search_threat_model(model_type, publication_status, signature_type)
    params.update(assign_params(
        alias=alias,
        value=keyword_search,
        feed_id=feed_id,
        name=name,
        is_email=is_email.lower() if is_email else None,
        is_public=is_public.lower() if is_public else None,
        model_type=model_type,
        publication_status=','.join(argToList(publication_status)),
        tags=','.join(argToList(tags)),
        trusted_circle_ids=trusted_circle_id,

    ))
    if signature_type:
        params['signature$type'] = ','.join(argToList(signature_type))
    demisto.debug("params to request threat_model_search", params)
    res = client.search_threat_model_request(params)
    data_res = res.get('objects', [])

    return CommandResults(
        outputs_prefix=f"{THREAT_STREAM}.ThreatModel",
        outputs_key_field="id",
        outputs=data_res,
        readable_output=tableToMarkdown("Threat model entities", data_res, removeNull=True,
                                        headerTransform=header_transformer,
                                        headers=["id", "model_type", "name", "publication_status", "modified_ts"]),
        raw_response=res,
    )


def add_threat_model_association_command(client: Client, entity_type: str = None, entity_id: str = None,
                                         associated_entity_type: str = None, associated_entity_ids: str = None) -> CommandResults:
    """
    Creates associations between threat model entities on the ThreatStream platform
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        entity_type: The type of threat model entity on which you are adding the association.
        entity_id: The ID of the threat model entity on which you are adding the association.
        associated_entity_type: The type of threat model entity on which you are adding the association.
        associated_entity_ids: The entity id we want to associate with the primary entity.
    Returns:
        (CommandResults).
    """
    entity_type_url = entity_type.replace(' ', '').lower() if entity_type else None
    associated_entity_type_url = associated_entity_type.replace(' ', '').lower() if associated_entity_type else None
    associated_entity_ids_list = [int(id) for id in argToList(associated_entity_ids)]
    num_associated_entity_ids = len(associated_entity_ids_list)
    res = client.add_threat_model_association_request(entity_type_url, entity_id,
                                                      associated_entity_type_url,
                                                      associated_entity_ids_list)
    res_ids = res.get('ids')
    associated_entity_ids_results = len(res_ids) if res.get('success') and isinstance(res_ids, list) else 0
    readable_output: str = ''
    if associated_entity_ids_results == num_associated_entity_ids:
        readable_output = f'The {associated_entity_type} entities with ids {", ".join(map(str, res.get("ids",[])))} ' \
                          f'were associated successfully to entity id: {entity_id}.'
    elif associated_entity_ids_results > 0:
        readable_output = f'Part of the {associated_entity_type} entities with ids {", ".join(map(str, res.get("ids",[])))} ' \
                          f'were associated successfully to entity id: {entity_id}.'
    else:
        raise DemistoException(f'Unsuccessful association to {associated_entity_type} entity id: {entity_id}.')
    return CommandResults(
        readable_output=readable_output,
        raw_response=res,
    )


def get_intelligence(client: Client, indicator, ioc_type):
    relationships: List[EntityRelationship] = []
    intelligence_outputs: Dict[str, Any] = {}

    for intelligence_type in INTELLIGENCE_TYPES:
        intelligence_relationships, intelligence_output = get_intelligence_information(
            client, indicator, ioc_type, intelligence_type)
        if intelligence_relationships:
            relationships.extend(intelligence_relationships)

        intelligence_outputs[INTELLIGENCE_TYPE_TO_CONTEXT[intelligence_type]] = intelligence_output

    return relationships, intelligence_outputs


def create_element_list(arguments_dict: dict) -> tuple[list, list]:
    """
    Creates an elements list.
    Args:
        arguments_dict (Str):  dict of the required argument to creat the element list.
    Returns:
        A list of dict.
    """
    # a list of all the association
    associated_list = []
    element_list = []
    investigation_id = arguments_dict.get('investigation_id')
    is_update = arguments_dict.get('is_update')
    add_related_indicators = arguments_dict.get('add_related_indicators')
    for type, ids_list in arguments_dict.items():
        if isinstance(ids_list, list):
            associated_list.extend(ids_list)
            if is_update:
                element_list.extend([{"r_type": type, "r_id": arg_to_number(id),
                                     "add_related_indicators": add_related_indicators, "investigation_id": investigation_id}
                                     for id in ids_list])
            else:
                element_list.extend([{"r_type": type, "r_id": arg_to_number(id),
                                     "add_related_indicators": add_related_indicators}
                                     for id in ids_list])
    return element_list, associated_list


def get_intelligence_information(client: Client, indicator, ioc_type, intelligence_type):

    value = indicator.get('value')
    url = f"v1/{intelligence_type}/associated_with_intelligence/"
    params = {'value': value}

    if client.remote_api:
        params['remote_api'] = 'true'

    intelligences = client.http_request('GET', url, params=params).get('objects', [])
    relationships: List[EntityRelationship] = []
    entity_b_type = INTELLIGENCE_TYPE_TO_ENTITY_TYPE[intelligence_type]

    for intelligence in intelligences:
        entity_b_name = intelligence.get('name')

        if entity_b_name:
            relationship = create_intelligence_relationship(
                client,
                indicator,
                ioc_type,
                entity_b_name,
                entity_b_type)

            if relationship:
                relationships.append(relationship)

    return relationships, intelligences


def create_human_readable(intelligence_outputs):  # pragma: no cover
    table = ''
    for intelligence in intelligence_outputs:
        table += tableToMarkdown(f'{intelligence} details:', intelligence_outputs[intelligence], headers=['name', 'id'])

    return table


def domains_reputation_command(client: Client, score_calc: DBotScoreCalculator, domain, status, threshold=None,
                               threat_model_association=False):
    """
        Wrapper function for get_domain_reputation.
    """
    results = []  # type: ignore
    domains = argToList(domain, ',')
    for single_domain in domains:
        results.append(get_domain_reputation(client, score_calc, single_domain, status, threshold, threat_model_association))
    return results


def get_domain_reputation(client: Client, score_calc: DBotScoreCalculator, domain, status, threshold=None,
                          threat_model_association=False):
    """
        Checks the reputation of given domain from ThreatStream and
        returns the indicator with highest confidence score.
    """
    # get the indicator
    params = {'value': domain, 'type': DBotScoreType.DOMAIN, 'status': status, 'limit': 0}
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return create_indicator_result_with_dbotscore_unknown(indicator=domain,
                                                              indicator_type=DBotScoreType.DOMAIN,
                                                              reliability=client.reliability)

    # Convert the tags objects into s string for the human readable.
    threat_context = get_generic_threat_context(indicator)
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'Domain reputation for: {domain}', threat_context | {'Tags': tags_csv})

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

    if threat_model_association:
        intelligence_relationships, outputs = get_intelligence(client,
                                                               indicator,
                                                               FeedIndicatorType.Domain
                                                               )
        if intelligence_relationships:
            relationships.extend(intelligence_relationships)
        threat_context.update(outputs)
        human_readable += create_human_readable(outputs)

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


def files_reputation_command(client: Client, score_calc: DBotScoreCalculator, file, status, threshold=None,
                             threat_model_association=False):
    """
        Wrapper function for get_file_reputation.
    """
    results = []
    files = argToList(file, ',')
    for single_file in files:
        results.append(get_file_reputation(client, score_calc, single_file, status, threshold, threat_model_association))
    return results


def get_file_reputation(client: Client, score_calc: DBotScoreCalculator, file, status, threshold=None,
                        threat_model_association=False):
    """
        Checks the reputation of given hash of the file from ThreatStream and
        returns the indicator with highest severity score.
    """
    # get the indicator
    params = {'value': file, 'type': "md5", 'status': status, 'limit': 0}
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return create_indicator_result_with_dbotscore_unknown(indicator=file,
                                                              indicator_type=DBotScoreType.FILE,
                                                              reliability=client.reliability)

    # save the hash value under the hash type key
    threat_context = get_generic_threat_context(indicator, indicator_mapping=FILE_INDICATOR_MAPPING)
    file_type: str = indicator.get('subtype')  # The real type of the hash is in subtype field.
    if file_type:
        threat_context[file_type] = indicator.get('value')

    # Convert the tags objects into s string for the human readable.
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'File reputation for: {file}', threat_context | {'Tags': tags_csv})

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

    if threat_model_association:
        intelligence_relationships, outputs = get_intelligence(client,
                                                               indicator,
                                                               FeedIndicatorType.File
                                                               )
        if intelligence_relationships:
            relationships.extend(intelligence_relationships)
        threat_context.update(outputs)

        human_readable += create_human_readable(outputs)

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


def urls_reputation_command(client: Client, score_calc: DBotScoreCalculator, url, status, threshold=None,
                            threat_model_association=False):
    """
        Wrapper function for get_url_reputation.
    """
    results = []
    urls = argToList(url, ',')
    for single_url in urls:
        results.append(get_url_reputation(client, score_calc, single_url, status, threshold, threat_model_association))
    return results


def get_url_reputation(client: Client, score_calc: DBotScoreCalculator, url, status, threshold=None,
                       threat_model_association=False):
    """
        Checks the reputation of given url address from ThreatStream and
        returns the indicator with highest confidence score.
    """

    # get the indicator
    params = {'value': url, 'type': DBotScoreType.URL, 'status': status, 'limit': 0}
    indicator = search_worst_indicator_by_params(client, params)
    if not indicator:
        return create_indicator_result_with_dbotscore_unknown(indicator=url,
                                                              indicator_type=DBotScoreType.URL,
                                                              reliability=client.reliability)

    # Convert the tags objects into s string for the human readable.
    threat_context = get_generic_threat_context(indicator)
    tags_csv = ', '.join(threat_context.get('Tags', []))
    human_readable = tableToMarkdown(f'URL reputation for: {url}', threat_context | {'Tags': tags_csv})

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

    if threat_model_association:
        intelligence_relationships, outputs = get_intelligence(client,
                                                               indicator,
                                                               FeedIndicatorType.URL
                                                               )
        if intelligence_relationships:
            relationships.extend(intelligence_relationships)
        threat_context.update(outputs)
        human_readable += create_human_readable(outputs)

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
    params = {'value': email, 'type': DBotScoreType.EMAIL, 'status': status, 'limit': 0}
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
    human_readable = tableToMarkdown(f'Email reputation for: {email}', threat_context | {'Tags': tags_csv})

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


def get_passive_dns(client: Client, value, all_results=None, type=DBotScoreType.IP, limit=50):
    """
        Receives value and type of indicator and returns
        enrichment data for domain or ip.
    """
    dns_results = client.http_request("GET", F"v1/pdns/{type}/{value}/").get('results', None)
    demisto.debug(dns_results)
    if not dns_results:
        return f'No Passive DNS enrichment data found for {value}'
    if all_results == 'false':
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
                             threat_type="exploit", severity="low", default_state='inactive',
                             ip_mapping=None, domain_mapping=None,
                             url_mapping=None, email_mapping=None, md5_mapping=None, tags=None,
                             source_confidence_weight=None, tags_tlp: str = None, expiration_ts=None):
    """
        Imports indicators data to ThreatStream.
        The data can be imported using one of three import_types: data-text (plain-text),
        file-id of uploaded file to war room or URL.
    """
    data = assign_params(
        classification=classification,
        confidence=int(confidence),
        source_confidence_weight=arg_to_number(source_confidence_weight) if source_confidence_weight else None,
        ip_mapping=ip_mapping,
        default_state=default_state,
        expiration_ts=expiration_ts,
        domain_mapping=domain_mapping,
        url_mapping=url_mapping,
        email_mapping=email_mapping,
        md5_mapping=md5_mapping,
        threat_type=threat_type,
        severity=severity,
        tags=(json.dumps([({'name': tag, 'tlp': tags_tlp.lower()} if tags_tlp else {'name': tag}) for tag in argToList(tags)])
              if tags else None)
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
    res = client.http_request("POST", "v2/intelligence/import/", data=data, files=files)

    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()

    # checking that response contains success key
    if res.get('success', False):
        imported_id = res.get('import_session_id', '')
        job_id = res.get('job_id', '')
        readable_output = 'The data was imported successfully.\n' \
                          f'The ID of imported job is: {imported_id}.\n The identifier for the job on ThreatStream is: {job_id}.'
        return CommandResults(
            outputs_prefix=f'{THREAT_STREAM}.Import',
            outputs_key_field='ImportID',
            outputs={'ImportID': imported_id, 'JobID': job_id},
            readable_output=readable_output,
            raw_response=res,
        )
    else:
        raise DemistoException('The data was not imported. Check if valid arguments were passed')


def import_ioc_without_approval(client: Client, classification, file_id=None, confidence=None,
                                allow_unresolved='no',
                                source_confidence_weight=None, expiration_ts=None, severity=None,
                                tags=None, trustedcircles=None, indicators_json=None, tags_tlp: str = None):
    """
        Imports indicators data to ThreatStream.
        file_id of uploaded file to war room.
    """
    if not file_id and not indicators_json:
        raise DemistoException(f'{THREAT_STREAM} - Please specify file_id or indicators_json')
    if tags:
        tags = argToList(tags)
    if trustedcircles:
        trustedcircles = argToList(trustedcircles)
    if confidence:
        confidence = int(confidence)
    if source_confidence_weight:
        source_confidence_weight = int(source_confidence_weight)
    ioc_to_import = {}
    if file_id:
        try:
            # entry id of uploaded file to war room
            file_info = demisto.getFilePath(file_id)
            with open(file_info['path'], 'rb') as uploaded_file:
                ioc_to_import = json.load(uploaded_file)
        except json.JSONDecodeError:
            raise DemistoException(f'{THREAT_STREAM} - Entry {file_id} does not contain a valid json file.')
        except Exception:
            raise DemistoException(f'{THREAT_STREAM} - Entry {file_id} does not contain a file.')
    elif indicators_json:
        ioc_to_import = json.loads(indicators_json.replace("'", '"'))
    meta = ioc_to_import.get('meta', {})
    meta |= assign_params(
        classification=classification,
        confidence=confidence,
        allow_unresolved=argToBoolean(allow_unresolved),
        source_confidence_weight=source_confidence_weight,
        expiration_ts=expiration_ts,
        severity=severity,
        tags=([({'name': tag, 'tlp': tags_tlp.lower()} if tags_tlp else {'name': tag}) for tag in argToList(tags)]
              if tags else None),
        trustedcircles=trustedcircles
    )
    ioc_to_import.update({"meta": meta})
    client.http_request("PATCH", "v2/intelligence/", json=ioc_to_import, resp_type='text')
    return "The data was imported successfully."


def get_model_list(client: Client, model, limit="50", page=None, page_size=None):
    """
        Returns list of Threat Model that was specified. By default limit is set to 50 results.
        Possible values for model are : actor, campaign, incident, signature, ttp, vulnerability, tipreport
    """
    # if limit=0 don't put to context
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    params.update({'skip_intelligence': "true", 'skip_associations': "true", 'order_by': '-created_ts'})
    url = f"v1/{model}/"
    if model == 'attack pattern':
        url = 'v1/attackpattern/'
    model_list = client.http_request("GET", url, params=params).get('objects', None)

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
    hr_title = f"List of {model.title()}s"
    if model == 'vulnerability':
        hr_title = "List of Vulnerabilities"
    readable_output = tableToMarkdown(hr_title, models_context)
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
    params = {'skip_intelligence': "true", 'skip_associations': "true"}
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


def get_iocs_by_model(client: Client, model, id, limit="20", page=None, page_size=None):
    """
        Returns list of indicators associated with specific Threat Model by model id.
    """
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    model_type = model.title()
    url = f"v1/{model}/{id}/intelligence/"
    if model == 'attack pattern':
        url = f"v1/attackpattern/{id}/intelligence/"
    response = client.http_request("GET", url, params=params, resp_type='response')

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


def get_supported_platforms(client: Client, sandbox_type="default", limit=None, all_results=None):
    """
        Returns list of supported platforms for premium sandbox or default sandbox.
    """
    platform_data = client.http_request("GET", "v1/submit/parameters/")
    result_key = 'platform_choices' if sandbox_type == 'default' else 'premium_platform_choices'
    available_platforms = platform_data.get(result_key, [])
    if not available_platforms:
        return f'No supported platforms found for {sandbox_type} sandbox'
    if limit and isinstance(available_platforms, list) and all_results == 'false':
        output = camelize(available_platforms[:int(limit)])
    else:
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


def submit_report(client: Client, submission_type, submission_value, import_indicators=True,
                  submission_classification="private", report_platform="WINDOWS7",
                  premium_sandbox="false", detail=None):
    """
        Detonates URL or file that was uploaded to war room to ThreatStream sandbox.
    """
    import_indicators = argToBoolean(import_indicators)
    data = {
        'report_radio-classification': submission_classification,
        'report_radio-platform': report_platform,
        'use_premium_sandbox': premium_sandbox,
        'import_indicators': import_indicators
    }
    if detail:
        data['report_radio-notes'] = detail

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
    return None


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
    page = kwargs.get('page')
    page_size = kwargs.get('page_size')
    limit = kwargs['limit'] = int(kwargs.get('limit', 20))
    params = return_params_of_pagination_or_limit(arg_to_number(page), arg_to_number(page_size), arg_to_number(limit))
    kwargs.update(params)
    if 'page' in kwargs:
        kwargs.pop('page')
    if 'page_size' in kwargs:
        kwargs.pop('page_size')
    url = "v2/intelligence/"
    if 'query' in kwargs:
        url += f"?q={kwargs.pop('query')}"
    res = client.http_request("GET", url, params=kwargs)
    iocs_list = res.get('objects', None)
    if not iocs_list:
        return 'No indicators found from ThreatStream'

    iocs_context = parse_indicators_list(iocs_list)
    # handle the issue that the API does not return more than 1000 indicators.
    if limit > 1000:
        next_page = res.get('meta', {}).get('next', None)
        while len(iocs_context) < limit and next_page:
            next_page = next_page.replace('api/', '')
            res = client.http_request("GET", next_page, without_credentials="api_key" in next_page)
            iocs_list = res.get('objects', None)
            next_page = res.get('meta', {}).get('next', None)
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


def search_intelligence(client: Client, **kwargs):
    """
        Returns filtered indicators by parameters from ThreatStream.
        By default the limit of indicators result is set to 50.
    """
    page = int(kwargs.pop('page', 0))
    page_size = int(kwargs.pop('page_size', 0))
    if page_size > 0:
        kwargs['limit'] = page_size
    else:
        kwargs['limit'] = int(kwargs.get('limit', 50))
    kwargs['offset'] = page * page_size
    url = 'v2/intelligence/'
    if 'query' in kwargs:
        url += f"?q={kwargs.pop('query')}"
    if 'confidence' in kwargs:
        conf = kwargs.get('confidence', '').split(' ')
        if len(conf) > 1:
            if conf[0] not in {'gt', 'lt'}:
                raise DemistoException(f'Confidence operator must be on of gt or lt, if used.{conf[0]} is not a legal value.')
            kwargs[f'confidence__{conf[0]}'] = conf[1]
            del kwargs['confidence']
    intelligence_list = client.http_request('GET', url, params=kwargs).get('objects', None)
    if not intelligence_list:
        return 'No intelligence found from ThreatStream'

    intelligence_table = tableToMarkdown('The intelligence results', intelligence_list, removeNull=True,
                                         headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Intelligence',
        outputs=intelligence_list,
        readable_output=intelligence_table,
        raw_response=intelligence_list
    )


def add_indicator_tag_command(client: Client, **kwargs) -> CommandResults:
    indicator_ids: list[str] = argToList(kwargs["indicator_ids"])
    tags: list[str] = argToList(kwargs["tags"])

    client.add_indicator_tag(indicator_ids, tags)

    return CommandResults(
        readable_output=f"The tags have been successfully added"
                        f" for the following ids:\n `{', '.join(indicator_ids)}`"
    )


def remove_indicator_tag_command(client: Client, **kwargs) -> CommandResults:
    indicator_ids: list[str] = argToList(kwargs["indicator_ids"])
    tags: list[str] = argToList(kwargs["tags"])

    client.remove_indicator_tag(indicator_ids, tags)

    return CommandResults(
        readable_output=f"The tags were successfully deleted"
                        f" for the following ids:\n `{', '.join(indicator_ids)}`"
    )


def clone_ioc_command(client: Client, indicator_id: str = None) -> CommandResults:
    """
    Clone already imported indicator to be used with adding to a Trusted Circle
    - Clone will fail with 403 if indicator value is not cloneable (403 not in ok_codes)
    - ThreatStream - Error in API call 403 - {"message": "The entity <ip> is not cloneable"}
    - You cannot clone
        - type=string
        - status=pending
        - owner_organization_id=<your own org id>
    Args:
        indicator_id: Client to perform calls to Anomali ThreatStream service.
    Returns:
        (CommandResults).
    """

    res_json = client.http_request("POST", F"v2/intelligence/{indicator_id}/clone/")

    # append the indocator ID being used in the clone
    res_json["ID"] = indicator_id

    clone_table = tableToMarkdown(f'Clone operation results for indicator {indicator_id}', res_json, removeNull=True,
                                  headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix=f'{THREAT_STREAM}.Clone',
        outputs=res_json,
        readable_output=clone_table,
        raw_response=res_json
    )


def edit_classification_job_command(client: Client, import_id: str = None, data: str = None) -> CommandResults:
    """
    Edit cloned observables in an import job
    Args:
        client: Client to perform calls to Anomali ThreatStream service.
        import_id:  The id of a specific import entry.
        data: The json data for fields to be edited for a cloned observable
    Returns:
        (CommandResults).
    """
    res = client.edit_classification_job_request(import_id, data)

    if res.get("status") != 'errors':

        readable_output = 'The import session was successfully approved.'
    else:
        raise DemistoException('Import Session Approval Failed.')

    return CommandResults(
        readable_output=readable_output,
        raw_response=res,
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
        'threatstream-clone-imported-indicator': clone_ioc_command,
        'threatstream-edit-classification': edit_classification_job_command,

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

        'threatstream-search-intelligence': search_intelligence,

        'threatstream-list-rule': list_rule_command,
        'threatstream-create-rule': create_rule_command,
        'threatstream-update-rule': update_rule_command,
        'threatstream-delete-rule': delete_rule_command,

        'threatstream-list-user': list_user_command,
        'threatstream-list-investigation': list_investigation_command,

        'threatstream-create-investigation': create_investigation_command,
        'threatstream-update-investigation': update_investigation_command,
        'threatstream-delete-investigation': delete_investigation_command,
        'threatstream-add-investigation-element': add_investigation_element_command,

        'threatstream-list-whitelist-entry': list_whitelist_entry_command,
        'threatstream-create-whitelist-entry': create_whitelist_entry_command,
        'threatstream-update-whitelist-entry-note': update_whitelist_entry_note_command,
        'threatstream-delete-whitelist-entry': delete_whitelist_entry_command,

        'threatstream-list-import-job': list_import_job_command,
        'threatstream-approve-import-job': approve_import_job_command,
        'threatstream-search-threat-model': search_threat_model_command,
        'threatstream-add-threat-model-association': add_threat_model_association_command,
        'threatstream-add-indicator-tag': add_indicator_tag_command,
        'threatstream-remove-indicator-tag': remove_indicator_tag_command,
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
            remote_api=argToBoolean(params.get('remote_api', 'false'))
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
