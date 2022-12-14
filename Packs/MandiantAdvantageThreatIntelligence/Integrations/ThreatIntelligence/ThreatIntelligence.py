import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MAP_TYPE_TO_URL = {
    'Malware': 'malware',
    'Actors': 'actor',
    'Indicators': 'indicator',
    'Vulnerability': 'vulnerability'
}
MAP_TYPE_TO_RESPONSE = {
    'Malware': 'malware',
    'Actors': 'threat-actors',
    'Indicators': 'indicators'
}
MAP_NAME_TO_TYPE = {
    'Malware': ThreatIntel.ObjectsNames.MALWARE,
    'Actors': ThreatIntel.ObjectsNames.THREAT_ACTOR
}
MAP_INDICATORS_TYPE = {'fqdn': FeedIndicatorType.Domain,
                       'ipv4': FeedIndicatorType.IP,
                       'md5': FeedIndicatorType.File,
                       'sha1': FeedIndicatorType.File,
                       'sha256': FeedIndicatorType.File,
                       'url': FeedIndicatorType.URL,
                       'vulnerability': FeedIndicatorType.CVE}

MAP_TYPE_TO_ATTACKPATTERN_KEY = {
    'Actors': 'threat-actors',
    'Malware': 'malware'
}
MAP_TYPE_TO_DBOTSCORE_TYPE = {
    'Malware': DBotScoreType.CUSTOM,
    'Actors': DBotScoreType.CUSTOM
}

''' CLIENT CLASS '''


class MandiantClient(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, api_key: str, secret_key: str, verify: bool, proxy: bool, timeout: int,
                 first_fetch: str, limit: int, types: List,
                 metadata: bool = False, enrichment: bool = False, tags: List = None, tlp_color: Optional[str] = None):
        if not tags:
            tags = []

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200,))
        self._api_credentials = (api_key, secret_key)

        self._headers = {
            'X-App-Name': "content.xsoar.cortex.mandiantadvantage.v1.0",
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._get_token()}'
        }
        self.timeout = timeout
        self.first_fetch = first_fetch
        self.limit = limit
        self.types = types
        self.metadata = metadata
        self.tlp_color = tlp_color
        self.tags = tags
        self.enrichment = enrichment

        add_sensitive_log_strs(self._get_token())

    def _get_token(self) -> str:
        """
        Returns the token from the integration context if available and has not expired
        Otherwise, a new token is retrieved from the Mandiant API and stored in the integration context
        Returns:
            str: the bearer token that is currently in the integration context
        """
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        valid_until = integration_context.get('valid_until')

        now_timestamp = arg_to_datetime('now').timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until:
            if now_timestamp < valid_until:
                return token

        # else generate a token and update the integration context accordingly
        token = self._retrieve_token()

        return token

    def _retrieve_token(self) -> str:
        """
        Retrieve a new token from the Mandiant API
        """
        headers = {
            "accept": "application/json"
        }
        data = {
            'grant_type': 'client_credentials'
        }

        resp = self._http_request(method='POST', auth=self._api_credentials, headers=headers, url_suffix='token',
                                  resp_type='json', data=data)
        self._token = resp.get('access_token')

        integration_context = get_integration_context()
        integration_context.update({'token': self._token})

        token_expiration = resp.get("expires_in", datetime.timestamp(datetime.now(timezone.utc)))

        # Subtract 10 minutes from the expiration time as a buffer
        integration_context.update({'valid_until': token_expiration - 600})
        set_integration_context(integration_context)

        return self._token

    def get_indicator_info(self, identifier: str, indicator_type: str, info_type: str = "") \
            -> Union[Dict, List]:
        """
        Retrieve detailed information for a given indicator.
        Args:
            identifier (Dict): Indicator's identifier.
            indicator_type (str): The indicator type.
            info_type (str): Type of additional info
        Returns:
            Dict: Additional data of the indicator.
        """
        url = f"v4/{MAP_TYPE_TO_URL[indicator_type]}"
        url = urljoin(url, identifier)
        url = urljoin(url, info_type)
        if url[-1] == '/':
            url = url[:-1]

        call_result = {}
        try:
            call_result = self._http_request(method="GET", url_suffix=url, timeout=self.timeout)
        except DemistoException as e:
            # If there is an internal issue inside the server, don't fail the entire fetch session
            if e.res.status_code != 500:
                raise e

        if not info_type:
            return call_result

        if info_type == 'attack-pattern':
            res = call_result.get(MAP_TYPE_TO_ATTACKPATTERN_KEY[indicator_type], [])
            if len(res) >= 1:
                res = res[0].get('attack-patterns', [])
            else:
                return []
            if isinstance(res, str) and res == 'redacted':
                return []
            elif res and isinstance(res, dict):
                return list(res.keys())
            else:
                return []
        else:
            return call_result.get(info_type, [])

    def get_indicators(self, indicator_type: str = "Indicators", params: Dict = None) -> List:
        """
        Retrieve a list of indicators from Mandiant Threat Intelligence
        Args:
            indicator_type (str): The indicator type.  Defaults to `indicators` (all indicators).
            params (Dict): HTTP call params
        Returns:
            List: A list of indicators
        """
        params = params or {}
        try:
            url = f'/v4/{MAP_TYPE_TO_URL[indicator_type]}'
            response = self._http_request(method="GET", url_suffix=url, timeout=self.timeout, params=params)
            response = response.get(MAP_TYPE_TO_RESPONSE[indicator_type], [])

        except DemistoException as e:
            demisto.log(f"Error retrieving objects from Mandiant Threat Intel: {e}")
            response = []

        return response

    def get_indicators_by_value(self, indicator_value: str, params: Dict = None):
        params = params or {}
        request_body = {
            "requests": [
                {
                    "values": [
                        indicator_value
                    ]
                }
            ]
        }
        try:
            url = f'/v4/indicator'
            response = self._http_request(method="POST", url_suffix=url, timeout=self.timeout, params=params,
                                          json_data=request_body)
            response = response.get("indicators", [])

        except DemistoException as e:
            demisto.log(f"Error retrieving objects from Mandiant Threat Intel: {e}")
            response = []

        return response


''' HELPER FUNCTIONS '''


def get_verdict(mscore: Optional[str]) -> int:
    """
    Convert mscore to dbot score
    Args:
        mscore (str): mscore, value from 0 to 100
    Returns:
        int: DBotScore
    """
    if not mscore:
        return Common.DBotScore.NONE
    mscore = int(mscore)
    if 0 <= mscore <= 20:
        return Common.DBotScore.GOOD
    elif 21 <= mscore <= 50:
        return Common.DBotScore.NONE
    elif 51 <= mscore <= 80:
        return Common.DBotScore.SUSPICIOUS
    elif 81 <= mscore <= 100:
        return Common.DBotScore.BAD
    else:
        return Common.DBotScore.NONE


def get_dbot_score(indicator: str,
                   mscore: str,
                   type: DBotScoreType,
                   reliability: DBotScoreReliability = DBotScoreReliability.A_PLUS) -> Dict:
    verdict = get_verdict(mscore)
    return {
        'Indicator': indicator,
        'Type': type,
        'Vendor': "Mandiant",
        'Score': verdict,
        'Reliability': reliability
    }


def get_indicator_relationships(raw_indicator: Dict, indicator_field: str, entity_a_field: str, entity_a_type: str,
                                entity_b_field: str, entity_b_type: str, name: str, reverse_name: str):
    """
    Creates relationships for the given indicator
    Args:
        raw_indicator (Dict): indicator
        indicator_field (str): indicator field that contains the entities list
        entity_a_field (str): indicator field that contains the entity name
        entity_a_type (str): indicator field that contains the entity type
        entity_b_field (str): entity field that contains the entity name
        entity_b_type (str): entity field that contains the entity type
        name (str): the relationship name
        reverse_name (str): the relationship reverse name
    Returns:
    """
    entities_list = raw_indicator.get(indicator_field, [])
    relationships = []

    if entities_list != 'redacted':
        relationships = [EntityRelationship(entity_a=raw_indicator.get(entity_a_field, ''),
                                            entity_a_type=entity_a_type,
                                            name=name,
                                            entity_b=entity.get(entity_b_field, ''),
                                            entity_b_type=entity_b_type,
                                            reverse_name=reverse_name,
                                            brand="Mandiant Advantage Threat Intelligence",
                                            source_reliability="A - Completely reliable"
                                            ).to_indicator()
                         for entity in entities_list]
    return relationships


def create_malware_indicator(client: MandiantClient, raw_indicator: Dict) -> Dict:
    """
      Creates a malware indicator
      Args:
          client (MandiantClient): client
          raw_indicator (Dict): indicator
      Returns:
          Common.CustomIndicator: malware indicator
    """
    raw_indicator = {k: v for k, v in raw_indicator.items() if v and v != 'redacted'}  # filter none and redacted values

    fields = {'operatingsystemrefs': raw_indicator.get('operating_systems'),
              'aliases': [i["name"] for i in raw_indicator.get('aliases', [])],
              'capabilities': raw_indicator.get('capabilities'),
              'tags': [i.get('name', '') for i in  # type:ignore
                       argToList(raw_indicator.get('industries'))] + client.tags,  # type:ignore
              'mandiantdetections': raw_indicator.get('detections'),
              'yara': [(yara.get('name'), yara.get('id')) for yara in  # type: ignore
                       raw_indicator.get('yara', [])] if raw_indicator.get('yara', []) != 'redacted' else [],
              'roles': raw_indicator.get('roles'),
              'stixid': raw_indicator.get('id'),
              'name': raw_indicator.get('name'),
              'description': raw_indicator.get('description'),
              'updateddate': raw_indicator.get('last_updated'),
              'lastseenbysource': raw_indicator.get('last_activity_time'),
              'trafficlightprotocol': client.tlp_color,
              'Is Malware Family': raw_indicator.get('inherently_malicious', 0) == 1,
              'DBot Score': get_dbot_score(raw_indicator.get('name'), raw_indicator.get('mscore'), DBotScoreType.CUSTOM)
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values

    relationships = get_indicator_relationships(raw_indicator, 'actors', 'name', ThreatIntel.ObjectsNames.MALWARE,
                                                'name',
                                                ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                EntityRelationship.Relationships.RELATED_TO,
                                                EntityRelationship.Relationships.RELATED_TO)

    relationships += get_indicator_relationships(raw_indicator, 'cve', 'name', ThreatIntel.ObjectsNames.MALWARE,
                                                 'name',
                                                 FeedIndicatorType.CVE,
                                                 EntityRelationship.Relationships.RELATED_TO,
                                                 EntityRelationship.Relationships.RELATED_TO)

    relationships += get_indicator_relationships(raw_indicator, 'malware', 'name', ThreatIntel.ObjectsNames.MALWARE,
                                                 'name',
                                                 ThreatIntel.ObjectsNames.MALWARE,
                                                 EntityRelationship.Relationships.RELATED_TO,
                                                 EntityRelationship.Relationships.RELATED_TO)

    indicator_obj = {
        'value': raw_indicator.get('name'),
        'type': ThreatIntel.ObjectsNames.MALWARE,
        'rawJSON': raw_indicator,
        'fields': fields,
        'relationships': relationships,
        'score': get_verdict(raw_indicator.get('mscore'))
    }

    return indicator_obj


def create_actor_indicator(client: MandiantClient, raw_indicator: Dict) -> Dict:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    raw_indicator = {k: v for k, v in raw_indicator.items() if v and v != 'redacted'}  # filter none and redacted values

    primary_motivation = None
    if len(raw_indicator.get('motivations', [])) >= 1:
        primary_motivation = raw_indicator.get('motivations')[0].get("name")

    fields = {'primarymotivation': primary_motivation,
              'tags': [industry.get('name') for industry in  # type: ignore
                       raw_indicator.get('industries', [])] + client.tags,
              'aliases': [alias.get('name') for alias in raw_indicator.get('aliases', [])],  # type:ignore
              'firstseenbysource': [item.get('earliest') for item in raw_indicator.get('observed', [])],  # type:ignore
              'lastseenbysource': [item.get('recent') for item in raw_indicator.get('observed', [])],  # type:ignore
              'targets': [target.get('name') for target in  # type:ignore
                          raw_indicator.get('locations', {}).get('target', [])],  # type:ignore
              'stixid': raw_indicator.get('id'),
              'name': raw_indicator.get('name'),
              'description': raw_indicator.get('description'),
              'updateddate': raw_indicator.get('last_updated'),
              'trafficlightprotocol': client.tlp_color
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values

    relationships = get_indicator_relationships(raw_indicator, 'malware', 'name', ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                'name',
                                                ThreatIntel.ObjectsNames.MALWARE,
                                                EntityRelationship.Relationships.RELATED_TO,
                                                EntityRelationship.Relationships.RELATED_TO)

    relationships += get_indicator_relationships(raw_indicator, 'cve', 'name', ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                 'cve_id',
                                                 FeedIndicatorType.CVE,
                                                 EntityRelationship.Relationships.TARGETS,
                                                 EntityRelationship.Relationships.TARGETED_BY)

    relationships += get_indicator_relationships(raw_indicator, 'tools', 'name', ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                 'name',
                                                 ThreatIntel.ObjectsNames.TOOL,
                                                 EntityRelationship.Relationships.USES,
                                                 EntityRelationship.Relationships.USED_BY)

    relationships += get_indicator_relationships(raw_indicator, 'associated_uncs', 'name',
                                                 ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                 'name',
                                                 ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                 EntityRelationship.Relationships.RELATED_TO,
                                                 EntityRelationship.Relationships.RELATED_TO)

    indicator_obj = {
        'value': raw_indicator.get('name'),
        'type': ThreatIntel.ObjectsNames.THREAT_ACTOR,
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields,
        'relationships': relationships
    }
    return indicator_obj


def get_cvss_score(cve: dict) -> str:
    if "v3.1" in cve.get("common_vulnerability_scores", {}):
        return cve["common_vulnerability_scores"]["v3.1"]["base_score"]
    elif "v2.0" in cve.get("common_vulnerability_scores", {}):
        return cve["common_vulnerability_scores"]["v2.0"]["base_score"]


def create_cve_indicator(raw_indicator: Dict) -> Common.CVE:
    """
    Create CVE indicator
    Args:
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = {
        "id": raw_indicator.get("cve_id"),
        "cvss": get_cvss_score(raw_indicator),
        "published": raw_indicator.get("publish_date").rstrip("Z"),
        "modified": raw_indicator.get("last_modified_date").rstrip("Z"),
        "description": raw_indicator.get("description")
    }
    return Common.CVE(**indicator_obj)


def create_file_indicator(raw_indicator: Dict) -> Common.File:
    """
    Args:
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = {
        "md5": raw_indicator.get("value"),
        "dbot_score": Common.DBotScore(indicator=raw_indicator["value"], indicator_type=DBotScoreType.FILE,
                                       score=get_verdict(raw_indicator["mscore"]))
    }
    sha1_hashes = [hash["value"] for hash in raw_indicator["associated_hashes"] if hash["type"] == "sha1"]
    sha256_hashes = [hash["value"] for hash in raw_indicator["associated_hashes"] if hash["type"] == "sha256"]
    if len(sha1_hashes) >= 1:
        indicator_obj["sha1"] = sha1_hashes[0]
    if len(sha256_hashes) >= 1:
        indicator_obj["sha256"] = sha256_hashes[0]
    return Common.File(**indicator_obj)


def create_ip_indicator(raw_indicator: Dict) -> Common.IP:
    """
    Args:
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = {
        "ip": raw_indicator.get("value"),
        "dbot_score": Common.DBotScore(indicator=raw_indicator["value"], indicator_type=DBotScoreType.IP,
                                       score=get_verdict(raw_indicator["mscore"]))
    }
    return Common.IP(**indicator_obj)


def create_fqdn_indicator(raw_indicator: Dict) -> Common.Domain:
    """
    Args:
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = {
        "domain": raw_indicator.get("value"),
        "dns": raw_indicator.get("value"),
        "dbot_score": Common.DBotScore(indicator=raw_indicator["value"], indicator_type=DBotScoreType.DOMAIN,
                                       score=get_verdict(raw_indicator["mscore"]))
    }
    return Common.Domain(**indicator_obj)


def create_url_indicator(raw_indicator: Dict) -> Common.URL:
    """
    Args:
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    indicator_obj = {
        "url": raw_indicator.get("value"),
        "dbot_score": Common.DBotScore(indicator=raw_indicator["value"], indicator_type=DBotScoreType.URL,
                                       score=get_verdict(raw_indicator["mscore"]))
    }
    return Common.URL(**indicator_obj)


def create_indicator(client: MandiantClient, raw_indicator: Dict) -> Dict:
    """
    Create indicator
    Args:
        client (MandiantClient): client
        raw_indicator (Dict): raw indicator
    Returns: Parsed indicator
    """
    # If the indicator is only Open-Source intelligence, mark the TLP Color as
    # GREEN.  Otherwise, use the configured value

    information_is_osint = True
    for source in raw_indicator.get('sources', []):
      if source.get('osint', False) == False:
        information_is_osint = False

    if information_is_osint:
      tlp_color = 'GREEN'
    else:
      tlp_color = client.tlp_color

    fields = {'primarymotivation': raw_indicator.get('motivations'),
              'firstseenbysource': raw_indicator.get('first_seen'),
              'lastseenbysource': raw_indicator.get('last_seen'),
              'stixid': raw_indicator.get('id'),
              'trafficlightprotocol': tlp_color
              }

    fields = {k: v for k, v in fields.items() if v and v != 'redacted'}  # filter none and redacted values
    indicator_obj = {
        'value': raw_indicator.get('value'),
        'type': MAP_INDICATORS_TYPE[raw_indicator.get('type', '')],
        'rawJSON': raw_indicator,
        'score': get_verdict(raw_indicator.get('mscore')),
        'fields': fields
    }
    return indicator_obj


MAP_INDICATORS_FUNCTIONS = {
    'Malware': create_malware_indicator,
    'Actors': create_actor_indicator,
    'Indicators': create_indicator
}


def enrich_indicators(client: MandiantClient, indicators_list: List, indicator_type: str) -> None:
    """
    For each indicator in indicators_list create relationships and adding the relevant indicators
    Args:
        client (MandiantClient): client
        indicators_list (List): list of raw indicators
        indicator_type (str): the current indicator type
    Returns:
        List of relevant indicators
    """
    for indicator in indicators_list:
        indicator_id = indicator.get('fields', {}).get('stixid', '')
        indicator_name = indicator.get('fields', {}).get('name', '')

        reports_list = client.get_indicator_info(indicator_type=indicator_type,
                                                 identifier=indicator_id,
                                                 info_type='reports')

        reports_relationships = [EntityRelationship(entity_a=indicator_name,
                                                    entity_a_type=MAP_NAME_TO_TYPE[indicator_type],
                                                    name=EntityRelationship.Relationships.RELATED_TO,
                                                    entity_b=report.get('title'),
                                                    entity_b_type=ThreatIntel.ObjectsNames.REPORT,
                                                    reverse_name=EntityRelationship.Relationships.RELATED_TO
                                                    ).to_indicator()
                                 for report in reports_list if report]

        general_list = client.get_indicator_info(indicator_type=indicator_type,
                                                 identifier=indicator_id,
                                                 info_type='indicators')

        general_relationships = [EntityRelationship(entity_a=indicator_name,
                                                    entity_a_type=MAP_NAME_TO_TYPE[indicator_type],
                                                    name=EntityRelationship.Relationships.INDICATED_BY,
                                                    entity_b=general_indicator.get('value'),
                                                    entity_b_type=MAP_INDICATORS_TYPE[
                                                        general_indicator.get('type', '')],
                                                    reverse_name=EntityRelationship.Relationships.INDICATOR_OF).to_indicator()
                                 for general_indicator in general_list if general_indicator]

        attack_pattern_list = client.get_indicator_info(indicator_type=indicator_type,
                                                        identifier=indicator_id,
                                                        info_type='attack-pattern')

        attack_pattern_relationships = [EntityRelationship(entity_a=indicator_name,
                                                           entity_a_type=MAP_NAME_TO_TYPE[indicator_type],
                                                           name=EntityRelationship.Relationships.USES,
                                                           entity_b=attack_pattern,
                                                           entity_b_type=ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                                                           reverse_name=EntityRelationship.Relationships.USED_BY
                                                           ).to_indicator()
                                        for attack_pattern in attack_pattern_list if attack_pattern]
        relationships = reports_relationships + general_relationships + attack_pattern_relationships

        indicator['relationships'] = relationships
        indicator['fields']['publications'] = [{'source': "Mandiant", 'title': report.get("title"),
                                                'link': f"https://advantage.mandiant.com/reports/{report.get('report_id')}"}
                                               for report in reports_list]


def get_new_indicators(client: MandiantClient, last_run: str, indicator_type: str, limit: int) -> List:
    """
    Get a list of new indicators
    Args:
        client (MandiantClient): client
        last_run (str): last run as free text or date format
        indicator_type (str): the desired type to fetch
        limit (int): number of indicator to fetch
    Returns:
        List: A list of new indicators
    """
    start_date = arg_to_datetime(last_run)
    minimum_mscore = int(demisto.params().get('feedMinimumConfidence', 80))
    exclude_osint = demisto.params().get('feedExcludeOSIntel', True)

    params = {}
    if indicator_type == 'Indicators':
        # for indicator type the earliest time to fetch is 90 days ago
        earliest_fetch = arg_to_datetime('90 days ago')
        start_date = max(earliest_fetch, start_date)  # type:ignore
        params = {'start_epoch': int(start_date.timestamp()),
                  'limit': limit,
                  'gte_mscore': minimum_mscore,
                  'exclude_osint': exclude_osint}  # type:ignore

    new_indicators_list = client.get_indicators(indicator_type, params=params)

    if indicator_type != 'Indicators': \
            # new to old
        new_indicators_list.sort(key=lambda x: arg_to_datetime(x.get('last_updated')), reverse=True)  # type:ignore
        new_indicators_list = list(
            filter(lambda x: arg_to_datetime(x['last_updated']).timestamp() > start_date.timestamp(),  # type: ignore
                   new_indicators_list))

    return new_indicators_list


def get_indicator_list(client: MandiantClient, limit: int, first_fetch: str, indicator_type: str,
                       update_context: bool = True) -> List[Dict]:
    """
    Get a list of indicators of the given type
    Args:
        client (MandiantClient): client
        limit (int): number of indicators to return.
        first_fetch (str): Get indicators newer than first_fetch.
        indicator_type (str): indicator type
        update_context (bool): Whether to save the LastFetch data to the context
    Returns:
        List[Dict]: list of indicators
    """
    last_run_dict = demisto.getLastRun()
    indicators_list = last_run_dict.get(f'{indicator_type}List', [])

    if len(indicators_list) < limit:
        last_run = last_run_dict.get(indicator_type + 'Last', first_fetch)
        new_indicators_list = get_new_indicators(client, last_run, indicator_type, limit)
        indicators_list += new_indicators_list

    if indicators_list:
        new_indicators_list = indicators_list[:limit]
        last_run_dict[indicator_type + 'List'] = indicators_list[limit:]
        date_key = 'last_seen' if indicator_type == 'Indicators' else 'last_updated'
        last_run_dict[indicator_type + 'LastFetch'] = new_indicators_list[-1][date_key]

        if update_context:
            demisto.setLastRun(last_run_dict)

        indicators_list = new_indicators_list

    return indicators_list


def fetch_indicators(client: MandiantClient, args: Dict = None, update_context: bool = True) -> List:
    """
    For each type the fetch indicator command will:
        1. Fetch a list of indicators from the Mandiant Threat Intelligence API
        2. Fetch additional information about each indicator from the Mandiant Threat Intelligence API and add it to the
           original indicator
        3. Enrich indicators by retrieving relationship information from the Mandiant Threat Intelligence API and adding
           it to the original indicator
        NOTE: This requires an additional 3 API calls per indicator
    Args:
        client (MandiantClient): client
        args (Dict): If provided, these arguments override those in the `client`
        update_context (bool): Whether to update the context.
    Returns:
        List of all indicators
    """
    args = args if args else {}
    limit = int(args.get('limit', client.limit))
    metadata = argToBoolean(args.get('indicatorMetadata', client.metadata))
    enrichment = argToBoolean(args.get('indicatorRelationships', client.enrichment))
    types = argToList(args.get('type', client.types))

    first_fetch = client.first_fetch

    result = []
    for indicator_type in types:
        indicators_list = get_indicator_list(client, limit, first_fetch, indicator_type, update_context)

        if metadata and indicator_type != 'Indicators':
            indicators_list = [client.get_indicator_info(identifier=indicator.get('id'),  # type:ignore
                                                         indicator_type=indicator_type)
                               for indicator in indicators_list]

        indicators = [MAP_INDICATORS_FUNCTIONS[indicator_type](client, indicator) for indicator in indicators_list]
        if enrichment and indicator_type != 'Indicators':
            enrich_indicators(client, indicators, indicator_type)

        result += indicators
    return result

def batch_fetch_indicators(client: MandiantClient, args: Dict = None, update_context: bool = True):
    """
    For each type the fetch indicator command will:
        1. Fetch a list of indicators from the Mandiant Threat Intelligence API
        2. Fetch additional information about each indicator from the Mandiant Threat Intelligence API and add it to the
           original indicator
        3. Enrich indicators by retrieving relationship information from the Mandiant Threat Intelligence API and adding
           it to the original indicator
        NOTE: This requires an additional 3 API calls per indicator
    Args:
        client (MandiantClient): client
        args (Dict): If provided, these arguments override those in the `client`
        update_context (bool): Whether to update the context.
    Returns:
        List of all indicators
    """
    args = args if args else {}

    result = fetch_indicators(client=client, args=args, update_context=update_context)

    for b in batch(result, batch_size=2000):
        demisto.createIndicators(b)

def fetch_indicator_by_value(client: MandiantClient, args: Dict = None):
    args = args if args else {}
    indicator_value = args.get("indicator_value")

    INDICATOR_FUNC_MAP = {
        "ipv4": create_ip_indicator,
        "fqdn": create_fqdn_indicator,
        "url": create_url_indicator,
        "md5": create_file_indicator
    }
    INDICATOR_TYPE_MAP = {
        "ipv4": "ip",
        "fqdn": "domain",
        "url": "url",
        "md5": "file"
    }

    indicators_list = client.get_indicators_by_value(indicator_value=indicator_value)
    indicators = [INDICATOR_FUNC_MAP[indicator["type"]](indicator) for indicator in indicators_list]

    for indicator in indicators_list:
        indicator['value'] = indicators_value_to_clickable([indicator['value']])

    return CommandResults(
        outputs_prefix=INDICATOR_TYPE_MAP[indicators_list[0]["type"]],
        outputs=indicators_list,
        indicators=indicators
    )


def fetch_threat_actor(client: MandiantClient, args: Dict = None):
    args = args if args else {}
    actor_name = args.get("actor_name")

    indicator_obj = client.get_indicator_info(identifier=actor_name, indicator_type="Actors")
    indicator = [create_actor_indicator(client, indicator_obj)]

    if client.enrichment:
        enrich_indicators(client, indicator, "Actors")

        dummy_indicator = [{
            "value": "$$DummyIndicator$$",
            "relationships": indicator[0]["relationships"]
        }]
        demisto.createIndicators(dummy_indicator)

    demisto.createIndicators(indicator)

    indicator[0]['fields']['name'] = indicators_value_to_clickable([indicator[0]['fields']['name']])

    return CommandResults(
        content_format=formats['json'],
        outputs=indicator[0]['fields'],
        outputs_prefix="MANDIANTTI.ThreatActor",
        outputs_key_field="name",
        ignore_auto_extract=True)


def fetch_malware_family(client: MandiantClient, args: Dict = None):
    args = args if args else {}
    malware_name = args.get("malware_name")

    indicator = client.get_indicator_info(identifier=malware_name, indicator_type="Malware")
    indicator = [create_malware_indicator(client, indicator)]
    if client.enrichment:
        enrich_indicators(client, indicator, "Malware")

        dummy_indicator = [{
            "value": "$$DummyIndicator$$",
            "relationships": indicator[0]["relationships"]
        }]
        demisto.createIndicators(dummy_indicator)

    demisto.createIndicators(indicator)

    indicator[0]['fields']['name'] = indicators_value_to_clickable([indicator[0]['fields']['name']])

    return CommandResults(
        content_format=formats['json'],
        outputs=indicator[0]['fields'],
        outputs_prefix="MANDIANTTI.Malware",
        outputs_key_field="name",
        ignore_auto_extract=True)


def fetch_reputation(client: MandiantClient, args: Dict = None):
    args = args if args else {}
    input_type = demisto.command()
    indicator_value = args.get(input_type)

    INDICATOR_TYPE_MAP = {
        "file": create_file_indicator,
        "ip": create_ip_indicator,
        "domain": create_fqdn_indicator,
        "url": create_url_indicator
    }

    if input_type in INDICATOR_TYPE_MAP.keys():
        indicators_list = client.get_indicators_by_value(indicator_value=indicator_value)
        indicators = [INDICATOR_TYPE_MAP[input_type](indicator) for indicator in indicators_list]
        indicators_list[0]['value'] = indicators_value_to_clickable([indicators_list[0]['value']])
    elif input_type == "cve":
        indicators_list = [client.get_indicator_info(indicator_value, "Vulnerability")]
        indicators = [create_cve_indicator(indicator) for indicator in indicators_list]
        indicators_list[0]['cve_id'] = indicators_value_to_clickable([indicators_list[0]['cve_id']])

    return CommandResults(
        content_format=formats['json'],
        outputs=indicators_list[0],
        outputs_prefix=input_type,
        indicators=indicators
    )


''' COMMAND FUNCTIONS '''


def test_module(client: MandiantClient, args: Dict) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``MandiantClient``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # Note: As part of client initialization, a token is retrieved, which requires successful authentication
    # Therefor, if a user has reached this point with a valid MandiantClient, everything is working
    return 'ok'

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)
    api_key = params.get('api_key', '')
    secret_key = params.get('secret_key', '')
    base_url = params.get('api_base_url', '')
    timeout = int(params.get('timeout', 60))
    tlp_color = demisto.params().get('tlp_color')
    feedTags = argToList(demisto.params().get('feedTags'))
    first_fetch = params.get('first_fetch', '3 days ago')
    limit = int(params.get('max_fetch', 50))
    metadata = argToBoolean(params.get('indicatorMetadata', False))
    enrichment = argToBoolean(params.get('indicatorRelationships', False))
    types = argToList(params.get('type'))

    demisto.debug(f'Command being called is {command}')
    try:
        client = MandiantClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            secret_key=secret_key,
            timeout=timeout,
            tags=feedTags,
            tlp_color=tlp_color,
            first_fetch=first_fetch,
            limit=limit,
            metadata=metadata,
            enrichment=enrichment,
            types=types
        )

        command_map = {
            "test-module": test_module,
            "threat-intelligence-get-indicators": fetch_indicators,
            "fetch-indicators": batch_fetch_indicators,
            "get-indicator": fetch_indicator_by_value,
            "get-actor": fetch_threat_actor,
            "get-malware": fetch_malware_family,
            "file": fetch_reputation,
            "ip": fetch_reputation,
            "url": fetch_reputation,
            "domain": fetch_reputation,
            "cve": fetch_reputation
        }

        return_results(command_map[demisto.command()](client, args))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
