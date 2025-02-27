from CommonServerPython import *

''' IMPORTS '''
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'AlienVault OTX v2'
INTEGRATION_COMMAND_NAME = 'alienvault'
INTEGRATION_CONTEXT_NAME = 'AlienVaultOTX'


class Client(BaseClient):
    def __init__(self, base_url, headers, verify, proxy, default_threshold, max_indicator_relationships,
                 reliability, create_relationships=True, should_error=True):

        BaseClient.__init__(self, base_url=base_url, headers=headers, verify=verify, proxy=proxy, )

        self.reliability = reliability
        self.create_relationships = create_relationships
        self.default_threshold = default_threshold
        self.max_indicator_relationships = 0 if not max_indicator_relationships else max_indicator_relationships
        self.should_error = should_error

    def test_module(self) -> dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self.query(section='IPv4', argument='8.8.8.8')

    def query(self, section: str, argument: str = None, sub_section: str = 'general', params: dict = None) -> dict:
        """Query the specified kwargs.

        Args:
            section: indicator type
            argument: indicator value
            sub_section: sub section of api
            params: params to send in http request

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        if section == 'pulses':
            suffix = f'{section}/{argument}'
        elif argument and sub_section:
            suffix = f'indicators/{section}/{argument}/{sub_section}'
        else:
            suffix = f'{section}/{sub_section}'
        # Send a request using our http_request wrapper
        if sub_section == 'passive_dns':
            return self._http_request('GET',
                                      url_suffix=suffix,
                                      params=params,
                                      timeout=30)
        try:
            result = self._http_request('GET',
                                        url_suffix=suffix,
                                        params=params)
            return result
        except DemistoException as e:
            if hasattr(e.res, 'status_code'):
                if e.res.status_code == 404:
                    result = 404
                elif e.res.status_code == 400:
                    demisto.debug(f'{e.res.text} response received from server when trying to get api:{e.res.url}')
                    raise Exception(f'The command could not be execute: {argument} is invalid.')
                else:
                    raise
            else:
                raise


''' HELPER FUNCTIONS '''


def calculate_dbot_score(client: Client, raw_response: dict | None) -> float:
    """
    calculate DBot score for query

    Args:
        client: Client object with request
        raw_response: The response gotten from the server

    :returns:
        score - good (if 0), bad (if grater than default), suspicious if between
    """
    default_threshold = int(client.default_threshold)
    false_Positive = {}
    pulase_info_dict = {}
    validation = []
    if isinstance(raw_response, dict):
        false_Positive = raw_response.get('false_positive', {})
        validation = raw_response.get("validation", [])
        pulase_info_dict = raw_response.get('pulse_info', {})
    if false_Positive and false_Positive[0].get("assessment") == "accepted":
        return Common.DBotScore.GOOD
    else:
        if not validation and pulase_info_dict:
            count = int(pulase_info_dict.get('count', '0'))
            if count >= default_threshold:
                return Common.DBotScore.BAD
            elif 0 < count < default_threshold:
                return Common.DBotScore.SUSPICIOUS
            else:
                return Common.DBotScore.NONE
        elif len(validation) == 1:
            return Common.DBotScore.SUSPICIOUS
        else:
            return Common.DBotScore.GOOD


def create_list_by_ec(list_entries: list, list_type: str) -> list:
    def create_entry_by_ec(entry: dict) -> dict:
        if list_type == 'passive_dns':
            return ({
                'Hostname': entry.get('hostname'),
                'IP': entry.get('address'),
                'Type': entry.get('asset_type'),
                'FirstSeen': entry.get('first'),
                'LastSeen': entry.get('last')
            })

        if list_type == 'url_list':
            return assign_params(**{
                'Data': entry.get('url')
            })

        if list_type == 'hash_list':
            return assign_params(**{
                'Hash': entry.get('hash')
            })

        # should not get here
        return {}

    return [create_entry_by_ec(entry) for entry in list_entries]


def create_pulse_by_ec(entry: dict) -> dict:
    pulse_by_ec = {
        'ID': entry.get('id'),
        'Author': {
            'ID': entry.get('author', {}).get('id'),
            'Username': entry.get('author', {}).get('username')
        },
        'Count': entry.get('indicator_count'),
        'Modified': entry.get('modified_text'),
        'Name': entry.get('name'),
        'Source': entry.get('pulse_source'),
        'SubscriberCount': entry.get('subscriber_count'),
        'Tags': entry.get('tags'),
        'Description': entry.get('description')
    }
    return assign_params(**pulse_by_ec)


def extract_attack_ids(raw_response: dict):
    """
    extract the attack_ids field from the raw response if exists

    Args:
        raw_response: The response gotten from the server

    :returns:
        the attack_ids list of all the attack_ids that exists in the response.
    """
    pulses = dict_safe_get(raw_response, ['pulse_info', 'pulses']) or [{}]
    attack_ids = []
    for pulse in pulses:
        if pulse.get('attack_ids'):
            attack_ids.extend(pulse.get('attack_ids'))
    return attack_ids


def relationships_manager(client: Client, entity_a: str, entity_a_type: str, indicator_type: str, attack_ids: list,
                          indicator: str, field_for_passive_dns_rs: str, feed_indicator_type_for_passive_dns_rs: str):
    """
    manage the relationships creation

    Args:
        client: Client object with request
        entity_a: str the first entity of the relationship
        entity_a_type: str the type of the first entity
        indicator_type: str the indicator type to get the related information by
        entity_b_type: str the indicator to get the related information by

    :returns:
        a list of the relationships that were created
    """
    relationships = create_relationships(client, attack_ids, entity_a, entity_a_type, 'display_name',
                                         FeedIndicatorType.indicator_type_by_server_version("STIX Attack Pattern"))

    if client.max_indicator_relationships > 0:
        limit = str(client.max_indicator_relationships)
        _, _, urls_raw_response = alienvault_get_related_urls_by_indicator_command(client, indicator_type, indicator,
                                                                                   limit)
        urls_raw_response = delete_duplicated_entities(urls_raw_response.get('url_list', []), 'url')
        relationships += create_relationships(client, urls_raw_response, entity_a, entity_a_type, 'url',
                                              FeedIndicatorType.URL)

        _, _, hash_raw_response = alienvault_get_related_hashes_by_indicator_command(client, indicator_type, indicator,
                                                                                     limit)
        hash_raw_response = delete_duplicated_entities(hash_raw_response.get('data', []), 'hash')
        relationships += create_relationships(client, hash_raw_response, entity_a, entity_a_type, 'hash',
                                              FeedIndicatorType.File)

        _, _, passive_dns_raw_response = alienvault_get_passive_dns_data_by_indicator_command(client, indicator_type,
                                                                                              indicator, limit)
        passive_dns_raw_response = delete_duplicated_entities(passive_dns_raw_response.get('passive_dns', []),
                                                              field_for_passive_dns_rs)
        passive_dns_raw_response = validate_string_is_not_url(passive_dns_raw_response, field_for_passive_dns_rs)
        passive_dns_raw_response = passive_dns_raw_response[0:client.max_indicator_relationships]
        relationships += create_relationships(client, passive_dns_raw_response, entity_a,
                                              entity_a_type, field_for_passive_dns_rs,
                                              feed_indicator_type_for_passive_dns_rs)

    return relationships


def create_relationships(client: Client, relevant_field: list, entity_a: str,
                         entity_a_type: str, relevant_id: str, entity_b_type: str):
    """
    create relationships list for the given fields

    Args:
        client: Client object with request
        relevant_field: the field that holds the relevant display name(entity_b) for the relationship
        entity_a: str the first entity of the relationship
        entity_a_type: str the type of the first entity
        relevant_id: str the exact key where the display name is located inside the relevant_field
        entity_b_type: str the type of the second entity

    :returns:
        a list of the relationships that were created
    """
    relationships: list = []
    if not client.create_relationships:
        return relationships

    if relevant_field and isinstance(relevant_field, list) and relevant_id in relevant_field[0]:
        display_names = [item.get(relevant_id) for item in relevant_field]
        if display_names:
            relationships = [EntityRelationship(
                name=EntityRelationship.Relationships.INDICATOR_OF,
                entity_a=entity_a,
                entity_a_type=entity_a_type,
                entity_b=display_name,
                entity_b_type=entity_b_type,
                source_reliability=client.reliability,
                brand=INTEGRATION_NAME) for display_name in display_names]
    return relationships


def delete_duplicated_entities(entities_list: List[dict], field_name: str):
    """delete duplicated results from a response

    Args:
        entities_list: The list of the entities brought back from the query.
        field_name: The field to compare according to between the given entities.

    Returns:
        a list without duplicated entities.
    """
    unique_dict: dict = {}
    for entity_dict in entities_list:
        if isinstance(entity_dict, dict) and (ind_value := entity_dict.get(field_name)) not in unique_dict:
            unique_dict[ind_value] = entity_dict
    return list(unique_dict.values())


def validate_string_is_not_url(entities_list: List[dict], field_name: str):
    """delete url type entities from a given list.

    Args:
        entities_list: The list of the entities brought back from the query.
        field_name: The field to compare according to between the given entities.

    Returns:
        a list without url type entities.
    """
    return [dict for dict in entities_list if auto_detect_indicator_type(dict.get(field_name)) != 'URL']


def lowercase_protocol_callback(pattern: re.Match) -> str:
    return pattern.group(0).lower()


''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'city' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def ip_command(client: Client, ip_address: str, ip_version: str) -> List[CommandResults]:
    """ Enrichment for IPv4/IPv6

    Args:
        client: Client object with request
        ip_address: ip address
        ip_version: IPv4 or IPv6

    Returns:
        List of CommandResults
    """
    ips_list: list = argToList(ip_address)

    title = f'{INTEGRATION_NAME} - Results for ips query'
    command_results: List[CommandResults] = []

    for ip_ in ips_list:
        try:
            raw_response = client.query(section=ip_version,
                                        argument=ip_)
        except requests.exceptions.ReadTimeout as e:
            if client.should_error:
                raise e
            demisto.error(f"An error was raised {e=}")
            return_warning(f"{e}")
            raw_response = {}

        if raw_response and raw_response != 404:
            ip_version = FeedIndicatorType.IP if ip_version == 'IPv4' else FeedIndicatorType.IPv6
            relationships = relationships_manager(client, entity_a=ip_, entity_a_type=ip_version,
                                                  indicator_type=ip_version, indicator=ip_,
                                                  field_for_passive_dns_rs="hostname",
                                                  feed_indicator_type_for_passive_dns_rs=FeedIndicatorType.Domain,
                                                  attack_ids=extract_attack_ids(raw_response))

            dbot_score = Common.DBotScore(indicator=ip_, indicator_type=DBotScoreType.IP,
                                          integration_name=INTEGRATION_NAME,
                                          score=calculate_dbot_score(client, raw_response),
                                          reliability=client.reliability)

            ip_object = Common.IP(ip=ip_, dbot_score=dbot_score, asn=raw_response.get('asn'),
                                  geo_country=raw_response.get('country_code'),
                                  geo_latitude=raw_response.get("latitude"),
                                  geo_longitude=raw_response.get("longitude"),
                                  relationships=relationships)

            context = {
                'Reputation': raw_response.get('reputation'),
                'IP': ip_
            }

            human_readable_context = {
                'Address': ip_object.to_context().get('IP(val.Address && val.Address == obj.Address)').get('Address'),
                'Geo': ip_object.to_context().get('IP(val.Address && val.Address == obj.Address)').get('Geo')
            }

            human_readable = tableToMarkdown(
                name=title,
                t=human_readable_context)

            command_results.append(CommandResults(
                readable_output=human_readable,
                outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IP(val.IP && val.IP === obj.IP)',
                outputs={'IP': context},
                indicator=ip_object,
                raw_response=raw_response,
                relationships=relationships
            ))
        else:
            command_results.append(create_indicator_result_with_dbotscore_unknown(indicator=ip_,
                                                                                  indicator_type=DBotScoreType.IP,
                                                                                  reliability=client.reliability))
    if not command_results:
        return [CommandResults(f'{INTEGRATION_NAME} - Could not find any results for given query.')]
    return command_results


@logger
def domain_command(client: Client, domain: str) -> List[CommandResults]:
    """Enrichment for domain

    Args:
        client: Client object with request
        domain: domains to query

    Returns:
        List of CommandResults
    """
    domains_list: list = argToList(domain)

    title = f'{INTEGRATION_NAME} - Results for Domain query'
    command_results: List[CommandResults] = []

    for domain in domains_list:
        try:
            raw_response = client.query(section='domain', argument=domain)
        except requests.exceptions.ReadTimeout as e:
            if client.should_error:
                raise e
            demisto.error(f"An error was raised {e=}")
            return_warning(f"{e}")
            raw_response = {}

        if raw_response and raw_response != 404:
            relationships = relationships_manager(client, entity_a=domain, indicator_type='domain',
                                                  entity_a_type=FeedIndicatorType.Domain, indicator=domain,
                                                  field_for_passive_dns_rs='address',
                                                  feed_indicator_type_for_passive_dns_rs=FeedIndicatorType.IP,
                                                  attack_ids=extract_attack_ids(raw_response))

            dbot_score = Common.DBotScore(indicator=domain, indicator_type=DBotScoreType.DOMAIN,
                                          integration_name=INTEGRATION_NAME,
                                          score=calculate_dbot_score(client, raw_response),
                                          reliability=client.reliability)
            domain_object = Common.Domain(domain=domain, dbot_score=dbot_score, relationships=relationships)

            context = {
                'Name': raw_response.get('indicator'),
                'Alexa': raw_response.get('alexa'),
                'Whois': raw_response.get('whois')
            }

            human_readable = tableToMarkdown(t=context, name=title)

            command_results.append(CommandResults(
                readable_output=human_readable,
                outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Domain(val.Alexa && val.Alexa === obj.Alexa &&'
                               f' val.Whois && val.Whois === obj.Whois)',
                outputs=context,
                indicator=domain_object,
                raw_response=raw_response,
                relationships=relationships
            ))
        else:
            command_results.append(create_indicator_result_with_dbotscore_unknown(indicator=domain,
                                                                                  indicator_type=DBotScoreType.DOMAIN,
                                                                                  reliability=client.reliability))
    if not command_results:
        return [CommandResults(f'{INTEGRATION_NAME} - Could not find any results for given query')]

    return command_results


@logger
def file_command(client: Client, file: str) -> List[CommandResults]:
    """Enrichment for file hash MD5/SHA1/SHA256

    Args:
        client: Client object with request
        file: File hash MD5/SHA1/SHA256

    Returns:
        List of CommandResults
    """
    hashes_list: list = argToList(file)

    title = f'{INTEGRATION_NAME} - Results for File hash query'
    command_results: List[CommandResults] = []

    for hash_ in hashes_list:
        try:
            raw_response_analysis = client.query(section='file',
                                                argument=hash_,
                                                sub_section='analysis')
            raw_response_general = client.query(section='file',
                                                argument=hash_)
        except requests.exceptions.ReadTimeout as e:
            if client.should_error:
                raise e
            demisto.error(f"An error was raised {e=}")
            return_warning(f"{e}")
            raw_response_analysis =  {}

        if raw_response_analysis and raw_response_general and (
                shortcut := dict_safe_get(raw_response_analysis, ['analysis', 'info', 'results'],
                                          {})) and raw_response_general != 404 and raw_response_analysis != 404:

            relationships = create_relationships(client, extract_attack_ids(raw_response_general), hash_,
                                                 FeedIndicatorType.File, 'display_name',
                                                 FeedIndicatorType.indicator_type_by_server_version(
                                                     "STIX Attack Pattern"))

            dbot_score = Common.DBotScore(
                indicator=hash_, indicator_type=DBotScoreType.FILE, integration_name=INTEGRATION_NAME,
                score=calculate_dbot_score(client, raw_response_general),
                malicious_description=raw_response_general.get('pulse_info', {}).get('pulses'),
                reliability=client.reliability)

            file_object = Common.File(md5=shortcut.get('md5'), sha1=shortcut.get('sha1'), sha256=shortcut.get('sha256'),
                                      ssdeep=shortcut.get('ssdeep'), size=shortcut.get('filesize'),
                                      file_type=shortcut.get('file_type'), dbot_score=dbot_score,
                                      relationships=relationships)

            context = {
                'MD5': shortcut.get('md5'),
                'SHA1': shortcut.get('sha1'),
                'SHA256': shortcut.get('sha256'),
                'SSDeep': shortcut.get('ssdeep'),
                'Size': shortcut.get('filesize'),
                'Type': shortcut.get('file_type'),
                'Malicious': {
                    'PulseIDs': raw_response_general.get('pulse_info', {}).get('pulses')
                }
            }

            human_readable = tableToMarkdown(name=title, t=context)

            command_results.append(CommandResults(
                readable_output=human_readable,
                outputs_prefix=outputPaths.get("file"),
                outputs=context,
                indicator=file_object,
                raw_response=raw_response_general,
                relationships=relationships
            ))
        else:
            command_results.append(create_indicator_result_with_dbotscore_unknown(indicator=hash_,
                                                                                  indicator_type=DBotScoreType.FILE,
                                                                                  reliability=client.reliability))
    if not command_results:
        return [CommandResults(f'{INTEGRATION_NAME} - Could not find any results for given query')]

    return command_results


@logger
def url_command(client: Client, url: str) -> List[CommandResults]:
    """Enrichment for url

    Args:
        client: Client object with request
        url:  url address

    Returns:
        List of CommandResults
    """
    urls_list: list = argToList(url)

    title = f'{INTEGRATION_NAME} - Results for url query'
    command_results: List[CommandResults] = []

    for url in urls_list:
        url = re.sub(r'(\w+)://', lowercase_protocol_callback, url)
        try:
            raw_response = client.query(section='url', argument=url)
        except requests.exceptions.ReadTimeout as e:
            if client.should_error:
                raise e
            demisto.error(f"An error was raised {e=}")
            return_warning(f"{e}")
            raw_response = 404

        if raw_response:
            if raw_response == 404:
                command_results.append(create_indicator_result_with_dbotscore_unknown(indicator=url,
                                                                                      indicator_type=DBotScoreType.URL,
                                                                                      reliability=client.reliability))
            else:

                relationships = []
                if client.create_relationships:
                    indicator = FeedIndicatorType.indicator_type_by_server_version("STIX Attack Pattern")
                    relationships = create_relationships(client, extract_attack_ids(raw_response), url,
                                                         FeedIndicatorType.URL, 'display_name', indicator)

                    domain = raw_response.get('domain')
                    if domain:
                        relationships.extend([EntityRelationship(
                            name=EntityRelationship.Relationships.HOSTED_ON, entity_a=url,
                            entity_a_type=FeedIndicatorType.URL,
                            entity_b=domain, entity_b_type=FeedIndicatorType.Domain,
                            source_reliability=client.reliability, brand=INTEGRATION_NAME)])

                dbot_score = Common.DBotScore(
                    indicator=url, indicator_type=DBotScoreType.URL, integration_name=INTEGRATION_NAME,
                    score=calculate_dbot_score(client, raw_response), reliability=client.reliability)

                url_object = Common.URL(url=url, dbot_score=dbot_score, relationships=relationships)

                context = {
                    'Url': url,
                    'Hostname': raw_response.get('hostname'),
                    'Domain': raw_response.get('domain'),
                    'Alexa': raw_response.get('alexa'),
                    'Whois': raw_response.get('whois')
                }

                human_readable = tableToMarkdown(name=title, t=context)

                command_results.append(CommandResults(
                    readable_output=human_readable,
                    outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.URL(val.Url && val.Url === obj.Url)',
                    outputs=context,
                    indicator=url_object,
                    raw_response=raw_response,
                    relationships=relationships
                ))

    if not command_results:
        command_results.append(CommandResults(f'{INTEGRATION_NAME} - Could not find any results for given query'))
    return command_results


@logger
def alienvault_search_hostname_command(client: Client, hostname: str) -> tuple[str, dict, dict]:
    """Search for hostname details

    Args:
        client: Client object with request
        hostname: hostname address

    Returns:
        Outputs
    """
    raw_response = client.query(section='hostname', argument=hostname)
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - Results for Hostname query'
        context_entry: dict = {
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': {
                'Hostname': raw_response.get('indicator')
            },
            'AlienVaultOTX.Endpoint(val.Alexa && val.Alexa === obj.Alexa &&'
            'val.Whois && val.Whois === obj.Whois)': {
                'Hostname': raw_response.get('indicator'),
                'Alexa': raw_response.get('alexa'),
                'Whois': raw_response.get('whois')
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(client, raw_response),
                'Type': 'hostname',
                'Vendor': 'AlienVault OTX v2',
                'Reliability': client.reliability
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=context_entry.get(
                                             'AlienVaultOTX.Endpoint(val.Alexa && val.Alexa === obj.Alexa &&'
                                             'val.Whois && val.Whois === obj.Whois)'))

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_search_cve_command(client: Client, cve_id: str) -> tuple[str, dict, dict]:
    """Get Common Vulnerabilities and Exposures by id

    Args:
        client: Client object with request
        cve_id: CVE id

    Returns:
        Outputs
    """
    raw_response = client.query(section='cve',
                                argument=cve_id)
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - Results for Hostname query'
        context_entry: dict = {
            outputPaths.get("cve"): {
                'ID': raw_response.get('indicator'),
                'CVSS': raw_response.get('cvss', {}).get('Score'),
                'Published': raw_response.get('date_created'),
                'Modified': raw_response.get('date_modified'),
                'Description': raw_response.get('description')
            },
            outputPaths.get("dbotscore"): {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(client, raw_response),
                'Type': 'cve',
                'Vendor': 'AlienVault OTX v2',
                'Reliability': client.reliability
            }
        }
        human_readable = tableToMarkdown(t=context_entry.get(outputPaths.get("cve")),
                                         name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_related_urls_by_indicator_command(client: Client, indicator_type: str, indicator: str,
                                                     limit: str = '') \
        -> tuple[str, dict, dict]:
    """Get related urls by indicator (IPv4,IPv6,domain,hostname,url)

    Args:
        client: Client object with request
        indicator_type: IPv4,IPv6,domain,hostname,url
        indicator: indicator its self (google.com)
        limit: the maximum number of indicators to fetch

    Returns:
        Outputs
    """
    if indicator_type == "IP":
        indicator_type = "IPv4"
    params = {}
    if limit:
        params['limit'] = limit
    raw_response = client.query(section=indicator_type,
                                argument=indicator,
                                sub_section='url_list',
                                params=params)
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - Related url list to queried indicator'
        context_entry: list = create_list_by_ec(list_entries=raw_response.get('url_list', {}), list_type='url_list')
        context: dict = {
            'AlienVaultOTX.URL(val.URL.Data && val.URL.Data == obj.URL.Data)': context_entry
        }
        human_readable = tableToMarkdown(t=context_entry, name=title)

        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_related_hashes_by_indicator_command(client: Client, indicator_type: str, indicator: str,
                                                       limit: str = '') \
        -> tuple[str, dict, dict]:
    """Get related file hashes by indicator (IPv4,IPv6,domain,hostname)

       Args:
           client: Client object with request
           indicator_type: IPv4,IPv6,domain,hostname
           indicator: indicator its self (google.com)
           limit: the maximum number of indicators to fetch

       Returns:
           Outputs
       """
    if indicator_type == "IP":
        indicator_type = "IPv4"
    params = {}
    if limit:
        params['limit'] = limit
    raw_response = client.query(section=indicator_type,
                                argument=indicator,
                                sub_section='malware',
                                params=params)
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - Related malware list to queried indicator'
        context_entry: dict = {
            'AlienVaultOTX.File(val.File.Hash && val.File.Hash == obj.File.Hash)':
                create_list_by_ec(list_entries=raw_response.get('data', {}), list_type='hash_list')
        }
        human_readable = tableToMarkdown(t=context_entry.get('AlienVaultOTX.File(val.File.Hash && val.File.Hash \
                                            == obj.File.Hash)'),
                                         name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_passive_dns_data_by_indicator_command(client: Client, indicator_type: str, indicator: str,
                                                         limit: str = '') -> tuple[str, dict, dict]:
    """Get related file hashes by indicator (IPv4,IPv6,domain,hostname)

       Args:
           client: Client object with request
           indicator_type: IPv4,IPv6,domain,hostname
           indicator: indicator its self (google.com)
           limit: the maximum number of indicators to fetch
       Returns:
           Outputs
       """
    if indicator_type == "IP":
        indicator_type = "IPv4"
    params = {}
    if limit:
        params['limit'] = limit
    raw_response = client.query(section=indicator_type,
                                argument=indicator,
                                sub_section='passive_dns',
                                params=params)
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - Related passive dns list to queried indicator'
        context_entry: dict = {
            'AlienVaultOTX.PassiveDNS(val.PassiveDNS.Hostname && val.PassiveDNS.Hostname == obj.PassiveDNS.Hostname &&'
            'val.PassiveDNS.LastSeen && val.PassiveDNS.LastSeen == obj.PassiveDNS.LastSeen &&'
            'val.PassiveDNS.IP && val.PassiveDNS.IP == obj.PassiveDNS.IP)':
                create_list_by_ec(list_entries=raw_response.get('passive_dns', {}), list_type='passive_dns')
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            'AlienVaultOTX.PassiveDNS(val.PassiveDNS.Hostname && val.PassiveDNS.Hostname == obj.PassiveDNS.Hostname &&'
            'val.PassiveDNS.LastSeen && val.PassiveDNS.LastSeen == obj.PassiveDNS.LastSeen &&'
            'val.PassiveDNS.IP && val.PassiveDNS.IP == obj.PassiveDNS.IP)'),
            name=title)
        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_search_pulses_command(client: Client, page: str) -> tuple[str, dict, dict]:
    """Get pulse page by number of the page

    Args:
        client: Client object with request
        page: pulse page number

    Returns:
        Outputs
    """
    raw_response = client.query(section='search',
                                sub_section='pulses',
                                params={'page': page})
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - pulse page {page}'
        context_entry: dict = {
            'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID && '
            'val.Modified && val.Modified == obj.Modified)':
                [create_pulse_by_ec(entry) for entry in raw_response.get('results', {})]
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID && '
            'val.Modified && val.Modified == obj.Modified)'),
            name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def alienvault_get_pulse_details_command(client: Client, pulse_id: str) -> tuple[str, dict, dict]:
    """Get pulse by ID

    Args:
        client: Client object with request
        pulse_id: pulse ID

    Returns:
        Outputs
    """
    raw_response = client.query(section='pulses',
                                argument=pulse_id)
    if raw_response and raw_response != 404:
        title = f'{INTEGRATION_NAME} - pulse id details'
        context_entry: dict = {
            'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID)': {
                'Description': raw_response.get('description'),
                'Created': raw_response.get('created'),
                'Author': {
                    'Username': raw_response.get('author', {}).get('username')
                },
                'ID': raw_response.get('id'),
                'Name': raw_response.get('name'),
                'Tags': raw_response.get('tags'),
                'TargetedCountries': raw_response.get('targeted_countries')
            }
        }
        human_readable = tableToMarkdown(t=context_entry.get(
            'AlienVaultOTX.Pulses(val.ID && val.ID == obj.ID)'),
            name=title)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()

    base_url = urljoin(params.get('url'), '/api/v1/')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    default_threshold = int(params.get('default_threshold', 2))
    max_indicator_relationships = arg_to_number(params.get('max_indicator_relationships', 0))
    token = params.get('credentials', {}).get('password', '') or params.get('api_token', '')
    reliability = params.get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.C
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Please provide a valid value for the Source Reliability parameter.")
    should_error = argToBoolean(params.get('should_error', True))

    client = Client(
        base_url=base_url,
        headers={'X-OTX-API-KEY': token},
        verify=verify_ssl,
        proxy=proxy,
        default_threshold=default_threshold,
        reliability=reliability,
        create_relationships=argToBoolean(params.get('create_relationships')),
        max_indicator_relationships=max_indicator_relationships,
        should_error=should_error
    )

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        'domain': domain_command,
        'file': file_command,
        'url': url_command,
        f'{INTEGRATION_COMMAND_NAME}-search-hostname': alienvault_search_hostname_command,
        f'{INTEGRATION_COMMAND_NAME}-search-cve': alienvault_search_cve_command,
        f'{INTEGRATION_COMMAND_NAME}-get-related-urls-by-indicator': alienvault_get_related_urls_by_indicator_command,
        f'{INTEGRATION_COMMAND_NAME}-get-related-hashes-by-indicator': alienvault_get_related_hashes_by_indicator_command,
        f'{INTEGRATION_COMMAND_NAME}-get-passive-dns-data-by-indicator': alienvault_get_passive_dns_data_by_indicator_command,
        f'{INTEGRATION_COMMAND_NAME}-search-pulses': alienvault_search_pulses_command,
        f'{INTEGRATION_COMMAND_NAME}-get-pulse-details': alienvault_get_pulse_details_command
    }
    try:
        if command == f'{INTEGRATION_COMMAND_NAME}-search-ipv6':
            return_results(ip_command(client=client,
                                      ip_address=demisto.args().get('ip'),
                                      ip_version='IPv6'))
        elif command == 'ip':
            return_results(ip_command(client=client,
                                      ip_address=demisto.args().get('ip'),
                                      ip_version='IPv4'))
        elif command in ['file', 'domain', 'url']:
            return_results(commands[command](client=client, **demisto.args()))
        else:
            readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
