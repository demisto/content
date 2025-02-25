from collections import defaultdict
from typing import Tuple, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket
from ipaddress import ip_network, ip_address
import traceback
import re
from collections.abc import Callable

UnmergedIPDataDict = dict[str, list[dict]]
MergedIPDataDict = dict[str, dict]
EnrichmentRawResults = list[dict]
EnrichmentFullOutputsDict = MergedIPDataDict
EnrichmentCommonIPsDict = dict[str, list[Common.IP]]
EnrichmentCommonIPsCommandResults = list[CommandResults]
HumanReadable = CommandResults
EnrichmentContextOutputs = tuple[UnmergedIPDataDict, EnrichmentCommonIPsDict]
HumanReadableList = list[str]
EnrichmentSubCommandOutput = Tuple[
    EnrichmentFullOutputsDict, EnrichmentCommonIPsDict, Optional[CommandResults]]

EnrichmentSubFlowOutput = Tuple[
    EnrichmentFullOutputsDict, EnrichmentCommonIPsDict, List[Optional[CommandResults]]]

PRIVATE_SUBNETS = [
    '172.16.0.0/12',
    '10.0.0.0/8',
    '198.18.0.0/15',
    '192.168.0.0/16',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '192.0.0.0/24',
    '0.0.0.0/8',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '255.255.255.255/32'
]


def is_brand_available(brand: str) -> bool:
    """Check if a brand is active and available."""
    return brand in {
        module.get("brand")
        for module in demisto.getModules().values()
        if module.get("state") == "active"
    }


def hr_to_command_results(
    command_name: str, args: dict[str, Any], human_readable: str, is_error: bool = False
) -> CommandResults | None:
    """
    Prepares human-readable output for a command execution.

    This function creates a formatted message containing the command details and its output.
    It can handle both successful executions and errors.

    Args:
        command_name (str): The name of the executed command.
        args (dict[str, Any]): A dictionary of command arguments and their values.
        human_readable (str): The human-readable output of the command.
        is_error (bool, optional): Flag indicating if the result is an error. Defaults to False.

    Returns:
        CommandResults: A list containing a CommandResults object with the formatted output.
    """

    command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
    result_type = EntryType.ERROR if is_error else None
    result_message = f"#### {'Error' if is_error else 'Result'} for {command}\n{human_readable}"
    return CommandResults(readable_output=result_message, entry_type=result_type, mark_as_note=True)


######################## OUTPUT PROCESSING FUNCTIONS ########################


def enrich_data_with_source(data: dict, source: str) -> dict:
    """
    Enrich the provided data with source information.

    This function recursively processes the input data, adding source information to each value
    and handling nested structures.

    Args:
        data (dict): The input data to be enriched.
        source (str): The source information to be added to each value.

    Returns:
        dict: The enriched data with source information added to each value.

    Note:
        - Empty elements are removed from the input data before processing.
        - Single-element lists are unwrapped to their contained value.
        - Nested dictionaries are processed recursively.
    """
    data = remove_empty_elements(data)
    result = {}
    for key, value in data.items():
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if isinstance(value, dict):
            result[key] = enrich_data_with_source(value, source)
        else:
            result[key] = {"Value": value, "Source": source}
    return result


def append_to_dict_list(target: dict[str, list[dict]], key: str, value: dict):
    if key not in target:
        target[key] = []
    target[key].append(value)


def merge_ip(ip_objects: list[dict]) -> dict[str, Any]:
    """
    Merge multiple ip dictionaries into a single ip.

    This function merges a list of ip dictionaries into a single ip dictionary.
    It handles nested dictionaries and special cases where a value is a dictionary with 'Value' and 'Source' keys.
    The merged ip is then converted to a Common.IP object and its context is returned.

    Args:
        ip_objects (list[dict[str, str]]): A list of ip dictionaries to merge.

    Returns:
        dict[str, Any]: A merged ip dictionary in the Common.IP context format.
                        Returns an empty dictionary if the input list is empty.
    """

    def recursive_merge(target: dict, source: dict):
        for key, value in source.items():
            # Check if the value is a dictionary and has specific keys 'Value' and 'Source'
            if isinstance(value, dict) and "Value" in value and "Source" in value:
                append_to_dict_list(target, key, value)
            elif isinstance(value, dict):
                if key not in target:
                    target[key] = {}
                recursive_merge(target[key], value)
            else:
                target[key] = value

    if len(ip_objects) == 1:
        return ip_objects[0]

    merged_ip: dict[str, Any] = {}
    for ip in ip_objects:
        recursive_merge(merged_ip, ip)
    return merged_ip


def group_values_by_keys(data: List[Dict[str, dict]]) -> Dict[str, List[Dict[str, dict]]]:
    """
    Transforms a list of dictionaries by grouping values under the same keys into lists.

    Args:
        data (List[Dict[str, Any]]): A list of dictionaries with common keys.

    Returns:
        Dict[str, List[Any]]: A dictionary where each key contains a list of corresponding values.
    """
    result = defaultdict(list)
    for entry in data:
        for key, value in entry.items():
            result[key].append(value)
    return dict(result)


def merge_ips(ips: list[EnrichmentFullOutputsDict]) -> MergedIPDataDict:
    """
    list of dicts, each holds outputs for various ips.
    across all dicts, merge the lists recursively for matching ip keys.
    """
    merged_result: Dict[str, Dict[str, Any]] = {}
    grouped_ip_objects: Dict[str, List[Dict[str, dict]]] = group_values_by_keys(ips)

    for ip_address, ip_outputs in grouped_ip_objects.items():
        if ip_address not in merged_result:
            merged_result[ip_address] = {}
        merged_result[ip_address] = merge_ip(ip_outputs)

    return merged_result


def common_ip_to_command_result(common_ips: EnrichmentCommonIPsDict) -> [CommandResults]:
    common_ip_objects = list(common_ips.values())
    common_ip_command_results = []
    for common_ip_list in common_ip_objects:
        for common_ip in common_ip_list:
            common_ip_command_results.append(CommandResults(indicator=common_ip))
    return common_ip_command_results


######### IP ENRICHMENT HELPER FUNCTIONS #########

def get_private_ips() -> list[str]:
    """Retrieve the list of private IP subnets."""
    # todo: error handeling
    private_ips_list = demisto.executeCommand("getList", {"listName": "PrivateIPs"})[0]["Contents"]
    private_ips = re.findall(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b/\d{1,2})", private_ips_list)
    return private_ips if private_ips else PRIVATE_SUBNETS


def is_ip_internal(ip: str) -> bool:
    """Determine if an IP is internal based on private subnets."""

    def is_ip_in_subnet(ip: str, subnet: str) -> bool:
        try:
            return ip_address(ip) in ip_network(subnet, strict=False)
        except ValueError:
            return False

    ip_ranges = get_private_ips()
    return any(is_ip_in_subnet(ip, subnet.strip()) for subnet in ip_ranges)


def separate_ips(ip_list: list[str]) -> tuple[list[str], list[str]]:
    """
    Separates a list of IPs into internal and external lists using set deduction.

    Args:
        ip_list (list[str]): A list of IP addresses.

    Returns:
        tuple[list[str], list[str]]: Two lists - internal IPs and external IPs.
    """
    internal_ips = {ip for ip in ip_list if is_ip_internal(ip)}
    external_ips = set(ip_list) - internal_ips
    return list(internal_ips), list(external_ips)


#################################################################################################


########################### search indicators #################################
def generate_common_ip_from_ip_indicator(ip_address: str, ip_type: str, score: int, custom_fields: dict) -> Common.IP:
    """
    todo: get a response regarding this for a complete mapping - https://panw-global.slack.com/archives/D072EEC9XJM/p1738588622110269

    """
    geolocation = custom_fields.get("geolocation", "").split(':')
    geo_latitude, geo_longitude = geolocation if len(geolocation) == 2 else (None, None)
    return Common.IP(
        dbot_score=Common.DBotScore(indicator=ip_address, indicator_type=DBotScoreType.IP, score=score),
        # todo - which dbot score should I put?
        ip=ip_address,
        ip_type=ip_type,
        asn=custom_fields.get('asn'),
        feed_related_indicators=[Common.FeedRelatedIndicators(
            value=indicator.get("value"),
            indicator_type=indicator.get("type"),
            description=indicator.get("description")

        ) for indicator in custom_fields.get("feedrelatedindicators", [])],
        geo_country=custom_fields.get("geocountry"),
        geo_latitude=geo_latitude,
        geo_longitude=geo_longitude,  # todo confirm order
        organization_name=custom_fields.get("organization"),
        organization_type=custom_fields.get("organizationtype"),
        positive_engines=custom_fields.get("positivedetections"),
        detection_engines=custom_fields.get("detectionengines"),
        hostname=custom_fields.get("hostname"),
        tags=custom_fields.get("tags"),
    )


def map_search_indicator_to_context(ip_indicator):
    filtered_ip_indicator = {key: value for key, value in ip_indicator.items() if
                             key not in ["CustomFields", "insightCache", "cacheVersn"]}
    return enrich_data_with_source(data=filtered_ip_indicator, source="searchIndicators")


def get_search_indicators_context_outputs(iocs: list[dict]) -> EnrichmentContextOutputs:
    """
    todo: describe the ioc stricture
    """
    full_outputs: UnmergedIPDataDict = {}
    common_ip_outputs: EnrichmentCommonIPsDict = {}
    for ip_indicator in iocs:
        # todo - which fields should be excluded?
        ip_address = ip_indicator.get('value')
        common_ip: Common.IP = generate_common_ip_from_ip_indicator(ip_address=ip_address,
                                                                    ip_type=ip_indicator.get('indicator_type'),
                                                                    score=ip_indicator.get('score'),
                                                                    custom_fields=ip_indicator.get('CustomFields', {}))
        ip_indicator_mapped_context = map_search_indicator_to_context(ip_indicator)
        append_to_dict_list(common_ip_outputs, ip_address, common_ip)
        append_to_dict_list(full_outputs, ip_address, ip_indicator_mapped_context)

    return full_outputs, common_ip_outputs


def search_indicators(ips: list[str], verbose: bool) -> EnrichmentSubCommandOutput:
    """Retrieve TIM data for IP indicators."""
    ips_value_query = " or ".join([f"value:{ip}" for ip in ips])
    query = f"(type:IPv6 or type:IPv6CIDR or type:IP) and ({ips_value_query})"
    # todo: describe the raw results structure
    raw_results: dict = demisto.searchIndicators(query=query)  # todo: reffer to batch search
    iocs: list[dict] = raw_results.get('iocs', [])
    outputs, common_ips = get_search_indicators_context_outputs(iocs)
    merged_search_indicators_outputs = merge_ips_outputs(outputs)
    hr = hr_to_command_results('searchIndicators', {'query': query},
                               str(raw_results)) if verbose else None  #todo - no human readable, look at the command when calling directly?

    return merged_search_indicators_outputs, common_ips, hr


######################################## internal flow #######################################

def generate_common_ip_from_endpoint_data(ip_address: str, endpoint_data: dict) -> Common.IP:
    return Common.IP(
        ip=ip_address,
        dbot_score=None
    )


def map_endpoint_data_to_context(endpoint_data):
    return endpoint_data


def get_endpoint_data_outputs(endpoints_data: List) -> EnrichmentContextOutputs:
    # print("get_endpoint_data_outputs")
    # todo: transform to dicts grouping by the IPAddress
    full_outputs = {}
    common_ip_outputs = {}
    # print(endpoints_data)
    if endpoints_data:
        endpoints_data[-1].get('EntryContext', {}).get("Endpoint(val.Hostname.Value && val.Hostname.Value == obj.Hostname.Value)",
                                                       [])  #get the last command results which will contain the actual data
    # for endpoint_data in endpoints_data:  # todo: do all the endpoints returned in a list in the entry context?
    #     common_ip = generate_common_ip_from_endpoint_data()
    #     endpoint_data_mapped_context = map_endpoint_data_to_context(endpoint_data)
    #     print(endpoint_data_mapped_context)
    #     common_ip_mapped_context = {}  # common_ip.to_context()
    #     # print(common_ip_mapped_context)
    #     outputs.append(endpoint_data_mapped_context)
    #     common_ips.append(common_ip_mapped_context)
    return full_outputs, common_ip_outputs


def get_endpoint_data_hr(hr_outputs: List[str], args: dict[str, Any]) -> CommandResults | None:
    hr = "\n".join(hr_outputs)
    return hr_to_command_results('get-endpoint-data', args, hr)


def get_endpoint_data(ips: list[str], verbose: bool) -> EnrichmentSubCommandOutput:
    # todo: check what happens when verbose is false
    ip_agent_brands = "VMware Carbon Black EDR v2,Cortex Core - IR,Generic Command,Cortex XDR - IR"
    command_name = "get-endpoint-data"
    outputs = {}
    common_ips = {}
    hr_outputs = []

    for ip in ips:
        args = {"agent_ip": ip, "verbose": str(verbose), "brands": ip_agent_brands}  # bug in get-endpoint-data, run only on
        # explicit agent_ip modules until resolved
        #running in a loop since get-endpoint-data lacks notion of order and object assoication
        raw_results = demisto.executeCommand(command_name, args)
        # todo: how is data returned for a list?
        if raw_results:
            get_endpoint_data_ip_output: list[dict] = raw_results[-1].get('EntryContext', {}).get(
                "Endpoint(val.Hostname.Value && val.Hostname.Value == obj.Hostname.Value)", [])
            outputs[ip] = {"Endpoint": get_endpoint_data_ip_output}
            if verbose:
                for endpoint_data in raw_results:
                    hr: Optional[str] = endpoint_data.get('HumanReadable')
                    if hr:
                        hr_outputs.append(hr)

        # outputs, common_ips = get_endpoint_data_outputs(raw_results)  # todo: can I access the key in this way? does it return a list for all the ips under the list of entry contetx?
    hr = get_endpoint_data_hr(hr_outputs, {"verbose": str(verbose)}) if verbose else None
    return outputs, common_ips, hr


######################################## external flow #######################################
def generate_common_ip_from_reputations_data(ip_context: dict) -> Common.IP:
    """
     Reconstructs an IP object from its context data.

     :type ip_context: ``dict``
     :param ip_context: The context data dictionary obtained from the to_context method.

     :return: An instance of the Common.IP class.
     :rtype: ``Common.IP``
     """

    #todo: ensure all are build as correct types

    ip_address = ip_context.get('Address')
    asn = ip_context.get('ASN')
    as_owner = ip_context.get('ASOwner')
    region = ip_context.get('Region')
    port = ip_context.get('Port')
    internal = ip_context.get('Internal')
    stix_id = ip_context.get('STIXID')
    updated_date = ip_context.get('UpdatedDate')
    registrar = ip_context.get('Registrar', {}).get('Abuse', {})
    registrar_abuse_name = registrar.get('Name')
    registrar_abuse_address = registrar.get('Address')
    registrar_abuse_country = registrar.get('Country')
    registrar_abuse_network = registrar.get('Network')
    registrar_abuse_phone = registrar.get('Phone')
    registrar_abuse_email = registrar.get('Email')
    campaign = ip_context.get('Campaign')
    description = ip_context.get('Description')
    traffic_light_protocol = ip_context.get('TrafficLightProtocol')
    community_notes = ip_context.get('CommunityNotes')
    publications = ip_context.get('Publications')
    threat_types = ip_context.get('ThreatTypes')
    hostname = ip_context.get('Hostname')
    geo = ip_context.get('Geo', {})
    geo_latitude = geo.get('Location', '').split(':')[0] if 'Location' in geo else None
    geo_longitude = geo.get('Location', '').split(':')[1] if 'Location' in geo else None
    geo_country = geo.get('Country')
    geo_description = geo.get('Description')
    detection_engines = ip_context.get('DetectionEngines')
    positive_engines = ip_context.get('PositiveDetections')
    organization = ip_context.get('Organization', {})
    organization_name = organization.get('Name')
    organization_type = organization.get('Type')
    feed_related_indicators = ip_context.get('FeedRelatedIndicators')
    tags = ip_context.get('Tags')
    malware_family = ip_context.get('MalwareFamily')
    relationships = ip_context.get('Relationships')
    blocked = ip_context.get('Blocked')
    organization_prevalence = ip_context.get('OrganizationPrevalence')
    global_prevalence = ip_context.get('GlobalPrevalence')
    organization_first_seen = ip_context.get('OrganizationFirstSeen')
    organization_last_seen = ip_context.get('OrganizationLastSeen')
    first_seen_by_source = ip_context.get('FirstSeenBySource')
    last_seen_by_source = ip_context.get('LastSeenBySource')

    dbot_score = Common.DBotScore(
        indicator=ip_address,
        indicator_type=DBotScoreType.IP,
        score=Common.DBotScore.NONE
        # integration_name='YourIntegrationName',  # Replace with the actual integration name
        # score=dbot_score_value,
        # malicious_description=malicious.get('Description') if malicious else None
    )

    ip_object = Common.IP(
        ip=ip_address,
        dbot_score=dbot_score,
        asn=asn,
        as_owner=as_owner,
        region=region,
        port=port,
        internal=internal,
        updated_date=updated_date,
        registrar_abuse_name=registrar_abuse_name,
        registrar_abuse_address=registrar_abuse_address,
        registrar_abuse_country=registrar_abuse_country,
        registrar_abuse_network=registrar_abuse_network,
        registrar_abuse_phone=registrar_abuse_phone,
        registrar_abuse_email=registrar_abuse_email,
        campaign=campaign,
        traffic_light_protocol=traffic_light_protocol,
        # community_notes=community_notes,
        # publications=publications,
        # threat_types=threat_types,
        hostname=hostname,
        geo_latitude=geo_latitude,
        geo_longitude=geo_longitude,
        geo_country=geo_country,
        geo_description=geo_description,
        detection_engines=detection_engines,
        positive_engines=positive_engines,
        organization_name=organization_name,
        organization_type=organization_type,
        # feed_related_indicators=feed_related_indicators,
        tags=tags,
        malware_family=malware_family,
        # relationships=relationships,
        blocked=blocked,
        description=description,
        stix_id=stix_id,
        # whois_records=None,  # Assuming WHOIS records are not available in the context
        organization_prevalence=organization_prevalence,
        global_prevalence=global_prevalence,
        organization_first_seen=organization_first_seen,
        organization_last_seen=organization_last_seen,
        first_seen_by_source=first_seen_by_source,
        last_seen_by_source=last_seen_by_source,
        ip_type="IP"  # or "IPv6" based on your context
    )

    return ip_object


def map_reputation_data_to_context(reputation_data: dict) -> dict:
    """
    extracts the objects under <integration_name>.IP returned by the reputation command and enriches them with the value and source new convention.
    """
    mapped_reputation_data = []
    for key, value in reputation_data.items():  # usually there is only one since the structure of reputation is IP, DBoyrScore
        # and the Integration name,from observation, but just adding to make sure.
        source_name = key.split(".")[0]
        mapped_reputation_data.append(enrich_data_with_source(value, source_name))
    if len(mapped_reputation_data) > 1:
        return merge_ip(mapped_reputation_data)

    return mapped_reputation_data[0] if mapped_reputation_data else {}


def merge_ips_outputs(outputs: UnmergedIPDataDict) -> MergedIPDataDict:
    """
    given a dict with list of data objects per ip, merged the list to a single object and sets it for the ip
    """
    merged_outputs = {}
    for ip_address, outputs_list in outputs.items():
        merged_outputs[ip_address] = merge_ip(outputs_list)
    return merged_outputs


def get_reputation_context_outputs(reputations_data: List) -> EnrichmentContextOutputs:
    """
    for a single end point, the reputations data is a list of objects , each is a command result, contains entry context which consists of:
    dbotscore, ip, and the brand.ip objects. I can identify the ip in question using the address if various ip are returned in one list
    """
    excluded_keys = {
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)",
        "IP(val.Address && val.Address == obj.Address)"
    }
    full_outputs: UnmergedIPDataDict = {}  # dict that maps the outputs for each ip address
    common_ip_outputs: EnrichmentCommonIPsDict = {}  # dict that maps the ip object generated by each brand
    for reputation_data in reputations_data:
        entry_context: Optional[dict] = reputation_data.get(
            'EntryContext')  # todo: if no entry context, and type is 4, should we report this? only if verbose?
        if entry_context:
            ip_context = entry_context.get("IP(val.Address && val.Address == obj.Address)", [])
            if not ip_context:
                continue
            ip_context = ip_context[0]
            address = ip_context.get("Address")
            common_ip = generate_common_ip_from_reputations_data(ip_context)
            reputation_data_mapped_context = map_reputation_data_to_context(
                {key: value for key, value in entry_context.items() if key not in excluded_keys})
            append_to_dict_list(full_outputs, address, reputation_data_mapped_context)
            append_to_dict_list(common_ip_outputs, address, common_ip)

            # todo - dbot score handle

    return full_outputs, common_ip_outputs


def get_reputation_hr(reputations_data: List, args: dict[str, Any]) -> CommandResults | None:
    hr_outputs = []
    for reputation_data in reputations_data:
        hr: Optional[str] = reputation_data.get('HumanReadable')
        if hr:
            hr_outputs.append(hr)
    hr = "\n".join(hr_outputs)
    return hr_to_command_results('ip', args, hr)


def check_reputation(ips: str, verbose: bool) -> EnrichmentSubCommandOutput:
    """Check the reputation of an IP address.
    """
    args = {"ip": ips}
    command_name = "ip"
    raw_results: list = demisto.executeCommand(command_name, args)  # todo format of raw result upon failure etc
    outputs, common_ips = get_reputation_context_outputs(raw_results)
    merged_reputation_outputs = merge_ips_outputs(outputs)
    hr = get_reputation_hr(raw_results, args) if verbose else None
    return merged_reputation_outputs, common_ips, hr


def generate_common_ip_from_analytics_prevalence_data(ip_context: dict) -> Common.IP:
    ip_address = ip_context.get("ip_address")
    data = ip_context.get("data", {})
    dbot_score = Common.DBotScore(
        indicator=ip_address,
        indicator_type=DBotScoreType.IP,
        score=Common.DBotScore.NONE
        # integration_name='YourIntegrationName',  # Replace with the actual integration name
        # score=dbot_score_value,
        # malicious_description=malicious.get('Description') if malicious else None
    )
    return Common.IP(
        ip=ip_address,
        dbot_score=dbot_score,
        organization_prevalence=data.get('local_prevalence'),
        global_prevalence=data.get('global_prevalence')
    )


def map_analytics_prevalence_data_to_context(analytics_prevalence_data: dict) -> dict:
    """
    extracts the objects under data, keeping
    """
    return {"AnalyticsPrevalence": enrich_data_with_source(analytics_prevalence_data, 'Cortex Core - IR')}


def get_analytics_prevalence_context_outputs(prevalence_raw_results: dict) -> EnrichmentContextOutputs:
    """
    for a single end point, the reputations data is a list of objects , each is a command result, contains entry context which consists of:
    dbotscore, ip, and the brand.ip objects. I can identify the ip in question using the address if various ip are returned in one list
    """
    # print("get_analytics_prevalence_context_outputs")
    full_outputs: UnmergedIPDataDict = {}  # dict that maps the outputs for each ip address
    common_ip_outputs: EnrichmentCommonIPsDict = {}  # dict that maps the ip object generated by each brand
    entry_context: Optional[dict] = prevalence_raw_results.get(
        'EntryContext')  #todo: if no entry context, and type is 4, should we report this? only if verbose?
    if entry_context:
        analytics_prevalence_ips_data: List[dict] = entry_context.get('Core', {}).get('AnalyticsPrevalence', {}).get('Ip', [])
        for analytics_prevalence_data in analytics_prevalence_ips_data:
            address = analytics_prevalence_data.get("ip_address")
            common_ip = generate_common_ip_from_analytics_prevalence_data(analytics_prevalence_data)
            analytics_prevalence_mapped_context = map_analytics_prevalence_data_to_context(analytics_prevalence_data)
            append_to_dict_list(full_outputs, address, analytics_prevalence_mapped_context)
            append_to_dict_list(common_ip_outputs, address, common_ip)

    return full_outputs, common_ip_outputs


def get_analytics_prevalence_hr(prevalences_data: List, args: dict[str, Any]):
    hr_outputs = []
    for prevalence_data in prevalences_data:
        hr: Optional[str] = prevalence_data.get('HumanReadable')
        if hr:
            hr_outputs.append(hr)
    hr = "\n".join(hr_outputs)
    return hr_to_command_results('core-get-IP-analytics-prevalence', args, hr)


def get_analytics_prevalence(ips: str, verbose: bool) -> EnrichmentSubCommandOutput:
    """Retrieve analytics prevalence data for IP indicators."""
    # print("get_analytics_prevalence")
    args = {"ip_address": ips}
    command_name = "core-get-IP-analytics-prevalence"
    raw_results = demisto.executeCommand(command_name, args)
    # print(raw_results)
    outputs, common_ips = get_analytics_prevalence_context_outputs(raw_results)
    merged_prevalence_outputs = merge_ips_outputs(outputs)
    hr = get_analytics_prevalence_hr(raw_results, args) if verbose else None
    return merged_prevalence_outputs, common_ips, hr


######################################### general flow #######################################
def enrich_internal_ip_address(ips: list[str], verbose: bool) -> EnrichmentSubFlowOutput:
    """Handle internal IP enrichment."""
    demisto.debug(f"Internal IP detected: {ips}")
    # joined_ips = ",".join(ips)
    endpoint_data_outputs, get_endpoint_data_common_ips, endpoint_data_hr = get_endpoint_data(ips,
                                                                                              verbose)
    return endpoint_data_outputs, get_endpoint_data_common_ips, [endpoint_data_hr]


def enrich_external_ip_address(ips: list[str], verbose: bool) -> EnrichmentSubFlowOutput:
    """Handle external IP enrichment."""
    command_results: list[Optional[CommandResults]] = []
    demisto.debug(f"External IPs detected: {ips}")
    joined_ips = ",".join(ips)
    check_reputation_outputs, check_reputation_common_ips, check_reputation_hr = check_reputation(joined_ips, verbose)
    outputs = check_reputation_outputs
    common_ips = check_reputation_common_ips
    if verbose and check_reputation_hr:
        command_results.append(check_reputation_hr)
    if is_xsiam():
        if is_brand_available("Cortex Core - IR"):
            analytics_prevalence_outputs, analytics_prevalence_common_ips, analytics_prevalence_hr = get_analytics_prevalence(
                joined_ips, verbose)
            outputs = merge_ips([outputs, analytics_prevalence_outputs])
            if verbose and analytics_prevalence_hr:
                command_results.append(analytics_prevalence_hr)
        else:
            command_results.append(CommandResults(readable_output=f'Skipping get_analytics_prevalence since the brand Cortex '
                                                                  f'Core - IR is not available.'))

    return outputs, common_ips, command_results


# def ip_enrichment_hr():
#     return tableToMarkdown(
#         name="Endpoint(s) data",
#         t=endpoint_outputs_list,
#         headers=["ID", "IPAddress", "Hostname"],
#         removeNull=True,
#     )

def transform_ip_enrichment_outputs(enrichment_dict: EnrichmentFullOutputsDict) -> list[dict]:
    """
    Transforms the output of the ip_enrichment method from a dictionary to a list of dictionaries.

    :param enrichment_dict: dict
        The dictionary containing IP enrichment data in the form {id1: o1, id2: o2, ...}.

    :return: list
        A list of dictionaries in the form [{'Address': id1, 'data': o1}, {'Address': id2, 'data': o2}, ...].
    """
    return [{'Address': ip, 'data': data} for ip, data in enrichment_dict.items()]


def ip_enrichment(ips, external_enrichment, verbose) -> list[CommandResults]:
    """Perform IP enrichment with validation."""
    try:
        command_results: list[CommandResults] = []
        search_indicators_outputs, search_indicators_common_ips, search_indicators_hr = search_indicators(ips, verbose)
        if not external_enrichment and search_indicators_outputs:
            command_results.extend(common_ip_to_command_result(search_indicators_common_ips))
            command_results.append(search_indicators_hr)
            outputs = transform_ip_enrichment_outputs(search_indicators_outputs)
            if outputs:
                command_results.append(CommandResults(
                    outputs_prefix="IPEnrichment.IP",
                    outputs_key_field="IPEnrichment.IP.Address",
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        name="IP Enrichemnt(s) data",
                        t=outputs,
                        # headers=["ID", "IPAddress", "Hostname"],
                        removeNull=True,

                    ),
                ))
            return command_results
        outputs = search_indicators_outputs
        internal_ips, external_ips = separate_ips(ips)
        # print(f"Internal IPs: {internal_ips}")
        # print(f"External IPs: {external_ips}")

        enriched_ip_address_outputs: EnrichmentFullOutputsDict = {}
        enriched_ip_address_common_ips = {}
        enriched_ip_address_hr = []

        if internal_ips:
            enriched_ip_address_outputs, enriched_ip_address_common_ips, enriched_ip_address_hr = enrich_internal_ip_address(
                internal_ips,
                verbose)
            command_results.extend(common_ip_to_command_result(enriched_ip_address_common_ips))  #todo: causes to context error
            command_results.extend(enriched_ip_address_hr)
            outputs = merge_ips([outputs, enriched_ip_address_outputs])
        if external_ips:
            enriched_ip_address_outputs, enriched_ip_address_common_ips, enriched_ip_address_hr = enrich_external_ip_address(
                external_ips, verbose)
            command_results.extend(common_ip_to_command_result(enriched_ip_address_common_ips))  #todo: causes to context error
            command_results.extend(enriched_ip_address_hr)
            outputs = merge_ips([outputs, enriched_ip_address_outputs])

        outputs = transform_ip_enrichment_outputs(outputs)

        if outputs:
            command_results.append(
                CommandResults(
                    outputs_prefix="IPEnrichment.IP",
                    outputs_key_field="IPEnrichment.IP.Address",
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        name="IP Enrichemnt(s) data",
                        t=outputs,
                        # headers=["ID", "IPAddress", "Hostname"],
                        removeNull=True,
                    ),
                )
            )

        return command_results
    except Exception as e:
        demisto.error(f"Failed to enrich IP: {e}")
        raise e


def main():
    try:
        args = demisto.args()
        ips = argToList(args.get("ip", ""))
        external_enrichment = argToBoolean(args.get("external_enrichment", False))
        verbose = argToBoolean(args.get("verbose", False))

        if not ips:
            raise ValueError("No IPs provided for enrichment.")

        return_results(ip_enrichment(ips, external_enrichment, verbose))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute IPEnrichment. Error: {str(e)} {traceback.format_exc()}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
