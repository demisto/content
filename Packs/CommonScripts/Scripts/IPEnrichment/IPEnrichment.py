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
EnrichmentCommonIPsDict = dict[str, list[dict]]
EnrichmentContextOutputs = tuple[UnmergedIPDataDict, EnrichmentCommonIPsDict]
EnrichmentSubCommandOutput = Tuple[
    EnrichmentRawResults, EnrichmentFullOutputsDict, EnrichmentCommonIPsDict]

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


def merge_ips(ips: list[dict[str, dict]]) -> dict[str, dict]:
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
    print("map_search_indicator_to_context")
    # todo: which fields should be excluded? what about module to feed map? insightcache?
    filtered_ip_indicator = {key: value for key, value in ip_indicator.items() if key not in ["CustomFields", "insightCache"]}
    return enrich_data_with_source(data=filtered_ip_indicator, source="searchIndicators")


def get_search_indicators_context_outputs(iocs: list[dict]) -> EnrichmentContextOutputs:
    """
    todo: describe the ioc stricture
    """
    print("get_search_indicators_context_outputs")
    full_outputs: UnmergedIPDataDict = {}
    common_ip_outputs: EnrichmentCommonIPsDict = {}
    for ip_indicator in iocs:
        # todo - which fields should be excluded?
        ip_address = ip_indicator.get('value')
        common_ip = generate_common_ip_from_ip_indicator(ip_address=ip_address,
                                                         ip_type=ip_indicator.get('indicator_type'),
                                                         score=ip_indicator.get('score'),
                                                         custom_fields=ip_indicator.get('CustomFields', {}))
        append_to_dict_list(common_ip_outputs, ip_address, common_ip.to_context())
        ip_indicator_mapped_context = map_search_indicator_to_context(ip_indicator)
        print(ip_indicator_mapped_context)
        append_to_dict_list(full_outputs, ip_address, ip_indicator_mapped_context)

    return full_outputs, common_ip_outputs


def search_indicators(ips: list[str]) -> EnrichmentSubCommandOutput:
    """Retrieve TIM data for IP indicators."""
    print("search_indicators")
    ips_value_query = " or ".join([f"value:{ip}" for ip in ips])
    query = f"(type:IPv6 or type:IPv6CIDR or type:IP) and ({ips_value_query})"
    # todo: describe the raw results structure
    raw_results: dict = demisto.searchIndicators(query=query)  # todo: reffer to batch search
    iocs: list[dict] = raw_results.get('iocs', [])
    # todo: wrap in command_results
    outputs, common_ips = get_search_indicators_context_outputs(iocs)
    merged_search_indicators_outputs = merge_ips_outputs(outputs)
    return iocs, merged_search_indicators_outputs, common_ips


######################################## internal flow #######################################

def generate_common_ip_from_endpoint_data():
    return {}


def map_endpoint_data_to_context(endpoint_data):
    return endpoint_data


def get_endpoint_data_outputs(endpoints_data: List) -> EnrichmentContextOutputs:
    print("get_endpoint_data_outputs")
    # todo: transform to dicts grouping by the IPAddress
    full_outputs = {}
    common_ip_outputs = {}
    for endpoint_data in endpoints_data:  # todo: do all the endpoints returned in a list in the entry context?
        common_ip = generate_common_ip_from_endpoint_data()
        endpoint_data_mapped_context = map_endpoint_data_to_context(endpoint_data)
        print(endpoint_data_mapped_context)
        common_ip_mapped_context = {}  # common_ip.to_context()
        # print(common_ip_mapped_context)
        outputs.append(endpoint_data_mapped_context)
        common_ips.append(common_ip_mapped_context)
    return outputs, common_ips


def get_endpoint_data(ips: str, verbose: bool) -> EnrichmentSubCommandOutput:
    # running with 192.168.1.143
    # todo: check what happens when verbose is false
    raw_results = demisto.executeCommand("get-endpoint-data", {"agent_ip": ips, "verbose": str(verbose)})
    # todo: how is data returned for a list?
    outputs, common_ips = get_endpoint_data_outputs(raw_results.get('EntryContext', {}).get('Endpoint(val.Hostname.Value && '
                                                                                            'val.Hostname.Value == obj.Hostname.Value)',
                                                                                            []))  # todo: can I access the key in this way? does it return a list for all the ips under the list of entry contetx?
    return raw_results, outputs, common_ips


######################################## external flow #######################################
def generate_common_ip_from_reputations_data(dict):
    pass


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
    print("get_reputation_context_outputs")
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
            common_ip = entry_context.get("IP(val.Address && val.Address == obj.Address)", {})
            address = common_ip.get("Address")
            reputation_data_mapped_context = map_reputation_data_to_context(
                {key: value for key, value in entry_context.items() if key not in excluded_keys})
            append_to_dict_list(full_outputs, address, reputation_data_mapped_context)
            append_to_dict_list(common_ip_outputs, address, common_ip)
            # todo - dbot score handle
            print(reputation_data_mapped_context)
            print(common_ip)
    return full_outputs, common_ip_outputs


def check_reputation(ips: str) -> EnrichmentSubCommandOutput:
    """Check the reputation of an IP address.
    """
    print("REPUTATION")
    raw_results: list = demisto.executeCommand("ip", {"ip": ips})  # todo format of raw result upon failure etc
    print(raw_results)
    outputs, common_ips = get_reputation_context_outputs(raw_results)
    merged_reputation_outputs = merge_ips_outputs(outputs)
    return raw_results, merged_reputation_outputs, common_ips


def get_analytics_prevalence_context_outputs(prevalences_data: List) -> EnrichmentContextOutputs:
    """
    for a single end point, the reputations data is a list of objects , each is a command result, contains entry context which consists of:
    dbotscore, ip, and the brand.ip objects. I can identify the ip in question using the address if various ip are returned in one list
    """
    print("get_analytics_prevalence_context_outputs")
    # excluded_keys = {
    #     "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)",
    #     "IP(val.Address && val.Address == obj.Address)"
    # }
    full_outputs: UnmergedIPDataDict = {}  # dict that maps the outputs for each ip address
    common_ip_outputs: EnrichmentCommonIPsDict = {}  # dict that maps the ip object generated by each brand
    # for prevalence_data in prevalences_data:
    #     entry_context: Optional[dict] = prevalence_data.get(
    #         'EntryContext')  #todo: if no entry context, and type is 4, should we report this? only if verbose?
    #     if entry_context:
    #         common_ip = entry_context.get("IP(val.Address && val.Address == obj.Address)", {})
    #         address = common_ip.get("Address")
    #         reputation_data_mapped_context = map_reputation_data_to_context(
    #             {key: value for key, value in entry_context.items() if key not in excluded_keys})
    #         append_to_dict_list(full_outputs, address, reputation_data_mapped_context)
    #         append_to_dict_list(common_ip_outputs, address, common_ip)
    #         #todo - dbot score handle
    #         print(reputation_data_mapped_context)
    #         print(common_ip)
    return full_outputs, common_ip_outputs


def get_analytics_prevalence(ips: str) -> EnrichmentSubCommandOutput:
    """Retrieve analytics prevalence data for IP indicators."""
    print("ANALYTICS PREVALENCE")
    raw_results = demisto.executeCommand("core-get-IP-analytics-prevalence", {"ip_address": ips})
    print(raw_results)
    outputs, common_ips = get_analytics_prevalence_context_outputs(raw_results)
    merged_prevalence_outputs = merge_ips_outputs(outputs)
    return raw_results, merged_prevalence_outputs, common_ips


######################################### general flow #######################################
def enrich_internal_ip_address(ips: list[str], verbose: bool) -> EnrichmentSubCommandOutput:
    """Handle internal IP enrichment."""
    demisto.debug(f"Internal IP detected: {ips}")
    joined_ips = ",".join(ips)
    get_endpoint_data_raw_results, get_endpoint_data_outputs, get_endpoint_data_common_ips = get_endpoint_data(joined_ips,
                                                                                                               verbose)
    return get_endpoint_data_raw_results, get_endpoint_data_outputs, get_endpoint_data_common_ips


def enrich_external_ip_address(ips: list[str]) -> EnrichmentSubCommandOutput:
    """Handle external IP enrichment."""
    raw_results: EnrichmentRawResults = []
    outputs, common_ips = {}, {}
    demisto.debug(f"External IPs detected: {ips}")
    joined_ips = ",".join(ips)
    check_reputation_raw_results, check_reputation_outputs, check_reputation_common_ips = check_reputation(joined_ips)
    raw_results.extend(check_reputation_raw_results)
    outputs = check_reputation_outputs
    common_ips = check_reputation_common_ips
    if is_xsiam():
        if is_brand_available("Cortex Core - IR"):
            get_analytics_prevalence_raw_results, get_analytics_prevalence_outputs, get_analytics_prevalence_common_ips = get_analytics_prevalence(
                joined_ips)
        else:
            demisto.debug(f'Skipping get_analytics_prevalence since the brand Cortex Core - IR is not available.')
            print(f'Skipping get_analytics_prevalence since the brand Cortex Core - IR is not available.')

    return raw_results, outputs, common_ips


def ip_enrichment(ips, external_enrichment, verbose):
    """Perform IP enrichment with validation."""
    try:
        print("gather_enrichment_data")
        search_indicators_raw_results, search_indicators_outputs, search_indicators_common_ips = search_indicators(ips)
        print(search_indicators_outputs)
        if not external_enrichment and search_indicators_outputs:
            return
        internal_ips, external_ips = separate_ips(ips)
        print(f"Internal IPs: {internal_ips}")
        print(f"External IPs: {external_ips}")
        if internal_ips:
            enriched_internal_ip_address_raw_results, enriched_internal_ip_address_outputs, enriched_internal_ip_address_common_ips = enrich_internal_ip_address(
                internal_ips,
                verbose)
        if external_ips:
            enriched_external_ip_address_raw_results, enriched_external_ip_address_outputs, enriched_external_ip_address_common_ips = enrich_external_ip_address(
                external_ips)

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

        try:
            ip_enrichment(ips, external_enrichment, verbose)

        except Exception as e:
            print(f"Failed to enrich IP: {e}")
            # ips_not_found_list.append({"ip": ip, "error": str(e)})

        # return_results(ip_command_runner.commands_results_list)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute IPEnrichment. Error: {str(e)} {traceback.format_exc()}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
