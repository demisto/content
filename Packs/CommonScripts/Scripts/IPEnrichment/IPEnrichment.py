import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket
from ipaddress import ip_network, ip_address
import traceback
import re
from collections.abc import Callable

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


class Command:
    def __init__(
        self,
        name: str,
        output_keys: List[str],
        output_mapping: dict | Callable,
        post_processing: Callable = None,
    ):
        """
        Initialize a MappedCommand object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            args_mapping (dict): A dictionary containing the command arguments
        """
        self.name = name
        self.output_keys = output_keys
        self.output_mapping = output_mapping
        self.post_processing = post_processing

    def __repr__(self):
        return f'{{ name: {self.name} }}'


def hr_to_command_results(command_name: str, args: dict[str, Any], human_readable: str, is_error: bool = False
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
    result = None
    if human_readable:
        command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        result_type = EntryType.ERROR if is_error else None
        result_message = f"#### {'Error' if is_error else 'Result'} for {command}\n{human_readable}"
        result = CommandResults(readable_output=result_message, entry_type=result_type, mark_as_note=True)
    return result


def run_execute_command(command: Command, args: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Executes a command if the brand is available and returns the results.

    Args:
        command (Command): An instance of MappedCommand that contains the command information.
        args (Dict[str, Any]): A dictionary containing the specific arguments for the command.
    Returns:
        Dict[str, Any]: A dictionary containing the command and its results.
    """

    return demisto.executeCommand(command.name, args)


def get_command_results(command: Command, results: list[dict[str, Any]], args: dict[str, Any], verbose) -> tuple[
    list, list, list, list]:
    """
    Processes the results of a previously executed command and extracts relevant outputs.

    Args:
        command (Command): An instance of MappedCommand that contains the command information.
        results (Dict[str, Any]): A dictionary containing the command results.
        args (Dict[str, Any]): A dictionary containing the specific arguments for the command.

    Returns:
        Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]]]:
            A tuple containing:
            - A list of command context outputs.
            - A human-readable string of the results.
            - A list of command error outputs.
    """

    command_error_outputs = []
    command_context_outputs = []
    command_contents = []
    command_human_readable_outputs = []
    demisto.debug(f'get_commands_outputs for command "{command}" with {len(results)} entry results')
    for entry in results:
        if is_error(entry):
            print("ERROR")
            command_error_outputs.append(hr_to_command_results(command.name, args, get_error(entry), is_error=True))
        if entry.get("EntryContext"):
            command_context_outputs.append(entry.get("EntryContext", {}))
        else:
            contents = entry.get("Contents")
            if isinstance(contents, list):
                command_contents.extend(contents)
            else:
                command_contents.append(contents)

        if verbose:
            command_human_readable_outputs.append(entry.get("HumanReadable") or "")
    return command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs


class IPCommandRunner:
    def __init__(self, verbose: bool) -> None:
        """
        Initializes the instance of EndpointCommandRunner.

        Args:
            module_manager (ModuleManager): An instance of ModuleManager used to manage the modules.

        Attributes:
            module_manager (ModuleManager): Stores the provided ModuleManager instance.
        """

        self.enabled_brands = {
            module.get("brand")
            for module in demisto.getModules().values()
            if module.get("state") == "active"
        }
        self.commands_context_outputs: list[dict[str, Any]] = []
        self.commands_results_list: list[CommandResults] = []
        self.ips_not_found_list: list[dict] = []
        self.verbose = verbose

    def is_brand_available(self, brand: str) -> bool:
        """Check if a brand is active and available."""
        return brand in self.enabled_brands

    def run_command(self, command: Command, args: dict[str, list[str] | str]):
        """
            Runs the given command with the provided arguments and returns the results.
            Args:
                command (Command): An instance of the Command class containing the command details.
                args (dict[str, list[str] | str]): A dictionary containing the arguments for the endpoint script.

            Returns:
                tuple[list[CommandResults], list[dict[str, dict]]]:
                    - A list of CommandResults objects, which contain the results of the command execution.
                    - A list of dictionaries, where each dictionary represents an endpoint and contains the raw output.
            """
        demisto.debug(f'run command {command.name} with args={args}')

        raw_outputs = run_execute_command(command, args)
        command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs = get_command_results(
            command, raw_outputs, args, self.verbose)
        if self.verbose:
            human_readable = "\n".join(command_human_readable_outputs)
            human_readable = [hr] if (hr := hr_to_command_results(command.name, args, human_readable)) else []
            self.commands_results_list.extend(human_readable)
            self.commands_results_list.extend(command_error_outputs)

        return command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs


def to_list(var):
    """
    Converts the input variable to a list if it is not already a list.
    """
    if not var:
        return []
    return [var] if not isinstance(var, list) else var


######################## OUTPUT PROCESSING FUNCTIONS ########################

def get_output_key(output_key: str, raw_context: dict[str, Any]) -> str:
    """
    Retrieves the full output key from the raw context based on the given output key.

    This function searches for the output key in the raw context. If an exact match is not found,
    it looks for keys that start with the given output key followed by parentheses.

    Args:
        output_key (str): The base output key to search for.
        raw_context (dict[str, Any]): The raw context dictionary to search in.

    Returns:
        str: The full output key if found, otherwise an empty string.

    Note:
        If the full output key is not found, a debug message is logged.
    """

    full_output_key = ""
    if raw_context:
        if output_key in raw_context:
            full_output_key = output_key
        else:
            for key in raw_context:
                if not key:
                    continue
                if key.startswith(f"{output_key}("):
                    full_output_key = key
                    break
        if not full_output_key:
            demisto.debug(
                f"Output key {output_key} not found in entry context keys: {list(raw_context.keys())}"
            )
    return full_output_key


def get_outputs(output_key: str, raw_context: dict[str, Any]) -> dict[str, Any]:
    """
    Extracts and processes the outputs from the raw context based on the given output key.

    This function retrieves the context from the raw_context using the output_key.
    If the context is a list, it takes the first element (if available).

    Args:
        output_key (str): The key to look up in the raw_context.
        raw_context (dict[str, Any]): The raw context containing the outputs.

    Returns:
        dict[str, Any]: The processed context, or an empty dictionary if not found.
    """
    full_output_key = get_output_key(output_key, raw_context)
    if not (raw_context and full_output_key):
        return {}
    context = raw_context.get(full_output_key, {})
    return context


def enrich_data_with_source(data: dict, source: str):
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


def merge_ips(ips: list[dict[str, str]]) -> dict[str, Any]:
    """
    Merge multiple ip dictionaries into a single ip.

    This function merges a list of ip dictionaries into a single ip dictionary.
    It handles nested dictionaries and special cases where a value is a dictionary with 'Value' and 'Source' keys.
    The merged ip is then converted to a Common.IP object and its context is returned.

    Args:
        ips (list[dict[str, str]]): A list of ip dictionaries to merge.

    Returns:
        dict[str, Any]: A merged ip dictionary in the Common.IP context format.
                        Returns an empty dictionary if the input list is empty.
    """

    def recursive_merge(target: dict, source: dict):
        for key, value in source.items():
            # Check if the value is a dictionary and has specific keys 'Value' and 'Source'
            if isinstance(value, dict) and "Value" in value and "Source" in value:
                if key not in target:
                    target[key] = []
                target[key].append(value)
            elif isinstance(value, dict):
                if key not in target:
                    target[key] = {}
                recursive_merge(target[key], value)
            else:
                target[key] = value

    merged_ip: dict[str, Any] = {}
    for ip in ips:
        recursive_merge(merged_ip, ip)

    return (
        Common.IP(**merged_ip).to_context()[Common.IP.CONTEXT_PATH]
        if merged_ip
        else {}
    )


######### IP ENRICHMENT HELPER FUNCTIONS #########

def get_private_ips() -> list[str]:
    """Retrieve the list of private IP subnets."""
    #todo: error handeling
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
    geo_latitude ,  geo_longitude = geolocation if len(geolocation) == 2 else (None, None)
    return Common.IP(
        dbot_score=Common.DBotScore(indicator=ip_address, indicator_type=DBotScoreType.IP, score=score),
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
        geo_longitude=geo_longitude,  #todo confirm order
        organization_name=custom_fields.get("organization"),
        organization_type=custom_fields.get("organizationtype"),
        positive_engines=custom_fields.get("positivedetections"),
        detection_engines=custom_fields.get("detectionengines"),
        hostname=custom_fields.get("hostname"),
        tags=custom_fields.get("tags"),
        #todo - which dbot score should I put?
    )


def map_search_indicator_to_context(ip_indicator):
    print("map_search_indicator_to_context")
    #todo: which fields should be excluded? what about module to feed map? insightcache?
    filtered_ip_indicator = {key: value for key, value in ip_indicator.items() if key not in ["CustomFields", "insightCache"]}
    return enrich_data_with_source(data=filtered_ip_indicator, source="searchIndicators")


def get_search_indicators_outputs(iocs: list[dict]) -> List[dict]:
    print("get_search_indicators_outputs")
    outputs = []
    for ip_indicator in iocs:
        #todo - which fields should be excluded?
        common_ip = generate_common_ip_from_ip_indicator(ip_address=ip_indicator.get('value'),
                                                         ip_type=ip_indicator.get('indicator_type'),
                                                         score=ip_indicator.get('score'),
                                                         custom_fields=ip_indicator.get('CustomFields', {}))
        ip_indicator_mapped_context = map_search_indicator_to_context(ip_indicator)
        print(ip_indicator_mapped_context)
        common_ip_mapped_context = common_ip.to_context()
        print(common_ip_mapped_context)
        common_keys = set(ip_indicator_mapped_context.keys()) & set(common_ip_mapped_context.keys())

        if common_keys:
            raise DemistoException(f"get_search_indicators_outputs - Common keys found: {common_keys}")

        outputs.append(common_ip_mapped_context | ip_indicator_mapped_context)
    return outputs


def search_indicators(ips: list[str]):
    """Retrieve TIM data for IP indicators."""
    print("search_indicators")

    ips_value_query = " or ".join([f"value:{ip}" for ip in ips])
    query = f"(type:IPv6 or type:IPv6CIDR or type:IP) and ({ips_value_query})"
    raw_results = demisto.searchIndicators(query=query)
    #todo: wrap in command_results
    outputs = get_search_indicators_outputs(raw_results.get('iocs', []))
    print(outputs)
    return raw_results, outputs

    # command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs = ip_command_runner.run_command(find_indicators_command, {
    #     "query": query})  #RETURNS A LIST OF DICTIONARIES PER INDICATOR, TODO: IF MISSING? IF EMPTY EMPTY LIST IS RETUNRED. WHAT TO DO IF MULTIPLE RESULTS FOR ONE IP?
    # demisto.debug(f"IPEnrichment: searchIndicators {command_contents=}")
    # # raw_content = command_contents[0] if isinstance(command_contents, list) else {}
    # for content in command_contents:
    #     scores = content.get("insightCache", {}).get("scores", {})
    #     ips_context = []
    #     dbot_scores_context = []
    #     integration_ips_context = []
    #     for score_source, score_value in scores.items():
    #         context = score_value.get("context", {})
    #         for key, value in context.items():
    #             if key == "IP(val.Address && val.Address == obj.Address)":
    #                 enrich_data_with_source(value[0], score_source)
    #                 ips_context.append(value)
    #                 continue
    #             if key == "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)":
    #                 enrich_data_with_source(value[0], score_source)
    #                 dbot_scores_context.append(value)
    #                 continue
    #             else:
    #                 #parse the integration name from this format: 'Whois.IP(val.query && val.query == obj.query)'
    #                 integration_prefix = key.split(".")[0]
    #                 enrich_data_with_source(value, integration_prefix)
    #                 integration_ips_context.append(value)
    #
    #     # # merge the context of the same type
    #     # ips_context = merge_ips(ips_context)

    #
    #
    # enriched_data = enrich_data_with_source(raw_content, "TIM")
    #
    # demisto.debug(f"IPEnrichment: searchIndicators {enriched_data=}")

    # tim_indicators = demisto.searchIndicators(query)


######################################## internal flow #######################################

def get_endpoint_data_outputs(endpoints_data) -> List[dict]:
    pass
    # print("get_endpoint_data_outputs")
    # outputs = []
    # for endpoint_data in endpoints_data:
    #     # todo - which fields should be excluded?
    #     common_ip = generate_common_ip_from_ip_indicator(ip_address=ip_indicator.get('value'),
    #                                                      ip_type=ip_indicator.get('indicator_type'),
    #                                                      score=ip_indicator.get('score'),
    #                                                      custom_fields=ip_indicator.get('CustomFields', {}))
    #     ip_indicator_mapped_context = map_search_indicator_to_context(ip_indicator)
    #     print(ip_indicator_mapped_context)
    #     common_ip_mapped_context = common_ip.to_context()
    #     print(common_ip_mapped_context)
    #     common_keys = set(ip_indicator_mapped_context.keys()) & set(common_ip_mapped_context.keys())
    #
    #     if common_keys:
    #         raise DemistoException(f"get_search_indicators_outputs - Common keys found: {common_keys}")
    #
    #     outputs.append(common_ip_mapped_context | ip_indicator_mapped_context)
    # return outputs


def get_endpoint_data(ips):
    raw_results = demisto.executeCommand("get-endpoint-data", {"agent_ip": ips, "verbose" : "true"})
    print(raw_results)
    outputs = get_endpoint_data_outputs(raw_results.get('Contents', []))
    return raw_results , outputs
######################################## external flow #######################################
def check_reputation(ip_command_runner: IPCommandRunner, ips: str):
    """Check the reputation of an IP address."""
    print("REPUTATION")
    ip_command = Command(
        name="ip",
        output_keys=["Contents"],
        output_mapping=lambda x: x.get("Contents", [])
    )
    command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs = ip_command_runner.run_command(
        ip_command, {"ip": ips})
    command_context_outputs = command_context_outputs[0] if isinstance(command_context_outputs, list) else command_context_outputs
    enriched_data = enrich_data_with_source(command_context_outputs, "Reputation")


def get_analytics_prevalence(ip_command_runner: IPCommandRunner, ips: str) -> dict:
    """Retrieve analytics prevalence data for IP indicators."""
    print("ANALYTICS PREVALENCE")
    if not ip_command_runner.is_brand_available("Cortex Core - IR"):
        demisto.debug(f'Skipping get_analytics_prevalence since the brand Cortex Core - IR is not available.')
        print(f'Skipping get_analytics_prevalence since the brand Cortex Core - IR is not available.')
    prevalence_command = Command(
        name="core-get-IP-analytics-prevalence",
        output_keys=["Contents"],
        output_mapping=lambda x: x.get("Contents", [])
    )
    command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs = ip_command_runner.run_command(
        prevalence_command, {"ip_address": ips})


######################################### general flow #######################################
def enrich_internal_ip_address(ips: list[str]):
    """Handle internal IP enrichment."""
    outputs = []
    demisto.debug(f"Internal IP detected: {ips}")
    joined_ips = ",".join(ips)
    get_endpoint_data_raw_results, get_endpoint_data_outputs = get_endpoint_data(joined_ips)


    # get_endpoint_data_command = Command(
    #     name="get-endpoint-data",
    #     output_keys=["Contents"],
    #     output_mapping=lambda x: x.get("Contents", [])
    # )
    # command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs = ip_command_runner.run_command(
    #     get_endpoint_data_command, {"agent_ip": joined_ips})
    # get_outputs("Core.AnalyticsPrevalence.Ip", command_context_outputs[0])
    return raw_results, outputs


def enrich_external_ip_address(ips: list[str]):
    """Handle external IP enrichment."""
    pass
    # raw_results, outputs = [], []
    # demisto.debug(f"External IPs detected: {ips}")
    # print("EXTERNAL IP")
    # joined_ips = ",".join(ips)
    # check_reputation(ip_command_runner, joined_ips)
    # if is_xsiam():
    #     get_analytics_prevalence(ip_command_runner, joined_ips)
    # return raw_results, outputs


def gather_enrichment_data(ips: list[str], external_enrichment: bool, verbose: bool):
    print("gather_enrichment_data")
    search_indicators_raw_results, search_indicators_outputs = search_indicators(ips)
    if not external_enrichment and search_indicators_outputs:
        return
    internal_ips, external_ips = separate_ips(ips)
    print(f"Internal IPs: {internal_ips}")
    print(f"External IPs: {external_ips}")
    if internal_ips:
        enrich_internal_ip_address(internal_ips)
    if external_ips:
        enrich_external_ip_address(external_ips)


def merge_enrichment_data():
    pass


def ip_enrichment(ips, external_enrichment, verbose):
    """Perform IP enrichment with validation."""
    try:
        gather_enrichment_data(ips, external_enrichment, verbose)
        merge_enrichment_data()



    except Exception as e:
        demisto.error(f"Failed to enrich IP: {e}")
        raise e


def main():
    try:
        args = demisto.args()
        ips = argToList(args.get("ip", ""))
        external_enrichment = argToBoolean(args.get("external_enrichment", False))
        verbose = argToBoolean(args.get("verbose", False))
        # ip_command_runner = IPCommandRunner(verbose)

        if not ips:
            raise ValueError("No IPs provided for enrichment.")

        try:
            ip_enrichment(ips, external_enrichment, verbose)

        except Exception as e:
            print(f"Failed to enrich IP: {e}")
            #ips_not_found_list.append({"ip": ip, "error": str(e)})

        # return_results(ip_command_runner.commands_results_list)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute IPEnrichment. Error: {str(e)} {traceback.format_exc()}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
