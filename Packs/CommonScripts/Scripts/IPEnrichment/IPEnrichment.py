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


def get_tim_indicator_hr(indicator: dict) -> str:
    # return specific information for found indicators
    # todo - handle a case of an empty indicator
    fields = ['id', 'indicator_type', 'value',
              'score']  # todo: which fields to return? maybe another command should be used per Yarden

    styled_indicator = {}
    for field in fields:
        styled_indicator[field] = indicator.get(field, indicator.get("CustomFields", {}).get(field, "n/a"))
    styled_indicator["verdict"] = scoreToReputation(styled_indicator['score'])
    headers = fields + ["verdict"]
    hr = tableToMarkdown("IP Enrichment- indicator data from TIM", styled_indicator, headers)
    return hr


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

    # else:
    #     command_context_outputs.append(entry.get("EntryContext", {}))
    #     human_readable_outputs.append(entry.get("HumanReadable") or "")

    # human_readable = "\n".join(human_readable_outputs)
    # human_readable = [hr] if (hr := hr_to_command_results(command, args, human_readable)) else []
    # return command_context_outputs, human_readable, command_error_outputs


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

    def run_command(self, command: Command, args: dict[str, list[str] | str]) -> tuple[list[CommandResults],list[dict[str, dict]]]:
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
        print(f'run command {command.name} with args={args}')

        raw_outputs = run_execute_command(command, args)
        command_context_outputs, command_contents, command_human_readable_outputs, command_error_outputs = get_command_results(command, raw_outputs, args, self.verbose)
        if self.verbose:
            human_readable = "\n".join(command_human_readable_outputs)
            human_readable = [hr] if (hr := hr_to_command_results(command.name, args, human_readable)) else []
            self.commands_results_list.extend(human_readable)
            self.commands_results_list.extend(command_error_outputs)





def to_list(var):
    """
    Converts the input variable to a list if it is not already a list.
    """
    if not var:
        return []
    return [var] if not isinstance(var, list) else var


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


def enrich_internal_ip_address(ip_command_runner, ips: list[str]) -> CommandResults:
    """Handle internal IP enrichment."""
    demisto.debug(f"Internal IP detected: {ips}")
    print("INTERNAL IP")
    joined_ips = ",".join(ips)
    get_endpoint_data_command = Command(
        name="get-endpoint-data",
        output_keys=["Contents"],
        output_mapping=lambda x: x.get("Contents", [])
    )
    ip_command_runner.run_command(get_endpoint_data_command, {"agent_ip": joined_ips})


def check_reputation(ip_command_runner: IPCommandRunner, ips: str):
    """Check the reputation of an IP address."""
    print("REPUTATION")
    ip_command = Command(
        name="ip",
        output_keys=["Contents"],
        output_mapping=lambda x: x.get("Contents", [])
    )
    ip_command_runner.run_command(ip_command, {"ip": ips})


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
    ip_command_runner.run_command(prevalence_command, {"ip_address": ips})


def get_indicator_tim_data(ip_command_runner: IPCommandRunner, ips: list[str]) -> tuple[dict[str, Any], CommandResults]:
    """Retrieve TIM data for IP indicators."""
    print("TIM DATA")
    find_indicators_command = Command(
        name="findIndicators",
        output_keys=["Contents"],
        output_mapping=lambda x: x.get("Contents", []),
    )
    ips_value_query = " or ".join([f"value:{ip}" for ip in ips])
    query = f"(type:IPv6 or type:IPv6CIDR or type:IP) and ({ips_value_query})"
    ip_command_runner.run_command(find_indicators_command, {
        "query": query})  #RETURNS A LIST OF DICTIONARIES PER INDICATOR, TODO: IF MISSING? IF EMPTY EMPTY LIST IS RETUNRED. WHAT TO DO IF MULTIPLE RESULTS FOR ONE IP?


def enrich_external_ip_address(ip_command_runner, ips: list[str]) -> CommandResults:
    """Handle external IP enrichment."""
    demisto.debug(f"External IPs detected: {ips}")
    print("EXTERNAL IP")
    joined_ips = ",".join(ips)
    check_reputation(ip_command_runner, joined_ips)
    if is_xsiam():
        get_analytics_prevalence(ip_command_runner, joined_ips)


def ip_enrichment(ip_command_runner, ips: list[str], third_enrichment: bool):
    """Perform IP enrichment with validation."""
    try:
        get_indicator_tim_data(ip_command_runner, ips)
        if not third_enrichment:
            return
        internal_ips, external_ips = separate_ips(ips)
        print(f"Internal IPs: {internal_ips}")
        print(f"External IPs: {external_ips}")
        if internal_ips:
            enrich_internal_ip_address(ip_command_runner, internal_ips)
        if external_ips:
            enrich_external_ip_address(ip_command_runner, external_ips)


    except Exception as e:
        demisto.error(f"Failed to enrich IP: {e}")
        raise e


def main():
    try:
        args = demisto.args()
        ips = argToList(args.get("ip", ""))
        third_enrichment = argToBoolean(args.get("third_enrichment", False))
        verbose = argToBoolean(args.get("verbose", False))
        ip_command_runner = IPCommandRunner(verbose)

        if not ips:
            raise ValueError("No IPs provided for enrichment.")

        try:
            ip_enrichment(ip_command_runner, ips, third_enrichment)

        except Exception as e:
            print(f"Failed to enrich IP: {e}")
            #ips_not_found_list.append({"ip": ip, "error": str(e)})

        return_results(ip_command_runner.commands_results_list)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute IPEnrichment. Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
