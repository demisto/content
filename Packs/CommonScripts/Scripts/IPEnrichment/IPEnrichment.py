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
        brand: Optional[str],
        name: str,
        output_keys: List[str],
        args_mapping: dict,
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
        self.brand = brand
        self.name = name
        self.output_keys = output_keys
        self.args_mapping = args_mapping
        self.output_mapping = output_mapping
        self.post_processing = post_processing

    def __repr__(self):
        return f'{{ name: {self.name}, brand: {self.brand} }}'


class ModuleManager:
    def __init__(self, modules: dict[str, Any]) -> None:
        """Initialize ModuleManager."""
        self.modules = modules
        self.enabled_brands = {
            module.get("brand")
            for module in self.modules.values()
            if module.get("state") == "active"
        }

    def is_brand_available(self, brand: str) -> bool:
        """Check if a brand is active and available."""
        return (brand in self.enabled_brands) or (brand is None)


def prepare_args(command: Command, args: dict[str, Any]) -> dict[str, Any]:
    """
    Prepares the arguments dictionary for the command.
    If the argument value is an empty string or None, the resulting dictionary will not include
    the argument.

    Args:
        command (Command): The command to prepare for.
        args (dict[str, Any]): The arguments received by this command.
    Returns:
        dict[str, Any]: The arguments dictionary that's right for the command.
    """
    command_args = {}
    for command_arg_key, arg_key in command.args_mapping.items():
        if command_arg_value := args.get(arg_key):
            command_args[command_arg_key] = command_arg_value

    return command_args


class IPCommandRunner:
    def __init__(self, module_manager: ModuleManager, verbose: bool) -> None:
        """
        Initializes the instance of EndpointCommandRunner.

        Args:
            module_manager (ModuleManager): An instance of ModuleManager used to manage the modules.

        Attributes:
            module_manager (ModuleManager): Stores the provided ModuleManager instance.
        """
        self.module_manager = module_manager
        self.ip_outputs_list: list[dict[str, Any]] = []
        self.command_results_list: list[CommandResults] = []
        self.ips_not_found_list: list[dict] = []
        self.verbose = verbose

    def run_command(self, command: Command, endpoint_args: dict[str, list[str] | str]) -> tuple[
        list[CommandResults],
        list[dict[str, dict]]
    ]:
        """
            Runs the given command with the provided arguments and returns the results.
            Args:
                command (Command): An instance of the Command class containing the command details.
                endpoint_args (dict[str, list[str] | str]): A dictionary containing the arguments for the endpoint script.

            Returns:
                tuple[list[CommandResults], list[dict[str, dict]]]:
                    - A list of CommandResults objects, which contain the results of the command execution.
                    - A list of dictionaries, where each dictionary represents an endpoint and contains the raw output.
            """
        args = prepare_args(command, endpoint_args)
        demisto.debug(f'run command {command.name} with args={args}')
        print(f'run command {command.name} with args={args}')

        if not self.is_command_runnable(command, args):
            return [], []

        raw_outputs = self.run_execute_command(command, args)
        print(f"raw_outputs {raw_outputs}")
        self.get_command_results(command, raw_outputs, args)

        # if not entry_context:
        #     return readable_errors, []
        #
        # endpoints = entry_context_to_endpoints(command, entry_context)
        # if command.post_processing:
        #     demisto.debug(f'command with post processing: {command.name}')
        #     endpoints = command.post_processing(endpoints, endpoint_args)
        #
        # return human_readable, endpoints

    def is_command_runnable(self, command: Command, args: dict[str, Any]) -> bool:
        """
        Checks if the given command is runnable.
        This function performs the following checks:
        1. Checks if the integration required for the command is installed and active using the
            module_manager.is_brand_available() method.
        2. Checks if the command has argument mapping and if the provided arguments match the command's expected arguments.

        Args:
            command (Command): An instance of the Command class containing the command details.
            args (dict[str, Any]): A dictionary containing the arguments for the command.

        Returns:
            bool: True if the command is runnable, False otherwise.
        """
        # checks if the integration required for the command is installed and active
        if not self.module_manager.is_brand_available(command.brand):
            demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
            print(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
            return False

        # checks if the command has argument mapping
        if command.args_mapping and not args.values():
            demisto.debug(f'Skipping command "{command.name}" since the provided arguments does not match the command.')
            print(f'Skipping command "{command.name}" since the provided arguments does not match the command.')
            return False

        return True

    @staticmethod
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

    @staticmethod
    def get_command_results(command: Command, results: list[dict[str, Any]], args: dict[str, Any]) -> tuple[list, list, list]:
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

        command_context_outputs = []
        human_readable_outputs = []
        command_error_outputs = []
        demisto.debug(f'get_commands_outputs for command "{command}" with {len(results)} entry results')
        for entry in results:
            print(f"ENTRY {entry}")
            if is_error(entry):
                print("ERROR")
            #     command_error_outputs.append(hr_to_command_results(command, args, get_error(entry), is_error=True))
            contents = entry.get("Contents")
            print(f"CONTENT {contents}")
            if isinstance(contents, list):
                for content in contents:
                    print(f"CONTENT {content}")
                    # command_context_outputs.append(content)
                    # human_readable_outputs.append(content.get("HumanReadable") or "")

            # else:
            #     command_context_outputs.append(entry.get("EntryContext", {}))
            #     human_readable_outputs.append(entry.get("HumanReadable") or "")

        # human_readable = "\n".join(human_readable_outputs)
        # human_readable = [hr] if (hr := hr_to_command_results(command, args, human_readable)) else []
        # return command_context_outputs, human_readable, command_error_outputs


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
    endpoint_data = demisto.executeCommand("get-endpoint-data", {"ip": ips})[0]["Contents"]
    readable_output = tableToMarkdown("Internal IP Data", endpoint_data)
    return CommandResults(
        outputs=endpoint_data,
        outputs_prefix="IPEnrichment.Internal",
        readable_output=readable_output
    )


def check_reputation(ip_command_runner: IPCommandRunner, ips: str):
    """Check the reputation of an IP address."""
    print("REPUTATION")
    ip_command = Command(
        brand=None,
        name="ip",
        output_keys=["Contents"],
        args_mapping={"ip": "ip"},
        output_mapping=lambda x: x.get("Contents", [])
    )
    ip_command_runner.run_command(ip_command, {"ip": ips})


def get_analytics_prevalence(ip_command_runner: IPCommandRunner, ips: str) -> dict:
    """Retrieve analytics prevalence data for IP indicators."""
    print("ANALYTICS PREVALENCE")
    prevalence_command = Command(
        brand="Cortex Core - IR",
        name="core-get-IP-analytics-prevalence",
        output_keys=["Contents"],
        args_mapping={"ip_address": "ip"},
        output_mapping=lambda x: x.get("Contents", [])
    )
    ip_command_runner.run_command(prevalence_command, {"ip": ips})


def get_indicator_tim_data(ip_command_runner: IPCommandRunner, ips: list[str]) -> tuple[dict[str, Any], CommandResults]:
    """Retrieve TIM data for IP indicators."""
    print("TIM DATA")
    find_indicators_command = Command(
        brand=None,
        name="findIndicators",
        output_keys=["Contents"],
        args_mapping={"query": "query"},
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
        get_analytics_prevalence(ip_command_runner,joined_ips)


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
        module_manager = ModuleManager(demisto.getModules())
        ip_command_runner = IPCommandRunner(module_manager, verbose)

        if not ips:
            raise ValueError("No IPs provided for enrichment.")

        try:
            ip_enrichment(ip_command_runner, ips, third_enrichment)

        except Exception as e:
            print(f"Failed to enrich IP: {e}")
            #ips_not_found_list.append({"ip": ip, "error": str(e)})

        return_results(ip_command_runner.command_results_list)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute IPEnrichment. Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
