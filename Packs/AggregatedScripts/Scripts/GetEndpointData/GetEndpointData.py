from collections.abc import Callable
from itertools import zip_longest
from typing import Any
from enum import StrEnum
from copy import deepcopy


from CommonServerPython import *


COMMAND_SUCCESS_MSG = "Command successful"
COMMAND_FAILED_MSG = "Command failed - no endpoint found"
IRRISKLEVEL = {"LOW": 0, "MED": 1, "HIGH": 2, 0: "LOW", 1: "MED", 2: "HIGH"}


class Brands(StrEnum):
    """
    Enum representing different integration brands.
    """

    ACTIVE_DIRECTORY_QUERY_V2 = "Active Directory Query v2"
    MCAFEE_EPO_V2 = "McAfee ePO v2"
    CROWDSTRIKE_FALCON = "CrowdstrikeFalcon"
    CORTEX_XDR_IR = "Cortex XDR - IR"
    CORTEX_CORE_IR = "Cortex Core - IR"
    FIREEYE_HX_V2 = "FireEyeHX v2"
    GENERIC_COMMAND = "Generic Command"

    @classmethod
    def get_all_values(cls) -> list[str]:
        """
        Returns a list of all string values defined in the Enum.
        """
        return [member.value for member in cls]


class Command:
    def __init__(
        self,
        brand: str,
        name: str,
        output_keys: list[str],
        args_mapping: dict[str, Any],
        output_mapping: dict,
        get_endpoint_output: bool = False,
        not_found_checker: str = "No entries.",
        additional_args: dict = None,
        prepare_args_mapping: Callable[[dict[str, str]], dict[str, str]] | None = None,
        post_processing: Callable[[Any, list[dict[str, Any]], dict[str, str]], list[dict[str, Any]]] | None = None,
    ):
        """
        Initialize a MappedCommand object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            output_keys (List[str]): List of keys to extract from command output.
            args_mapping (dict): A dictionary containing the command arguments
            output_mapping (dict): A mapping of command output keys to endpoint keys.
            get_endpoint_output (bool, optional): Flag to indicate if the command retrieves endpoint output. Defaults to False.
            not_found_checker (str, optional): A string to check if no entries are found. Defaults to "No entries.".
            additional_args (dict, optional): Additional arguments to add for the command, arguments with hard-coded values.
            prepare_args_mapping (Callable[[dict[str, str]], dict[str, str]], optional):
                A function to prepare arguments mapping. Defaults to None.
            post_processing (Callable, optional): A function for post-processing command results. Defaults to None.
        """
        self.brand = brand
        self.name = name
        self.output_keys = output_keys
        self.args_mapping = args_mapping
        self.output_mapping = output_mapping
        self.get_endpoint_output = get_endpoint_output
        self.not_found_checker = not_found_checker
        self.additional_args = additional_args
        self.prepare_args_mapping = prepare_args_mapping
        self.post_processing = post_processing

    def __repr__(self):
        return f"{{ name: {self.name}, brand: {self.brand} }}"

    def create_additional_args(self, args):
        self.additional_args = args


class ModuleManager:
    def __init__(self, modules: dict[str, Any], brands_to_run: list[str]) -> None:
        """
        Initializes the instance of ModuleManager.

        Args:
            modules (dict[str, Any]): A dictionary where keys represent module names
                                      and values are dictionaries containing module
                                      details such as 'brand' and 'state'.
            brands_to_run (list[str]): A list of brands to be run.

        Attributes:
            modules_context (dict[str, Any]): Stores the provided modules dictionary.
            _brands_to_run (list[str]): Stores the provided list of brands to run.
            _enabled_brands (set[str]): Stores a set of brands where the module's state is 'active'.
        """
        demisto.debug(f"Initializing ModuleManager with {modules=}")
        self.modules_context = modules
        self._brands_to_run = brands_to_run
        self._enabled_brands = {
            module.get("brand") for module in self.modules_context.values() if module.get("state") == "active"
        } | {Brands.GENERIC_COMMAND}

    def is_brand_in_brands_to_run(self, command: Command) -> bool:
        """
        Checks if the brand associated with the given command is in the list of brands to run.

        Args:
            command (Command): An instance of MappedCommand that contains the brand information.

        Returns:
            bool: True if the brand is in the list of brands to run, or if the list is empty; False otherwise.
        """
        if command.brand == Brands.GENERIC_COMMAND and command.additional_args:
            # in case no brands were given or no available brands were found
            return bool(command.additional_args.get("using-brand"))
        return command.brand in self._brands_to_run if self._brands_to_run else True

    def is_brand_available(self, command: Command) -> bool:
        """
        Checks if the brand associated with the given command is available.

        This function first checks if the brand is in the list of brands to run. If it is,
        it then checks if the brand is in the set of enabled brands.

        Args:
            command (Command): An instance of MappedCommand that contains the brand information.

        Returns:
            bool: True if the brand is in both the list of brands to run and the set of enabled brands;
                  False otherwise.
        """
        return False if not self.is_brand_in_brands_to_run(command) else command.brand in self._enabled_brands

    def get_enabled_brands(self):
        return deepcopy(self._enabled_brands)


def filter_empty_values(input_dict: dict) -> dict:
    """
    Filters out empty values from a dictionary.

    This function creates a new dictionary containing only the key-value pairs
    from the input dictionary where the value is not None, empty string, empty list,
    empty dictionary or empty tuple.

    Args:
        input_dict (dict): The input dictionary to filter.

    Returns:
        dict: A new dictionary with empty values removed.
    """
    return {key: value for key, value in input_dict.items() if value not in (None, "", [], {}, ())}


def convert_none_to_empty_string(item: str | None) -> str:
    """
    Converts None values to empty strings.

    This function takes a value that can be either a string or None and returns
    an empty string if the input is None, otherwise returns the original string value.

    Args:
        item (str | None): The input value that can be either a string or None.

    Returns:
        str: An empty string if the input is None, otherwise the original string value.
    """
    return "" if item is None else item


def get_endpoint_not_found(
    command: Command, human_readable: str, endpoints: list[dict[str, Any]], endpoint_args: dict[str, str]
) -> list[dict[str, Any]]:
    """
    Creates a list of endpoint dictionaries for endpoints that were not found.

    This function identifies endpoints that were not found by checking if the command's
    human-readable output indicates 'no entries' or if fewer endpoints were returned
    than requested. For each missing endpoint, it creates a standardized endpoint
    dictionary marked as not found.

    Args:
        command (Command): An instance of Command containing the command details and not_found_checker.
        human_readable (str): The human-readable output from the command execution.
        endpoints (list[dict[str, Any]]): A list of endpoint dictionaries that were found.
        endpoint_args (dict[str, str]): A dictionary containing endpoint arguments with keys
                                        'endpoint_id', 'endpoint_ip', and 'endpoint_hostname'.

    Returns:
        list[dict[str, Any]]: A list of endpoint dictionaries for endpoints that were not found,
                                or an empty list if all endpoints were found.
    """
    zipped_args = list(
        zip_longest(
            endpoint_args["endpoint_id"].split(","),
            endpoint_args["endpoint_ip"].split(","),
            endpoint_args["endpoint_hostname"].split(","),
            fillvalue="",
        )
    )
    endpoints_not_found_list = get_endpoints_not_found_list(endpoints, zipped_args)

    # Logic to identify "not found" scenarios:
    # 1. If command's human-readable output explicitly indicates 'no entries' (global not found).
    # 2. Or, if some endpoints were found but fewer than requested (partial not found for some inputs).
    if command.not_found_checker in human_readable or (endpoints and (len(endpoints) < len(zipped_args))):
        return [
            create_endpoint(
                endpoint_not_found, {"ID": "ID", "Hostname": "Hostname", "IPAddress": "IPAddress"}, command.brand, False, {}, True
            )
            for endpoint_not_found in endpoints_not_found_list
        ]
    else:
        return []


class EndpointCommandRunner:
    def __init__(self, module_manager: ModuleManager, add_additional_fields: bool) -> None:
        """
        Initializes the instance of EndpointCommandRunner.

        Args:
            module_manager (ModuleManager): An instance of ModuleManager used to manage the modules.
            add_additional_fields (bool): A flag indicating whether to include additional fields in the results.
        """
        self.module_manager = module_manager
        self.add_additional_fields = add_additional_fields

    def run_command(self, command: Command, endpoint_args: dict[str, str]) -> tuple[list[CommandResults], list[dict[str, Any]]]:
        """
        Runs the given command with the provided arguments and returns the results.
        Args:
            command (Command): An instance of the Command class containing the command details.
            endpoint_args (dict[str, str]): A dictionary containing the arguments for the endpoint script.

        Returns:
            tuple[list[CommandResults], list[dict[str, Any]]]:
                - A list of CommandResults objects, which contain the results of the command execution.
                - A list of dictionaries, where each dictionary represents an endpoint and contains the raw output.
        """
        args = (
            command.prepare_args_mapping(endpoint_args) if command.prepare_args_mapping else prepare_args(command, endpoint_args)
        )
        demisto.debug(f"run command '{command.name}' with args={args}")

        if not self.is_command_runnable(command, args):
            return [], []

        raw_outputs = self.run_execute_command(command, args)
        entry_context, human_readable, readable_errors = self.get_command_results(command.name, raw_outputs, args)

        if not entry_context:
            endpoints = get_endpoint_not_found(command, readable_errors[0].readable_output or "", [], endpoint_args)
            return readable_errors, endpoints
        endpoints = entry_context_to_endpoints(command, entry_context, self.add_additional_fields)
        endpoints.extend(get_endpoint_not_found(command, human_readable[0].readable_output or "", endpoints, endpoint_args))

        if command.post_processing:
            demisto.debug(f"command with post processing: {command.name}")
            endpoints = command.post_processing(self, endpoints, endpoint_args)

        return human_readable, endpoints

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
        if not self.module_manager.is_brand_available(command):
            demisto.debug(f'Skipping command "{command.name}" since the brand "{command.brand}" is not available.')
            return False

        # checks if the command has argument mapping
        if not args.values():
            demisto.debug(f'Skipping command "{command.name}" since the provided arguments does not match the command.')
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
            list[dict[str, Any]]: A list of dictionaries containing the command and its results.
        """

        return to_list(demisto.executeCommand(command.name, args))

    @staticmethod
    def get_command_results(
        command: str, results: list[dict[str, Any]], args: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[CommandResults], list[CommandResults]]:
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

        command_context_outputs: list[dict[str, Any]] = []
        human_readable_outputs: list[str] = []
        command_error_outputs: list[CommandResults] = []
        demisto.debug(f'get_commands_outputs for command "{command}" with {len(results)} entry results')

        for entry in results:
            entry_type = entry.get("Type")
            if entry_type == EntryType.ERROR or entry_type == EntryType.WARNING:
                command_error_outputs.append(hr_to_command_results(command, args, entry.get("Contents"), entry_type=entry_type))  # type: ignore[arg-type]
            elif entry_type == EntryType.NOTE:
                command_context_outputs.append(entry.get("EntryContext", {}))
                human_readable_outputs.append(entry.get("HumanReadable") or "")
            else:
                demisto.debug(f"Skipping result with entry type {entry_type}, type is not supported.")

        human_readable = "\n".join(human_readable_outputs)
        human_readable_entry: list[CommandResults] = [hr] if (hr := hr_to_command_results(command, args, human_readable)) else []
        return command_context_outputs, human_readable_entry, command_error_outputs


def to_list(var) -> list:
    """
    Converts the input variable to a list if it is not already a list.
    """
    if not var:
        return []
    return [var] if not isinstance(var, list) else var


def is_private_ip(ip_address: str) -> bool:
    """
    Checks if an IPv4 address is a private (local) IP address using regex pattern matching.

    This function validates IPv4 addresses against private IP ranges including:
    - Class A Private: 10.0.0.0 - 10.255.255.255
    - Class B Private: 172.16.0.0 - 172.31.255.255
    - Class C Private: 192.168.0.0 - 192.168.255.255
    - Loopback: 127.0.0.0 - 127.255.255.255
    - Link-Local: 169.254.0.0 - 169.254.255.255

    Args:
        ip_address (str): The IPv4 address string to check.

    Returns:
        bool: True if the IP address falls within any private range, False otherwise.
    """
    octet = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"  # Regex for a single octet (0-255)

    # Regex for Class A Private (10.0.0.0 - 10.255.255.255)
    private_a = rf"^10\.{octet}\.{octet}\.{octet}$"

    # Regex for Class B Private (172.16.0.0 - 172.31.255.255)
    private_b = rf"^172\.(?:1[6-9]|2\d|3[01])\.{octet}\.{octet}$"

    # Regex for Class C Private (192.168.0.0 - 192.168.255.255)
    private_c = rf"^192\.168\.{octet}\.{octet}$"

    # Regex for Loopback (127.0.0.0 - 127.255.255.255)
    loopback = rf"^127\.{octet}\.{octet}\.{octet}$"

    # Regex for Link-Local (169.254.0.0 - 169.254.255.255)
    link_local = rf"^169\.254\.{octet}\.{octet}$"

    # Combine all private ranges with OR |
    full_private_regex = re.compile(f"{private_a}|{private_b}|{private_c}|{loopback}|{link_local}")

    return bool(full_private_regex.match(ip_address))


def prepare_cs_falcon_args(args: dict[str, str]) -> dict[str, str]:
    """
    Prepares arguments for CrowdStrike Falcon commands by formatting IP addresses with appropriate filters.

    Args:
        args (dict[str, str]): Dictionary containing endpoint arguments with keys 'endpoint_id',
                                'endpoint_hostname', and 'endpoint_ip'.

    Returns:
        dict[str, str]: Formatted arguments dictionary with 'ids', 'hostname', and 'filter' keys.
                        IP addresses are prefixed with 'local_ip:' for private IPs and 'external_ip:'
                        for public IPs in the filter string.
    """
    ips = []
    for ip in argToList(args.get("endpoint_ip", [])):
        if is_private_ip(ip):
            ips.append(f"local_ip:'{ip}'")
        else:
            ips.append(f"external_ip:'{ip}'")

    return filter_empty_values(
        {"ids": args.get("endpoint_id", ""), "hostname": args.get("endpoint_hostname", ""), "filter": ",".join(ips)}
    )


def prepare_epo_args(args: dict[str, str]) -> dict[str, str]:
    """
    Prepares arguments for McAfee ePO commands by selecting the first available endpoint identifier.

    Args:
        args (dict[str, str]): Dictionary containing endpoint arguments with keys 'endpoint_hostname',
                                'endpoint_id', and 'endpoint_ip'.

    Returns:
        dict[str, str]: Formatted arguments dictionary with 'searchText' key containing the first
                        available identifier (hostname, ID, or IP), or empty dict if none provided.
    """
    value = args.get("endpoint_hostname") or args.get("endpoint_id") or args.get("endpoint_ip")
    return filter_empty_values({"searchText": value})


def initialize_commands(
    module_manager: ModuleManager, add_additional_fields: bool
) -> tuple[EndpointCommandRunner, list[Command], list[Command]]:
    """
    Initializes the EndpointCommandRunner and the lists of single-argument and multi-argument commands.
    single-argument commands are commands that accept only single values as arguments.
    multi-argument commands are commands that accept comma-seperated lists of values as arguments.
    Args:
        module_manager (ModuleManager): The ModuleManager instance used to check the availability of integrations.
        add_additional_fields (bool):  Flag to determine whether additional fields should be added to the results.

    Returns:
        tuple[EndpointCommandRunner, list[Command], list[Command]]:
        The initialized EndpointCommandRunner instance, the list of single-argument commands, and the list of
        multi-argument commands.
    """
    command_runner = EndpointCommandRunner(module_manager=module_manager, add_additional_fields=add_additional_fields)

    single_args_commands = [
        Command(
            brand=Brands.GENERIC_COMMAND,
            name="endpoint",
            output_keys=["Endpoint"],
            args_mapping={"id": "endpoint_id", "ip": "endpoint_ip", "hostname": "endpoint_hostname"},
            output_mapping={
                "ID": "ID",
                "Hostname": "Hostname",
                "IPAddress": "IPAddress",
                "Status": "Status",
                "IsIsolated": "IsIsolated",
                "Vendor": "Brand",
            },
            post_processing=generic_endpoint_post,
        ),
        Command(
            brand=Brands.ACTIVE_DIRECTORY_QUERY_V2,
            name="ad-get-computer",
            output_keys=["ActiveDirectory.Computers"],
            args_mapping={"name": "endpoint_hostname"},
            output_mapping={"dn": "ID", "name": "Hostname"},
            post_processing=active_directory_post,
        ),
        Command(
            brand=Brands.MCAFEE_EPO_V2,
            name="epo-find-system",
            output_keys=["McAfee.ePO.Endpoint"],
            args_mapping={},
            prepare_args_mapping=prepare_epo_args,
            output_mapping={"ID": "ID", "Hostname": "Hostname", "IPAddress": "IPAddress"},
            get_endpoint_output=True,
            not_found_checker="No systems found",
        ),
        Command(
            brand=Brands.CORTEX_XDR_IR,
            name="xdr-list-risky-hosts",
            output_keys=["PaloAltoNetworksXDR.RiskyHost"],
            args_mapping={"host_id": "endpoint_hostname"},
            output_mapping={"id": "Hostname", "risk_level": "RiskLevel"},
            not_found_checker="was not found",
        ),
        Command(
            brand=Brands.CORTEX_CORE_IR,
            name="core-list-risky-hosts",
            output_keys=["Core.RiskyHost"],
            args_mapping={"host_id": "endpoint_hostname"},
            output_mapping={"id": "Hostname", "risk_level": "RiskLevel"},
        ),
        Command(
            brand=Brands.FIREEYE_HX_V2,
            name="fireeye-hx-get-host-information",
            output_keys=["FireEyeHX.Hosts"],
            args_mapping={"agentId": "endpoint_id", "hostName": "endpoint_hostname"},
            output_mapping={
                "_id": "ID",
                "hostname": "Hostname",
                "primary_ip_address": "IPAddress",
                "containment_state": "Status",
            },
            not_found_checker="is not correct",
        ),
    ]

    list_args_commands = [
        Command(
            brand=Brands.CORTEX_CORE_IR,
            name="core-get-endpoints",
            output_keys=["Core.Endpoint"],
            args_mapping={"endpoint_id_list": "endpoint_id", "ip_list": "endpoint_ip", "hostname": "endpoint_hostname"},
            output_mapping={
                "ID": "ID",
                "Hostname": "Hostname",
                "IPAddress": "IPAddress",
                "Status": "Status",
                "IsIsolated": "IsIsolated",
            },
            get_endpoint_output=True,
        ),
        Command(
            brand=Brands.CORTEX_XDR_IR,
            name="xdr-get-endpoints",
            output_keys=["PaloAltoNetworksXDR.Endpoint"],
            args_mapping={"endpoint_id_list": "endpoint_id", "ip_list": "endpoint_ip", "hostname": "endpoint_hostname"},
            output_mapping={
                "ID": "ID",
                "Hostname": "Hostname",
                "IPAddress": "IPAddress",
                "Status": "Status",
                "IsIsolated": "IsIsolated",
            },
            get_endpoint_output=True,
        ),
        Command(
            brand=Brands.CROWDSTRIKE_FALCON,
            name="cs-falcon-search-device",
            output_keys=["CrowdStrike.Device"],
            args_mapping={"ids": "endpoint_id", "hostname": "endpoint_hostname"},
            prepare_args_mapping=prepare_cs_falcon_args,
            output_mapping={
                "ID": "ID",
                "Hostname": "Hostname",
                "IPAddress": "IPAddress",
                "Status": "Status",
                "IsIsolated": "IsIsolated",
            },
            get_endpoint_output=True,
            not_found_checker="Could not find any devices.",
        ),
    ]

    return command_runner, single_args_commands, list_args_commands


def run_single_args_commands(
    zipped_args,
    single_args_commands,
    command_runner: EndpointCommandRunner,
    verbose: bool,
    ir_mapping: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[CommandResults]]:
    """
    Runs the single-argument commands for each endpoint individually and returns the command results,
    human-readable outputs, and a list of endpoints that were found.

    Args:
        zipped_args (Iterable[Tuple[Any, Any, Any]]): A list of tuples containing endpoint ID, endpoint IP, and endpoint hostname.
        single_args_commands (List[Command]): A list of single-argument commands to run.
        command_runner (EndpointCommandRunner): The EndpointCommandRunner instance to use for running the commands.
        verbose (bool): A flag indicating whether to print verbose output.
        ir_mapping (dict[str, Any]): A dictionary mapping endpoints for core/xdr IR.

    Returns:
        tuple[list[dict[str, Any]], list[CommandResults]]:
        The endpoints that were successfully found and a list of command results.
    """
    endpoint_outputs_list = []
    command_results_list = []
    for endpoint_id, endpoint_ip, endpoint_hostname in zipped_args:
        single_endpoint_readable_outputs: list[CommandResults] = []

        for command in single_args_commands:
            readable_outputs, endpoint_output = command_runner.run_command(
                command=command,
                endpoint_args={"endpoint_id": endpoint_id, "endpoint_ip": endpoint_ip, "endpoint_hostname": endpoint_hostname},
            )

            if endpoint_output:
                if command.brand in [Brands.CORTEX_XDR_IR, Brands.CORTEX_CORE_IR]:
                    update_endpoint_in_mapping(endpoint_output, ir_mapping)
                else:
                    endpoint_outputs_list.extend(endpoint_output)
            single_endpoint_readable_outputs.extend(readable_outputs)

        if verbose:
            command_results_list.extend(single_endpoint_readable_outputs)

    demisto.debug(f"ending single arg loop with {len(endpoint_outputs_list)} new endpoints")
    return endpoint_outputs_list, command_results_list


def run_list_args_commands(
    list_args_commands,
    command_runner: EndpointCommandRunner,
    endpoint_id,
    endpoint_ips,
    endpoint_hostnames,
    verbose,
    ir_mapping: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[CommandResults]]:
    """
    Runs the list-argument commands for multiple endpoints and returns the command results,
    human-readable outputs, and a list of endpoints that were found.

    Args:
        list_args_commands (List[Command]): A list of list-argument commands to run.
        command_runner (EndpointCommandRunner): The EndpointCommandRunner instance to use for running the commands.
        endpoint_id (List[str]): A list of endpoint IDs.
        endpoint_ips (List[str]): A list of endpoint IP addresses.
        endpoint_hostnames (List[str]): A list of endpoint hostnames.
        verbose (bool): A flag indicating whether to print verbose output.
        ir_mapping (dict[str, Any]): A dictionary mapping endpoints for core/xdr IR.

    Returns:
        tuple[list[dict[str, Any]], list[CommandResults]]:
        The endpoints that were successfully found and a list of command results.
    """
    multiple_endpoint_outputs = []
    multiple_endpoint_readable_outputs: list[CommandResults] = []

    for command in list_args_commands:
        readable_outputs, endpoint_output = command_runner.run_command(
            command,
            {
                "endpoint_id": ",".join(endpoint_id),
                "endpoint_ip": ",".join(endpoint_ips),
                "endpoint_hostname": ",".join(endpoint_hostnames),
            },
        )

        if endpoint_output:
            if command.brand in [Brands.CORTEX_XDR_IR, Brands.CORTEX_CORE_IR]:
                add_endpoint_to_mapping(endpoint_output, ir_mapping)
            else:
                multiple_endpoint_outputs.extend(endpoint_output)

        if verbose:
            multiple_endpoint_readable_outputs.extend(readable_outputs)

    return multiple_endpoint_outputs, multiple_endpoint_readable_outputs


def create_endpoint(
    command_output: dict[str, Any],
    output_mapping: dict[str, str],
    brand: str,
    add_additional_fields: bool,
    endpoint_output: dict[str, Any],
    is_failed: bool = False,
) -> dict[str, Any]:
    """
    Creates an endpoint dictionary from command output, output mapping, and brand.

    This function processes the command output and creates a structured endpoint dictionary.
    It maps the command output keys to endpoint keys based on the provided output mapping,
    and includes the brand information for each value.

    Args:
        command_output (dict[str, Any]): The output from a command execution.
        output_mapping (dict[str, str]): A mapping of command output keys to endpoint keys.
            If a function is passed, the function does nothing and returns the result of the passed function.
        brand (str): The brand of the data.
        add_additional_fields (bool): Flag to include additional fields in the endpoint dictionary.
        endpoint_output (dict[str, Any]): The endpoint output dictionary.
        is_failed (bool, optional): Flag to indicate if the command failed. Defaults to False.

    Returns:
        dict[str, Any]: A structured endpoint dictionary with values and their brands.
    """
    if not command_output:
        return {}
    message = COMMAND_SUCCESS_MSG if not is_failed else COMMAND_FAILED_MSG
    endpoint: dict[str, Any] = {"Message": message}
    additional_fields = {}

    if endpoint_output:
        for key, value in endpoint_output.items():
            if mapped_key := output_mapping.get(key):
                endpoint[mapped_key] = value
        if add_additional_fields:
            additional_fields = command_output
    else:
        for key, value in command_output.items():
            if mapped_key := output_mapping.get(key):
                endpoint[mapped_key] = value
            else:
                additional_fields[key] = value

    if "Brand" not in endpoint:  # in case of not "Generic Command"
        endpoint["Brand"] = brand
    if add_additional_fields:
        endpoint["AdditionalFields"] = additional_fields

    return endpoint


def prepare_args(command: Command, endpoint_args: dict[str, Any]) -> dict[str, Any]:
    """
    Prepares the arguments dictionary for the command.
    If the endpoint argument value is an empty string or None, the resulting dictionary will not include
    the argument.

    Args:
        command (Command): The command to prepare for.
        endpoint_args (dict[str, Any]): The arguments received by this aggregation command.
    Returns:
        dict[str, Any]: The arguments dictionary that's right for the command.
    """
    command_args: dict[str, Any] = {}
    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        if command_arg_value := endpoint_args.get(endpoint_arg_key):
            command_args[command_arg_key] = command_arg_value

    if command.additional_args:  # adding additional arguments
        command_args.update(command.additional_args)

    return command_args


def hr_to_command_results(
    command_name: str, args: dict[str, Any], human_readable: str, entry_type: int = EntryType.NOTE
) -> CommandResults | None:
    """
    Converts human-readable output to CommandResults object for display in Demisto.

    This function creates a CommandResults object from human-readable text output,
    formatting it with the command name and arguments for better readability.

    Args:
        command_name (str): The name of the command that generated the output.
        args (dict[str, Any]): The arguments passed to the command.
        human_readable (str): The human-readable output text to display.
        is_error (bool, optional): Flag to indicate if this represents an error. Defaults to False.

    Returns:
        CommandResults | None: A CommandResults object with formatted output, or None if no human_readable text provided.
    """
    status_map = {
        EntryType.ERROR: "Error",
        EntryType.WARNING: "Warning",
    }
    result = None
    if human_readable:
        command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        result_message = f"#### {status_map.get(entry_type, 'Result')} for {command}\n{human_readable}"
        result = CommandResults(readable_output=result_message, entry_type=entry_type, mark_as_note=True)
    return result


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
            demisto.debug(f"Output key {output_key} not found in entry context keys: {list(raw_context.keys())}")
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


def get_raw_endpoints(output_keys: list[str], raw_context: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Merges data structures from different output keys into a single endpoint.

    This function processes data from different brands with varying structures
    and merges it into a list of dictionaries. Each dictionary represents a single
    endpoint, combining data from different keys.

    Args:
        output_keys (list of str): A list of strings representing the keys to access
                                   in the dictionaries within `raw_context`.
        raw_context (list of dict): A list of dictionaries where each dictionary
                                    contains data from different brands.

    Returns:
        list of dict: A consolidated list where each dictionary represents a single
                      endpoint, merging data from different keys.

    Example:
        raw_context = [
            {
                "Endpoint": {"data from Endpoint for object_1": "value1"},
                "Device": [{"data from Device for object_1": "value2"}]
            },
            {
                "Endpoint": {"data from Endpoint for object_2": "value3"},
                "Device": [{"data from Device for object_2": "value4"}]
            },
        ]

        output_keys = ['Endpoint', 'Device']

        get_raw_endpoints(output_keys, raw_context)
        # Expected output:
        # [
        #     {"data from Endpoint for object_1": "value1", "data from Device for object_1": "value2"},
        #     {"data from Endpoint for object_2": "value3", "data from Device for object_2": "value4"}
        # ]

    Example with single context containing lists of objects:
        raw_context = [
            {
                "Device": [
                    {"data from Device for object_1": "value1"},
                    {"data from Device for object_2": "value3"}
                ],
                "Endpoint": [
                    {"data from Endpoint for object_1": "value2"},
                    {"data from Endpoint for object_2": "value4"}
                ]
            }
        ]

        output_keys = ['Endpoint', 'Device']

        get_raw_endpoints(output_keys, raw_context)
        # Expected output:
        # [
        #     {"data from Endpoint for object_1": "value2", "data from Device for object_1": "value1"},
        #     {"data from Endpoint for object_2": "value4", "data from Device for object_2": "value3"}
        # ]
    """
    raw_endpoints = []

    for context in raw_context:
        # Convert each key's data to a list using to_list
        lists_of_objects = [to_list(get_outputs(key, context)) for key in output_keys]

        # Use zip to group corresponding elements together
        for grouped_objects in zip(*[output for output in lists_of_objects if output]):
            raw_endpoint = {}
            for raw_data in grouped_objects:
                raw_endpoint.update(raw_data)
            raw_endpoints.append(raw_endpoint)

    return raw_endpoints


def create_endpoints(
    raw_endpoints: list[dict[str, Any]],
    output_mapping: dict,
    brand: str,
    add_additional_fields: bool,
    raw_endpoints_output: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Creates a list of endpoint dictionaries from the raw endpoint data.
    Args:
        raw_endpoints (list[dict[str, Any]]): The raw endpoint data to be processed.
        output_mapping (dict): A dictionary or a callable that maps the raw data to the desired output format.
        brand (str): The brand associated with the endpoints.
        add_additional_fields (bool): Flag to determine whether to add additional fields to the endpoint.
        raw_endpoints_output (list[dict[str, Any]]): The raw endpoint data to be processed.

    Returns:
        list[dict[str, Any]]: A list of endpoint dictionaries.
    """
    endpoints = []
    if not raw_endpoints_output:
        raw_endpoints_output = [{} for _ in raw_endpoints]
    for raw_endpoint, raw_endpoint_output in zip(raw_endpoints, raw_endpoints_output):
        endpoints.append(create_endpoint(raw_endpoint, output_mapping, brand, add_additional_fields, raw_endpoint_output))
    return endpoints


def entry_context_to_endpoints(command: Command, entry_context: list, add_additional_fields: bool) -> list[dict[str, Any]]:
    """
    Processes the entry context and generates a list of endpoint dictionaries.
    Args:
        command (Command): A Command object containing the necessary configuration for the endpoint generation.
        entry_context (list): The entry context data to be processed.
        add_additional_fields (bool): Flag to determine whether to add additional fields to the endpoints.

    Returns:
        list[dict[str, Any]]: A list of endpoint dictionaries generated from the entry context.
    """
    raw_endpoints = get_raw_endpoints(command.output_keys, entry_context)
    endpoint_raw_data = []
    if command.get_endpoint_output:
        endpoint_raw_data = get_raw_endpoints(["Endpoint"], entry_context)

    endpoints = create_endpoints(raw_endpoints, command.output_mapping, command.brand, add_additional_fields, endpoint_raw_data)
    demisto.debug(f"Returning {len(endpoints)} endpoints")
    return endpoints


def add_endpoint_to_mapping(endpoints: list[dict[str, Any]], ir_mapping: dict[str, Any]):
    """
    Adds endpoints to the endpoint mapping.
    Args:
        endpoints (list[dict[str, Any]]): A list of endpoint dictionaries.
        ir_mapping (dict[str, Any]): A dictionary mapping endpoints for core/xdr IR.
    """
    for endpoint in endpoints:
        if COMMAND_SUCCESS_MSG not in endpoint.get("Message", ""):
            demisto.debug(f"skipping endpoint due to failure: {endpoint}")
            continue
        ir_mapping[endpoint["ID"]] = endpoint


def get_extended_hostnames_set(Ir_endpoints: dict[str, Any]) -> set[str]:
    """
    Retrieves a set of extended hostnames from the endpoint mappings.

    Args:
        Ir_endpoints (dict[str, Any]): A dictionary of endpoint mappings.

    Returns:
        set[str]: Set of extended hostnames.
    """
    hostnames = set()
    for endpoint in Ir_endpoints.values():
        hostnames.add(endpoint["Hostname"])
    return hostnames


def get_endpoints_not_found_list(endpoints: list[dict[str, Any]], zipped_args: list[tuple]) -> list[dict[str, str]]:
    """
    Identify endpoints not found in the provided endpoints.

    Args:
        endpoints (list of dict): List of endpoint dictionaries with 'Hostname', 'ID', and 'IPAddress' keys.
        zipped_args (list of tuple): List of tuples, each containing (endpoint_id, endpoint_ip, endpoint_hostname).

    Returns:
        list of dict: List of dictionaries with 'Key' for endpoints not found, containing comma-separated endpoint_id, endpoint_ip
        and endpoint_hostname.
    """
    endpoints_not_found = []
    hostnames = set()
    ids = set()
    ips = set()
    for endpoint in endpoints:
        if endpoint["Message"] == COMMAND_FAILED_MSG:
            continue
        hostnames_list = to_list(endpoint.get("Hostname"))
        ids_list = to_list(endpoint.get("ID"))
        ips_list = to_list(endpoint.get("IPAddress"))
        hostnames.update(hostnames_list)
        ids.update(ids_list)
        ips.update(ips_list)

    for endpoint_id, endpoint_ip, endpoint_hostname in zipped_args:
        if endpoint_id not in ids and endpoint_ip not in ips and endpoint_hostname not in hostnames:
            endpoint_not_found = filter_empty_values({"ID": endpoint_id, "Hostname": endpoint_hostname, "IPAddress": endpoint_ip})
            endpoints_not_found.append(endpoint_not_found)
    return endpoints_not_found


def active_directory_post(
    self: EndpointCommandRunner, endpoints: list[dict[str, Any]], args: dict[str, Any]
) -> list[dict[str, Any]]:
    fixed_endpoints = []
    for endpoint in endpoints:
        endpoint_hostname = endpoint["Hostname"]
        if isinstance(endpoint_hostname, str):
            fixed_endpoints.append(endpoint)
        elif isinstance(endpoint_hostname, list) and len(endpoint_hostname) == 1:
            endpoint["Hostname"] = endpoint_hostname[0]
            fixed_endpoints.append(endpoint)
        else:
            raise ValueError("Invalid hostname")
    return fixed_endpoints


def generic_endpoint_post(
    self: EndpointCommandRunner, endpoints: list[dict[str, Any]], args: dict[str, Any]
) -> list[dict[str, Any]]:
    endpoints_to_return = []
    for endpoint in endpoints:
        brand = endpoint["Brand"]
        if brand in Brands.get_all_values() and self.module_manager.is_brand_available(Command(brand, "", [], {}, {})):
            # If the brand is in the brands, we don't need if from the generic command
            demisto.debug(f"Skipping generic endpoint with brand: '{brand}'")
        else:
            endpoints_to_return.append(endpoint)
    return endpoints_to_return


def get_generic_command(single_args_commands: list[Command]) -> Command:
    """
    Retrieves the generic command object from a list of command objects.

    Args:
        single_args_commands (list of Command): A list of Command objects to search through.

    Returns:
        Command : The Command object with brand 'Generic Command', or None if not found.
    """
    for command in single_args_commands:
        if command.brand == Brands.GENERIC_COMMAND:
            return command
    raise ValueError("Generic Command not found in the Commands list.")


def create_using_brand_argument_to_generic_command(brands_to_run: list, generic_command: Command, module_manager: ModuleManager):
    """
    Creates the 'using-brand' argument for a generic command by filtering out specific predefined brands.

    Args:
        brands_to_run (list of str): List of brand names provided as input. If empty, defaults to removing all predefined brands.
        generic_command (Command): The generic command object where additional arguments will be added.
        module_manager (ModuleManager) : The module manager object.

    Returns:
        None: The function updates the generic_command object by adding the 'using-brand' argument with filtered brands.
    """
    predefined_brands = set(Brands.get_all_values())
    available_brands = module_manager.get_enabled_brands()

    if brands_to_run:
        brands_to_run_for_generic_command = list(set(brands_to_run) - predefined_brands)
    else:
        # we want to run the !endpoint on all brands available
        brands_to_run_for_generic_command = list(available_brands - set(predefined_brands))

    joined_brands = ",".join(brands_to_run_for_generic_command)
    generic_command.create_additional_args({"using-brand": joined_brands})


def update_endpoint_in_mapping(endpoints: list[dict[str, Any]], ir_mapping: dict[str, Any]):
    """
    Adds endpoints to the endpoint mapping.
    Args:
        endpoints (list[dict[str, Any]]): A list of endpoint dictionaries.
        ir_mapping (dict[str, Any]): A dictionary mapping endpoints for core/xdr IR.
    """
    for endpoint in endpoints:
        if COMMAND_SUCCESS_MSG not in endpoint.get("Message", ""):
            demisto.debug(f"skipping endpoint due to failure: {endpoint}")
            continue
        for ir_endpoint in ir_mapping.values():
            if ir_endpoint.get("Hostname") == endpoint.get("Hostname"):
                if not isinstance(endpoint.get("RiskLevel"), list):
                    endpoint["RiskLevel"] = [endpoint.get("RiskLevel")]
                for risk in endpoint.get("RiskLevel", []):
                    if "RiskLevel" in ir_endpoint:
                        ir_endpoint["RiskLevel"] = IRRISKLEVEL[max(IRRISKLEVEL[risk], IRRISKLEVEL[ir_endpoint.get("RiskLevel")])]  # type: ignore
                    else:
                        ir_endpoint["RiskLevel"] = risk
                if "additional_fields" in endpoint:
                    ir_endpoint.update(endpoint["additional_fields"])


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        args = demisto.args()
        endpoint_ids = argToList(args.get("endpoint_id", []), transform=convert_none_to_empty_string)
        endpoint_ips = argToList(args.get("endpoint_ip", []), transform=convert_none_to_empty_string)
        endpoint_hostnames = argToList(args.get("endpoint_hostname", []), transform=convert_none_to_empty_string)
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", []))
        add_additional_fields = argToBoolean(args.get("additional_fields", False))
        module_manager = ModuleManager(demisto.getModules(), brands_to_run)

        if not any((endpoint_ids, endpoint_ips, endpoint_hostnames)):
            raise ValueError(
                "At least one of the following arguments must be specified: endpoint_id, endpoint_ip or endpoint_hostname."
            )

        endpoint_outputs_list: list[dict[str, Any]] = []
        command_results_list: list[CommandResults] = []
        ir_mapping: dict[str, Any] = {}

        command_runner, single_args_commands, list_args_commands = initialize_commands(module_manager, add_additional_fields)

        generic_command = get_generic_command(single_args_commands)
        create_using_brand_argument_to_generic_command(brands_to_run, generic_command, module_manager)

        zipped_args: list[tuple] = list(zip_longest(endpoint_ids, endpoint_ips, endpoint_hostnames, fillvalue=""))

        endpoint_outputs_list_commands, command_results_list_commands = run_list_args_commands(
            list_args_commands, command_runner, endpoint_ids, endpoint_ips, endpoint_hostnames, verbose, ir_mapping
        )
        endpoint_outputs_list.extend(endpoint_outputs_list_commands)
        command_results_list.extend(command_results_list_commands)

        if extended_hostnames_set := get_extended_hostnames_set(ir_mapping):
            demisto.debug(f"got extended hostnames set: {extended_hostnames_set}")
            hostnames_to_run = set(endpoint_hostnames).union(extended_hostnames_set)
            demisto.debug(f"got total of hostnames to run: {hostnames_to_run}")
            zipped_args = list(zip_longest(endpoint_ids, endpoint_ips, hostnames_to_run, fillvalue=""))

        endpoint_outputs_single_commands, command_results_single_commands = run_single_args_commands(
            zipped_args, single_args_commands, command_runner, verbose, ir_mapping
        )

        demisto.debug("preparing to convert endpoint mapping to list.")
        endpoint_outputs_single_commands.extend(list(ir_mapping.values()))

        endpoint_outputs_list.extend(endpoint_outputs_single_commands)
        command_results_list.extend(command_results_single_commands)

        if endpoints_not_found_list := get_endpoints_not_found_list(endpoint_outputs_list, zipped_args):
            command_results_list.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) not found",
                        t=endpoints_not_found_list,
                    )
                )
            )
        if endpoint_outputs_list:
            command_results_list.append(
                CommandResults(
                    outputs_prefix="EndpointData",
                    outputs_key_field=["Brand", "ID", "Hostname"],
                    outputs=endpoint_outputs_list,
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) data",
                        t=list(filter(lambda ep: COMMAND_FAILED_MSG not in ep["Message"], endpoint_outputs_list)),
                        headers=["Brand", "ID", "Hostname", "IPAddress", "Status", "IsIsolated", "Message"],
                        removeNull=True,
                    ),
                )
            )
        return_results(command_results_list)

    except Exception as e:
        return_error(f"Failed to execute get-endpoint-data. Error: {e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
