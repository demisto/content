from CommonServerPython import *
from typing import Any
from collections.abc import Callable
from itertools import zip_longest


class Command:
    def __init__(
        self,
        brand: str,
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
        demisto.debug(f'Initializing ModuleManager with {modules=}')
        self.modules_context = modules
        self._brands_to_run = brands_to_run
        self._enabled_brands = {
            module.get("brand")
            for module in self.modules_context.values()
            if module.get("state") == "active"
        }

    def is_brand_in_brands_to_run(self, command: Command) -> bool:
        """
        Checks if the brand associated with the given command is in the list of brands to run.

        Args:
            command (Command): An instance of MappedCommand that contains the brand information.

        Returns:
            bool: True if the brand is in the list of brands to run, or if the list is empty; False otherwise.
        """
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


class EndpointCommandRunner:
    def __init__(self, module_manager: ModuleManager) -> None:
        """
        Initializes the instance of EndpointCommandRunner.

        Args:
            module_manager (ModuleManager): An instance of ModuleManager used to manage the modules.

        Attributes:
            module_manager (ModuleManager): Stores the provided ModuleManager instance.
        """
        self.module_manager = module_manager

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

        if not self.is_command_runnable(command, args):
            return [], []

        raw_outputs = self.run_execute_command(command, args)
        entry_context, human_readable, readable_errors = self.get_command_results(command.name,
                                                                                  raw_outputs,
                                                                                  args)

        if not entry_context:
            return readable_errors, []

        endpoints = entry_context_to_endpoints(command, entry_context)
        if command.post_processing:
            demisto.debug(f'command with post processing: {command.name}')
            endpoints = command.post_processing(endpoints, endpoint_args)

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
            demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
            return False

        # checks if the command has argument mapping
        if command.args_mapping and not args.values():
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
            Dict[str, Any]: A dictionary containing the command and its results.
        """

        return to_list(demisto.executeCommand(command.name, args))

    @staticmethod
    def get_command_results(command: str, results: list[dict[str, Any]], args: dict[str, Any]) -> tuple[list, list, list]:
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
            if is_error(entry):
                command_error_outputs.append(hr_to_command_results(command, args, get_error(entry), is_error=True))
            else:
                command_context_outputs.append(entry.get("EntryContext", {}))
                human_readable_outputs.append(entry.get("HumanReadable") or "")

        human_readable = "\n".join(human_readable_outputs)
        human_readable = [hr] if (hr := hr_to_command_results(command, args, human_readable)) else []
        return command_context_outputs, human_readable, command_error_outputs


def to_list(var):
    """
    Converts the input variable to a list if it is not already a list.
    """
    if not var:
        return []
    return [var] if not isinstance(var, list) else var


def initialize_commands(module_manager: ModuleManager) -> tuple[EndpointCommandRunner, list[Command], list[Command]]:
    """
    Initializes the EndpointCommandRunner and the lists of single-argument and multi-argument commands.
    single-argument commands are commands that accept only single values as arguments.
    multi-argument commands are commands that accept comma-seperated lists of values as arguments.
    Args:
        module_manager (ModuleManager): The ModuleManager instance used to check the availability of integrations.

    Returns:
        tuple[EndpointCommandRunner, list[Command], list[Command]]:
        The initialized EndpointCommandRunner instance, the list of single-argument commands, and the list of
        multi-argument commands.
    """
    command_runner = EndpointCommandRunner(module_manager=module_manager)

    single_args_commands = [
        Command(
            brand='VMware Carbon Black EDR v2',
            name='cb-edr-sensors-list',
            output_keys=["CarbonBlackEDR.Sensor"],
            args_mapping={'hostname': 'agent_hostname', 'id': 'agent_id', 'ip': 'agent_ip'},
            output_mapping={'id': 'ID', 'computer_name': 'Hostname', 'status': 'Status'}
        ),
        Command(
            brand='Cortex Core - IR',
            name='core-get-endpoints',
            output_keys=['Endpoint', 'Account'],
            args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'},
            output_mapping={}
        ),
        Command(
            brand="Generic Command",
            name="endpoint",
            output_keys=['Endpoint'],
            args_mapping={"id": "agent_id", "ip": "agent_ip", "name": "agent_hostname"},
            output_mapping={}
        ),
        Command(
            brand="Active Directory Query v2",
            name="ad-get-computer",
            output_keys=["Endpoint"],
            args_mapping={"name": "agent_hostname"},
            output_mapping={},
            post_processing=active_directory_post
        ),
        Command(
            brand='McAfee ePO v2',
            name='epo-find-system',
            output_keys=["Endpoint"],
            args_mapping={'searchText': 'agent_hostname'},
            output_mapping={},
        ),
        Command(
            brand='ExtraHop v2',
            name='extrahop-devices-search',
            output_keys=["ExtraHop.Device"],
            args_mapping={'name': 'agent_hostname'},
            output_mapping=extra_hop_mapping
        ),
        Command(
            brand='Cortex XDR - IR',
            name='xdr-list-risky-hosts',
            output_keys=["PaloAltoNetworksXDR.RiskyHost"],
            args_mapping={'host_id': 'agent_id'},
            output_mapping={'id': 'ID'}
        ),
        Command(
            brand="Cylance Protect v2",
            name="cylance-protect-get-devices",
            output_keys=["Endpoint"],
            args_mapping={},
            output_mapping={},
            post_processing=cylance_filtering
        )
    ]

    list_args_commands = [
        Command(
            brand='Cortex XDR - IR',
            name='xdr-get-endpoints',
            output_keys=['Endpoint', 'Account'],
            args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'},
            output_mapping={}
        ),
        Command(
            brand='Cortex Core - IR',
            name='core-list-risky-hosts',
            output_keys=["Endpoint"],
            args_mapping={'host_id': 'agent_id'},
            output_mapping={'id': 'ID'},

        ),
        Command(
            brand='CrowdstrikeFalcon',
            name='cs-falcon-search-device',
            output_keys=["Endpoint"],
            args_mapping={'ids': 'agent_id', 'hostname': 'agent_hostname'},
            output_mapping={},
        )
    ]

    return command_runner, single_args_commands, list_args_commands


def run_single_args_commands(
        zipped_args,
        single_args_commands,
        command_runner,
        verbose,
        endpoint_outputs_list
):
    """
    Runs the single-argument commands and returns the command results, human-readable outputs, and a list of endpoints
    that were not found.
    Args:
        zipped_args (Iterable[Tuple[Any, Any, Any]]): A list of tuples containing agent ID, agent IP, and agent hostname.
        single_args_commands (List[Command]): A list of single-argument commands to run.
        command_runner (EndpointCommandRunner): The EndpointCommandRunner instance to use for running the commands.
        verbose (bool): A flag indicating whether to print verbose output.
        endpoint_outputs_list (List[Dict[str, Any]]): A list to store the output from the commands.
    Returns:
        tuple[CommandResults, List[Command], List[Command]]:
        The endpoints that were successfully found, list of endpoints that were not found, and a list of command results.
    """
    command_results_list = []
    for agent_id, agent_ip, agent_hostname in zipped_args:
        single_endpoint_outputs = []
        single_endpoint_readable_outputs = []

        for command in single_args_commands:
            readable_outputs, endpoint_output = command_runner.run_command(
                command=command,
                endpoint_args={
                    'agent_id': agent_id,
                    'agent_ip': agent_ip,
                    'agent_hostname': agent_hostname
                }
            )

            if endpoint_output:
                single_endpoint_outputs.append(endpoint_output)
            single_endpoint_readable_outputs.extend(readable_outputs)

        if verbose:
            command_results_list.extend(single_endpoint_readable_outputs)

        merged_endpoints = merge_endpoint_outputs(single_endpoint_outputs)
        endpoint_outputs_list.extend(merged_endpoints)

    demisto.debug(f'ending single arg loop with {len(endpoint_outputs_list)} endpoints')
    return endpoint_outputs_list, command_results_list


def run_list_args_commands(
        list_args_commands,
        command_runner,
        agent_ids,
        agent_ips,
        agent_hostnames,
        endpoint_outputs_list,
        verbose
):
    """
    Runs the list-argument commands and returns the command results, human-readable outputs, and a list of
    endpoints that were not found.
    Args:
        list_args_commands (List[Command]): A list of list-argument commands to run.
        command_runner (EndpointCommandRunner): The EndpointCommandRunner instance to use for running the commands.
        agent_ids (List[str]): A list of agent IDs.
        agent_ips (List[str]): A list of agent IPs.
        agent_hostnames (List[str]): A list of agent hostnames.
        zipped_args (Iterable[Tuple[Any, Any, Any]]): A list of tuples containing agent ID, agent IP, and agent hostname.
        endpoint_outputs_list (List[Dict[str, Any]]): A list to store the output from the commands.
        verbose (bool): A flag indicating whether to print verbose output.
    Returns:
        tuple[list[dict], list[CommandResults]]:
        The endpoints that were successfully found and a list of command results.
    """
    multiple_endpoint_outputs = []
    multiple_endpoint_readable_outputs = []

    for command in list_args_commands:
        readable_outputs, endpoint_output = command_runner.run_command(
            command,
            {
                'agent_id': ",".join(agent_ids),
                'agent_ip': ",".join(agent_ips),
                'agent_hostname': ",".join(agent_hostnames)
            }
        )

        if endpoint_output:
            multiple_endpoint_outputs.append(endpoint_output)
        if verbose:
            multiple_endpoint_readable_outputs.extend(readable_outputs)

    merged_endpoints = merge_endpoint_outputs(multiple_endpoint_outputs)
    endpoint_outputs_list.extend(merged_endpoints)

    return endpoint_outputs_list, multiple_endpoint_readable_outputs


def safe_list_get(lst: list, idx: int, default: Any):
    """
    Safely retrieves an element from a list at the specified index.

    Args:
    l (list): The input list.
    idx (int): The index of the element to retrieve.
    default (Any): The default value to return if the index is out of range.

    Returns:
    Any: The element at the specified index if it exists, otherwise the default value.
    """
    try:
        return lst[idx]
    except IndexError:
        return default


def create_endpoint(
        command_output: dict[str, Any],
        output_mapping: dict[str, str],
        source: str
) -> dict[str, Any]:
    """
    Creates an endpoint dictionary from command output, output mapping, and source.

    This function processes the command output and creates a structured endpoint dictionary.
    It maps the command output keys to endpoint keys based on the provided output mapping,
    and includes the source information for each value.

    Args:
        command_output (dict[str, Any]): The output from a command execution.
        output_mapping (dict[str, str] | Callable): A mapping of command output keys to endpoint keys.
            If a function is passed, the function does nothing and returns the result of the passed function.
        source (str): The source of the data.

    Returns:
        dict[str, Any]: A structured endpoint dictionary with values and their sources.
    """
    if not command_output:
        return {}

    endpoint = {}
    for key, value in command_output.items():
        endpoint_key = mapped_key if (mapped_key := output_mapping.get(key)) else key
        endpoint[endpoint_key] = {'Value': value, 'Source': source}

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
    command_args = {}
    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        if command_arg_value := endpoint_args.get(endpoint_arg_key):
            command_args[command_arg_key] = command_arg_value

    return command_args


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
    result = None
    if human_readable:
        command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        result_type = EntryType.ERROR if is_error else None
        result_message = f"#### {'Error' if is_error else 'Result'} for {command}\n{human_readable}"
        result = CommandResults(readable_output=result_message, entry_type=result_type, mark_as_note=True)
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


def merge_endpoints(endpoints: list[dict[str, dict[str, Any]]]) -> dict[str, Any]:
    """
    Merges multiple endpoint dictionaries into a single dictionary.

    This function takes a list of endpoint dictionaries and combines them into a single dictionary.
    If conflicts occur for keys other than 'Hostname', the values are combined into a list.
    For 'Hostname', if a conflict is detected, an error is logged.

    Args:
        endpoints (list[dict[str, dict[str, Any]]]): A list of endpoint dictionaries to merge.

    Returns:
        dict[str, Any]: A merged dictionary containing all endpoint information.

    Note:
        - Conflicts for 'Hostname' are treated as errors and logged.
        - For other keys, conflicting values are combined into a list.
    """
    merged_endpoint: dict[str, Any] = {}
    for endpoint in endpoints:
        for key, value in endpoint.items():
            # If a different hostname was somehow returned by a vendor
            if key == 'Hostname' and key in merged_endpoint and value['Value'] != merged_endpoint[key]['Value']:
                demisto.error(f"Conflict detected for 'Hostname'. Conflicting dictionaries: {merged_endpoint[key]}, {value}")
            # For other keys, add to list if conflict exists
            elif key in merged_endpoint:
                if isinstance(merged_endpoint[key], list):
                    merged_endpoint[key].append(value)
                else:
                    merged_endpoint[key] = [merged_endpoint[key], value]
            else:
                merged_endpoint[key] = value

    return merged_endpoint


def get_raw_endpoints(output_keys: list[str], raw_context: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Merges data structures from different output keys into a single endpoint.

    This function processes data from different sources with varying structures
    and merges it into a list of dictionaries. Each dictionary represents a single
    endpoint, combining data from different keys.

    Args:
        output_keys (list of str): A list of strings representing the keys to access
                                   in the dictionaries within `raw_context`.
        raw_context (list of dict): A list of dictionaries where each dictionary
                                    contains data from different sources.

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

        merge_data(output_keys, raw_context)
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

        merge_data(output_keys, raw_context)
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
        for grouped_objects in zip(*lists_of_objects):
            raw_endpoint = {}
            for raw_data in grouped_objects:
                raw_endpoint.update(raw_data)
            raw_endpoints.append(raw_endpoint)

    return raw_endpoints


def create_endpoints(raw_endpoints: list[dict[str, Any]], output_mapping: dict | Callable, brand: str) -> list[dict[str, Any]]:
    """
    Creates a list of endpoint dictionaries from the raw endpoint data.
    Args:
        raw_endpoints (list[dict[str, Any]]): The raw endpoint data to be processed.
        output_mapping (dict | Callable): A dictionary or a callable that maps the raw data to the desired output format.
        brand (str): The brand associated with the endpoints.

    Returns:
        list[dict[str, Any]]: A list of endpoint dictionaries.
    """
    endpoints = []
    for raw_endpoint in raw_endpoints:
        output_map = output_mapping(raw_endpoint) if callable(output_mapping) else output_mapping
        endpoints.append(create_endpoint(raw_endpoint, output_map, brand))
    return endpoints


def entry_context_to_endpoints(command: Command, entry_context: list) -> list[dict[str, Any]]:
    """
    Processes the entry context and generates a list of endpoint dictionaries.
    Args:
        command (Command): A Command object containing the necessary configuration for the endpoint generation.
        entry_context (list): The entry context data to be processed.

    Returns:
        list[dict[str, Any]]: A list of endpoint dictionaries generated from the entry context.
    """
    raw_endpoints = get_raw_endpoints(command.output_keys, entry_context)
    endpoints = create_endpoints(raw_endpoints, command.output_mapping, command.brand)
    demisto.debug(f'Returning {len(endpoints)} endpoints')
    return endpoints


def merge_endpoint_outputs(endpoint_outputs: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """
    Merges a list of lists of endpoint dictionaries into a single list of merged endpoint dictionaries.
    Args:
        endpoint_outputs (list[list[dict[str, Any]]]): A list of lists of endpoint dictionaries, where each inner list
        represents the endpoint data from a different source.

    Returns:
        list[dict[str, Any]]: A list of merged endpoint dictionaries.
    """
    merged_endpoints = []
    for index in range(max(map(len, endpoint_outputs), default=0)):
        unmerged_endpoints = [safe_list_get(lst, index, {}) for lst in endpoint_outputs]
        if unmerged_endpoints:
            merged_endpoint = merge_endpoints(unmerged_endpoints)
            merged_endpoints.append(merged_endpoint)

    return merged_endpoints


def create_endpoints_not_found_list(endpoints: list[dict[str, Any]], zipped_args: list[tuple]) -> list[dict[str, str]]:
    """
    Identify endpoints not found in the provided endpoints.

    Args:
        endpoints (list of dict): List of endpoint dictionaries with 'Hostname', 'ID', and 'IPAddress' keys.
        zipped_args (list of tuple): List of tuples, each containing (agent_id, agent_ip, agent_hostname).

    Returns:
        list of dict: List of dictionaries with 'Key' for agents not found, containing comma-separated agent_id, agent_ip,
        and agent_hostname.
    """
    endpoints_not_found = []
    hostnames = set()
    ids = set()
    ips = set()
    for endpoint in endpoints:
        hostnames_list = [hostname['Value'] for hostname in to_list(endpoint.get('Hostname'))]
        ids_list = [id['Value'] for id in to_list(endpoint.get('ID'))]
        ips_list = [ip['Value'] for ip in to_list(endpoint.get('IPAddress'))]
        hostnames.update(hostnames_list)
        ids.update(ids_list)
        ips.update(ips_list)
    for agent_id, agent_ip, agent_hostname in zipped_args:
        if agent_id not in ids and agent_ip not in ips and agent_hostname not in hostnames:
            keys = (agent_id, agent_ip, agent_hostname)
            endpoints_not_found.append({'Key': ', '.join([key for key in keys if key])})
    return endpoints_not_found


def extra_hop_mapping(outputs: dict[str, Any]) -> dict[str, str]:
    output_mapping = {
        'Macaddr': 'MACAddress',
        'Vendor': 'Vendor',
        'Id': 'ID',
        'DhcpName': 'DHCPServer',
        'DnsName': 'Domain'
    }
    if outputs.get('Ipaddr6', None) and not outputs.get('Ipaddr4', None):
        output_mapping['Ipaddr6'] = 'IPAddress'
    else:
        output_mapping['Ipaddr4'] = 'IPAddress'
    return output_mapping


def cylance_filtering(endpoints: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    filtered_endpoints = []
    hostnames = to_list(args.get('agent_hostname', []))
    if not hostnames:
        return endpoints
    for endpoint in endpoints:
        endpoint_hostname = endpoint['Hostname']['Value']
        if endpoint_hostname in hostnames:
            filtered_endpoints.append(endpoint)
    return filtered_endpoints


def active_directory_post(endpoints: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    fixed_endpoints = []
    for endpoint in endpoints:
        endpoint_hostname = endpoint['Hostname']['Value']
        if isinstance(endpoint_hostname, str):
            fixed_endpoints.append(endpoint)
        elif isinstance(endpoint_hostname, list) and len(endpoint_hostname) == 1:
            endpoint['Hostname']['Value'] = endpoint_hostname[0]
            fixed_endpoints.append(endpoint)
        else:
            raise ValueError('Invalid hostname')
    return fixed_endpoints


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_hostnames = argToList(args.get("agent_hostname", []))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", []))
        module_manager = ModuleManager(demisto.getModules(), brands_to_run)

        if not any((agent_ids, agent_ips, agent_hostnames)):
            raise ValueError(
                "At least one of the following arguments must be specified: agent_id, agent_ip or agent_hostname."
            )

        endpoint_outputs_list: list[dict[str, Any]] = []
        endpoints_not_found_list: list[dict] = []

        command_runner, single_args_commands, list_args_commands = initialize_commands(module_manager)
        zipped_args: list[tuple] = list(zip_longest(agent_ids, agent_ips, agent_hostnames, fillvalue=''))

        endpoint_outputs_list, command_results_list = run_single_args_commands(
            zipped_args, single_args_commands, command_runner, verbose, endpoint_outputs_list
        )

        endpoint_outputs_list, command_results_list = run_list_args_commands(
            list_args_commands, command_runner, agent_ids, agent_ips, agent_hostnames, endpoint_outputs_list, verbose
        )

        if len(endpoint_outputs_list) < len(zipped_args):
            endpoints_not_found_list.extend(create_endpoints_not_found_list(endpoint_outputs_list, zipped_args))

        if endpoints_not_found_list:
            command_results_list.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) not found",
                        headers=["Key"],
                        t=endpoints_not_found_list,
                    )
                )
            )
        if endpoint_outputs_list:
            command_results_list.append(
                CommandResults(
                    outputs_prefix="Endpoint",
                    outputs_key_field="Hostname.Value",
                    outputs=endpoint_outputs_list,
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) data",
                        t=endpoint_outputs_list,
                        headers=["ID", "IPAddress", "Hostname"],
                        removeNull=True,
                    ),
                )
            )
        return_results(command_results_list)

    except Exception as e:
        return_error(f"Failed to execute get-endpoint-data. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
