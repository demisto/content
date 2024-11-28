from CommonServerPython import *
from typing import Any
import itertools


class MappedCommand:
    def __init__(
        self,
        brand: str,
        name: str,
        args_mapping: dict = None,
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
        self.args_mapping = args_mapping

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
        self.modules_context = modules
        self._brands_to_run = brands_to_run
        self._enabled_brands = {
            module.get("brand")
            for module in self.modules_context.values()
            if module.get("state") == "active"
        }

    def is_brand_in_brands_to_run(self, command: MappedCommand) -> bool:
        """
        Checks if the brand associated with the given command is in the list of brands to run.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the brand information.

        Returns:
            bool: True if the brand is in the list of brands to run, or if the list is empty; False otherwise.
        """
        return command.brand in self._brands_to_run if self._brands_to_run else True

    def is_brand_available(self, command: MappedCommand) -> bool:
        """
        Checks if the brand associated with the given command is available.

        This function first checks if the brand is in the list of brands to run. If it is,
        it then checks if the brand is in the set of enabled brands.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the brand information.

        Returns:
            bool: True if the brand is in both the list of brands to run and the set of enabled brands;
                  False otherwise.
        """
        return False if not self.is_brand_in_brands_to_run(command) else command.brand in self._enabled_brands


class CommandRunner:
    def __init__(self, module_manager: ModuleManager, endpoint_args: dict[str, Any], arg_free_commands: list[str]) -> None:
        """
        Initializes the instance of CommandRunner.

        Args:
            module_manager (ModuleManager): An instance of ModuleManager used to manage the modules.
            endpoint_args (Dict[str, Any]): A dictionary containing endpoint arguments.
            arg_free_commands (List[str]): A list of command strings that don't require additional arguments.

        Attributes:
            module_manager (ModuleManager): Stores the provided ModuleManager instance.
            _endpoint_args (Dict[str, Any]): Stores the provided dictionary of endpoint arguments.
            _arg_free_commands (List[str]): Stores the provided list of argument-free commands.
        """
        self.module_manager = module_manager
        self._endpoint_args = endpoint_args
        self._arg_free_commands = arg_free_commands

    def run_command_if_available(self, command: MappedCommand) -> tuple[list, str, list[CommandResults]]:
        """
        Executes a command if it is available and returns the results.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the command information.

        Returns:
            Tuple[List, str, List[CommandResults]]: A tuple containing the command outputs and any relevant results.
        """
        command_results = self._run_execute_command(command)
        command_outputs = self._get_commands_outputs(command_results)
        demisto.debug(f'ran command and returning {command_outputs=}')
        return command_outputs

    def _run_execute_command(self, command: MappedCommand) -> dict[str, Any]:
        """
        Executes a command if the brand is available and returns the results.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the command information.

        Returns:
            Dict[str, Any]: A dictionary containing the command and its results.
        """
        if not self.module_manager.is_brand_available(command):
            demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
            return {'command': command, 'results': []}

        args = {}

        for command_arg_key, endpoint_arg_key in command.args_mapping.items():
            if self._endpoint_args.get(endpoint_arg_key):
                args[command_arg_key] = self._endpoint_args[endpoint_arg_key]

        if not args and command.name not in self._arg_free_commands:
            return {'command': command, 'results': []}

        demisto.debug(f'Running "{command=}" with {args=}')
        command_results = to_list(demisto.executeCommand(command.name, args))
        demisto.debug(f'Command "{command.name}" returned {command_results}')
        return {'command': command, 'results': command_results}

    def _get_commands_outputs(self, command_results: dict[str, Any]):
        """
        Processes the results of a previously executed command and extracts relevant outputs.

        Args:
            command_results (Dict[str, Any]): A dictionary containing the command and its results.

        Returns:
            Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]]]:
                A tuple containing:
                - A list of command context outputs.
                - A human-readable string of the results.
                - A list of command error outputs.
        """
        demisto.debug(f'starting _get_command_outputs with {command_results=}')
        command, result = command_results['command'], command_results['results']
        args = {command_arg_key: self._endpoint_args.get(endpoint_arg_key) for command_arg_key, endpoint_arg_key in
                command.args_mapping.items()}

        command_context_outputs = []
        human_readable_outputs = []
        command_error_outputs = []
        demisto.debug(f'extracting outputs for command "{command.name}" with result {result}')

        for entry in result:
            demisto.debug(f'entry {json.dumps(entry)}')
            command_context_outputs.append(entry.get("EntryContext", {}))
            if is_error(entry):
                command_error_outputs.extend(
                    prepare_human_readable(
                        command.name, args, get_error(entry), is_error=True
                    )
                )
            else:
                human_readable_outputs.append(entry.get("HumanReadable") or "")

        human_readable = "\n".join(human_readable_outputs)
        command_outputs = {
            'command': command,
            'context': command_context_outputs,
            'hr': human_readable,
            'errors': command_error_outputs
        }
        demisto.debug(f'{command_outputs=}')
        return command_context_outputs, human_readable, command_error_outputs


def to_list(var):
    return [var] if not isinstance(var, list) else var


def safe_list_get(l: list, idx: int, default: Any):
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
        return l[idx]
    except IndexError:
        return default


def create_endpoint(command_output: dict[str, Any], output_mapping: dict[str, str], source: str) -> dict[str, Any]:
    """
    Creates an endpoint dictionary from command output, output mapping, and source.

    This function processes the command output and creates a structured endpoint dictionary.
    It maps the command output keys to endpoint keys based on the provided output mapping,
    and includes the source information for each value.

    Args:
        command_output (dict[str, Any]): The output from a command execution.
        output_mapping (dict[str, str]): A mapping of command output keys to endpoint keys.
        source (str): The source of the data.

    Returns:
        dict[str, Any]: A structured endpoint dictionary with values and their sources.
    """
    demisto.debug(f'creating endpoint with {command_output=}, {output_mapping=}, {source=}')

    if not command_output:
        return {}

    endpoint = {}

    for command_output_key, endpoint_key in output_mapping.items():
        endpoint[endpoint_key] = {'value': command_output[command_output_key], 'source': source}
        command_output.pop(command_output_key)

    for key, value in command_output.items():
        endpoint[key] = {'value': value, 'source': source}

    demisto.debug(f'created {endpoint=}')
    return endpoint


def prepare_human_readable(
    command_name: str, args: dict[str, Any], human_readable: str, is_error: bool = False
) -> list[CommandResults]:
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
        list[CommandResults]: A list containing a CommandResults object with the formatted output.
    """
    result = []
    if human_readable:
        command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        if not is_error:
            result_message = f"#### Result for {command}\n{human_readable}"
            result.append(
                CommandResults(readable_output=result_message, mark_as_note=True)
            )
        else:
            result_message = f"#### Error for {command}\n{human_readable}"
            result.append(
                CommandResults(
                    readable_output=result_message,
                    entry_type=EntryType.ERROR,
                    mark_as_note=True,
                )
            )
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

    if raw_context and output_key:
        context = raw_context.get(output_key, {})
        if isinstance(context, list):
            context = context[0] if context else {}
    else:
        context = {}
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
    demisto.debug(f'merging endpoints with {endpoints=}')
    merged_endpoint = {}
    for endpoint in endpoints:
        demisto.debug(f'current endpoint: {endpoint}')
        for key, value in endpoint.items():
            # If a different hostname was somehow returned by a vendor
            if key == 'Hostname' and key in merged_endpoint and value['value'] != merged_endpoint[key]['value']:
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


def run_ad_get_computer(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], dict[str, Any]]:
    command = MappedCommand(brand="Active Directory Query v2", name="ad-get-computer", args_mapping={"name": "agent_hostname"})
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("Endpoint", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    endpoint_output = create_endpoint(outputs, {}, command.brand)

    return readable_outputs_list, endpoint_output


def run_epo_find_system(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], dict[str, Any]]:
    command = MappedCommand(brand='McAfee ePO v2', name='epo-find-system', args_mapping={'searchText': 'agent_hostname'})
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("Endpoint", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    endpoint_output = create_endpoint(outputs, {}, command.brand)

    return readable_outputs_list, endpoint_output


def run_cb_edr_sensors_list(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], dict[str, Any]]:
    command = MappedCommand(
        brand='VMware Carbon Black EDR v2',
        name='cb-edr-sensors-list',
        args_mapping={'hostname': 'agent_hostname', 'id': 'agent_id', 'ip': 'agent_ip'}
    )
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("CarbonBlackEDR.Sensor", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    endpoint_output = create_endpoint(outputs, {'id': 'ID', 'computer_name': 'Hostname', 'status': 'Status'}, command.brand)

    return readable_outputs_list, endpoint_output


def run_xdr_list_risky_hosts(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], dict[str, Any]]:
    command = MappedCommand(brand='Cortex XDR - IR', name='xdr-list-risky-hosts', args_mapping={'host_id': 'agent_id'})
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("PaloAltoNetworksXDR.RiskyHost", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    endpoint_output = create_endpoint(outputs, {'id': 'ID'}, command.brand)

    return readable_outputs_list, endpoint_output


def run_extrahop_devices_search(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[list[CommandResults], dict[str, Any]]:
    command = MappedCommand(brand='ExtraHop v2', name='extrahop-devices-search', args_mapping={'name': 'agent_hostname'})
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("ExtraHop.Device", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
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
    endpoint_output = create_endpoint(outputs, output_mapping, command.brand)

    return readable_outputs_list, endpoint_output


def run_core_get_endpoints(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], dict[str, Any]]:
    command = MappedCommand(
        brand='Cortex Core - IR',
        name='core-get-endpoints',
        args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'}
    )
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("Endpoint", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    output_key = get_output_key("Account", entry_context[0])
    outputs.update(get_outputs(output_key, entry_context[0]))
    endpoint_output = create_endpoint(outputs, {}, command.brand)

    return readable_outputs_list, endpoint_output


def run_xdr_get_endpoints(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], list[dict[str, Any]]]:
    command = MappedCommand(
        brand='Cortex XDR - IR',
        name='xdr-get-endpoints',
        args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'}
    )
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    endpoints = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, []

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    entry = entry_context[0]
    output_key = get_output_key("Endpoint", entry)
    outputs = get_outputs(output_key, entry)
    raw_endpoints = to_list(outputs) if outputs else []
    output_key = get_output_key("Account", entry)
    raw_accounts = to_list(get_outputs(output_key, entry))
    demisto.debug(f'raw_endpoints: {raw_endpoints}')
    for index, raw_endpoint in enumerate(raw_endpoints):
        raw_endpoint.update(raw_accounts[index])
        endpoints.append(create_endpoint(raw_endpoint, {}, command.brand))

    return readable_outputs_list, endpoints


def run_core_list_risky_hosts(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], list[dict[str, Any]]]:
    """
    Run the 'core-list-risky-hosts' command to retrieve risky host data from Cortex Core - IR.

    This function executes the command, processes the results, and creates a list of endpoint objects
    based on the risky hosts retrieved. It maps the 'host_id' argument to 'agent_id' from the input.

    Args:
        command_runner (CommandRunner): An instance of CommandRunner to execute the command.
        endpoint_args (dict[str, Any]): A dictionary containing endpoint arguments.

    Returns:
        tuple[list[CommandResults], list[dict[str, Any]]]: A tuple containing a list of CommandResults
        (readable outputs) and a list of endpoint dictionaries created from the risky hosts data.
    """
    command = MappedCommand(
        brand='Cortex Core - IR',
        name='core-list-risky-hosts',
        args_mapping={'host_id': 'agent_id'}
    )
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    endpoints = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, []

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    entry = entry_context[0]
    output_key = get_output_key("Core.RiskyHost", entry)
    risky_hosts = to_list(get_outputs(output_key, entry))
    for host in risky_hosts:
        endpoints.append(create_endpoint(host, {'id': 'ID'}, command.brand))

    return readable_outputs_list, endpoints


def run_cs_falcon_search_device(command_runner: CommandRunner, endpoint_args: dict[str, Any]) -> tuple[
        list[CommandResults], list[dict[str, Any]]]:
    """
    Run the 'cs-falcon-search-device' command to retrieve device data from CrowdStrike Falcon.

    This function executes the command, processes the results, and creates a list of endpoint objects
    based on the devices retrieved. It maps the 'ids' and 'hostname' arguments to 'agent_id' and
    'agent_hostname' respectively from the input.

    Args:
        command_runner (CommandRunner): An instance of CommandRunner to execute the command.
        endpoint_args (dict[str, Any]): A dictionary containing endpoint arguments.

    Returns:
        tuple[list[CommandResults], list[dict[str, Any]]]: A tuple containing a list of CommandResults
        (readable outputs) and a list of endpoint dictionaries created from the device data.
    """
    command = MappedCommand(
        brand='CrowdstrikeFalcon',
        name='cs-falcon-search-device',
        args_mapping={'ids': 'agent_id', 'hostname': 'agent_hostname'}
    )
    demisto.debug(f'Running {command=} with {endpoint_args=}')
    args = {}
    readable_outputs_list = []
    endpoints = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, []

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    entry = entry_context[0]
    output_key = get_output_key("Endpoint", entry)
    raw_endpoints = to_list(get_outputs(output_key, entry))
    for endpoint in raw_endpoints:
        endpoints.append(create_endpoint(endpoint, {}, command.brand))

    return readable_outputs_list, endpoints


def run_cylance_protect_get_devices(command_runner: CommandRunner, agent_hostnames: list[str]):
    """
    Run the 'cylance-protect-get-devices' command to retrieve device data from Cylance Protect v2.

    This function executes the command, processes the results, and creates a list of endpoint objects
    based on the devices retrieved. It filters the results to include only the devices with hostnames
    matching the provided list.

    Args:
        command_runner (CommandRunner): An instance of CommandRunner to execute the command.
        agent_hostnames (list[str]): A list of hostnames to filter the retrieved devices.

    Returns:
        tuple[list[str], list[dict[str, Any]]]: A tuple containing a list of readable outputs
        and a list of endpoint dictionaries created from the filtered device data.
    """

    command = MappedCommand(brand="Cylance Protect v2", name="cylance-protect-get-devices", args_mapping={})
    demisto.debug(f'Running {command=} with {agent_hostnames=}')
    readable_outputs_list = []
    endpoints = []
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)
    readable_outputs_list.extend(readable_errors)

    if not entry_context:
        return readable_outputs_list, {}

    readable_outputs_list.extend(prepare_human_readable(command.name, {}, human_readable))
    output_key = get_output_key("Endpoint", entry_context[0])
    raw_endpoints = entry_context[0].get(output_key, [])
    for raw_endpoint in raw_endpoints:
        if raw_endpoint['Hostname'] in agent_hostnames:
            endpoints.append(create_endpoint(raw_endpoint, {}, command.brand))

    return readable_outputs_list, endpoints


def run_generic_endpoint_command(command_runner: CommandRunner, endpoint_args: dict[str, str]):
    """
    Run the 'endpoint' command to retrieve endpoint data.

    This function executes the 'endpoint' command, processes the results, and creates an endpoint object
    based on the retrieved data.

    Args:
        command_runner (CommandRunner): An instance of CommandRunner to execute the command.
        endpoint_args (dict[str, str]): A dictionary containing endpoint-specific arguments.

    Returns:
        tuple[list[str], dict[str, Any]]: A tuple containing a list of readable outputs
        and an endpoint dictionary created from the retrieved data.
    """

    args = {}
    readable_outputs_list = []
    command = MappedCommand(brand="", name="endpoint", args_mapping={
                            "id": "agent_id", "ip": "agent_ip", "name": "agent_hostname"})
    entry_context, human_readable, readable_errors = command_runner.run_command_if_available(command)

    if not entry_context:
        return readable_outputs_list, {}

    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        args[command_arg_key] = endpoint_args[endpoint_arg_key] if endpoint_args[endpoint_arg_key] else None

    readable_outputs_list.extend(prepare_human_readable(command.name, args, human_readable))
    output_key = get_output_key("Endpoint", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    endpoint_output = create_endpoint(outputs, {}, command.brand)

    return readable_outputs_list, endpoint_output


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

        command_results_list: list[CommandResults] = []
        endpoint_outputs_list: list[dict[str, Any]] = []
        endpoints_not_found_list: list[str] = []

        # Run a loop for commands that do not take an array as an input
        for agent_id, agent_ip, agent_hostname in list(
                itertools.zip_longest(agent_ids, agent_ips, agent_hostnames, fillvalue="")):
            single_endpoint_outputs = []
            single_endpoint_readable_outputs = []

            command_runner = CommandRunner(
                module_manager=module_manager,
                arg_free_commands=['cylance-protect-get-devices', 'endpoint'],
                endpoint_args={
                    'agent_id': agent_id,
                    'agent_ip': agent_ip,
                    'agent_hostname': agent_hostname
                })

            # commands that rely on any argument
            readable_outputs, endpoint_output = run_cb_edr_sensors_list(
                command_runner,
                {'agent_id': agent_id, 'agent_ip': agent_ip, 'agent_hostname': agent_hostname},
            )

            if endpoint_output:
                single_endpoint_outputs.append(endpoint_output)
            single_endpoint_readable_outputs.extend(readable_outputs)

            readable_outputs, endpoint_output = run_core_get_endpoints(
                command_runner,
                {'agent_id': agent_id, 'agent_ip': agent_ip, 'agent_hostname': agent_hostname},
            )

            if endpoint_output:
                single_endpoint_outputs.append(endpoint_output)
            single_endpoint_readable_outputs.extend(readable_outputs)

            readable_outputs, endpoint_output = run_generic_endpoint_command(
                command_runner,
                {'agent_id': agent_id, 'agent_ip': agent_ip, 'agent_hostname': agent_hostname}
            )

            if endpoint_output:
                single_endpoint_outputs.append(endpoint_output)
            single_endpoint_readable_outputs.extend(readable_outputs)

            # commands that rely on agent_hostname
            if agent_hostname:
                readable_outputs, endpoint_output = run_ad_get_computer(
                    command_runner,
                    {'agent_hostname': agent_hostname}
                )
                if endpoint_output:
                    single_endpoint_outputs.append(endpoint_output)
                single_endpoint_readable_outputs.extend(readable_outputs)

                readable_outputs, endpoint_output = run_epo_find_system(
                    command_runner,
                    {'agent_id': agent_id, 'agent_ip': agent_ip, 'agent_hostname': agent_hostname}
                )

                if endpoint_output:
                    single_endpoint_outputs.append(endpoint_output)
                single_endpoint_readable_outputs.extend(readable_outputs)

                readable_outputs, endpoint_output = run_extrahop_devices_search(
                    command_runner,
                    {'agent_hostname': agent_hostname}
                )

                if endpoint_output:
                    single_endpoint_outputs.append(endpoint_output)
                single_endpoint_readable_outputs.extend(readable_outputs)

            # commands that rely on agent_id
            if agent_id:
                readable_outputs, endpoint_output = run_xdr_list_risky_hosts(
                    command_runner,
                    {'agent_id': agent_id}
                )

                if endpoint_output:
                    single_endpoint_outputs.append(endpoint_output)
                single_endpoint_readable_outputs.extend(readable_outputs)

            if verbose:
                command_results_list.extend(single_endpoint_readable_outputs)

            merged_endpoint = merge_endpoints(single_endpoint_outputs)
            if merged_endpoint:
                endpoint_outputs_list.append(merged_endpoint)
            else:
                endpoints_not_found_list.append(agent_id or agent_ip or agent_hostname)

        demisto.debug(f'ending loop with {command_results_list=}, {endpoint_outputs_list=}, {endpoints_not_found_list=}')

        multiple_endpoint_outputs = []
        multiple_endpoint_readable_outputs = []

        command_runner = CommandRunner(
            module_manager=module_manager,
            arg_free_commands=['cylance-protect-get-devices', 'endpoint'],
            endpoint_args={
                'agent_id': agent_ids,
                'agent_ip': agent_ips,
                'agent_hostname': agent_hostnames
            })

        # Running commands that accept a list as input
        readable_outputs, endpoint_outputs = run_xdr_get_endpoints(
            command_runner,
            {'agent_id': agent_ids, 'agent_ip': agent_ips, 'agent_hostname': agent_hostnames}
        )

        multiple_endpoint_outputs.append(endpoint_outputs)
        multiple_endpoint_readable_outputs.extend(readable_outputs)

        readable_outputs, endpoint_outputs = run_core_list_risky_hosts(
            command_runner,
            {'agent_id': agent_ids, 'agent_ip': agent_ips, 'agent_hostname': agent_hostnames}
        )

        multiple_endpoint_outputs.append(endpoint_outputs)
        multiple_endpoint_readable_outputs.extend(readable_outputs)

        readable_outputs, endpoint_outputs = run_cs_falcon_search_device(
            command_runner,
            {'agent_id': agent_ids, 'agent_hostname': agent_hostnames}
        )

        multiple_endpoint_outputs.append(endpoint_outputs)
        multiple_endpoint_readable_outputs.extend(readable_outputs)

        readable_outputs, endpoint_outputs = run_cylance_protect_get_devices(
            command_runner,
            agent_hostnames
        )
        multiple_endpoint_outputs.append(endpoint_outputs)
        multiple_endpoint_readable_outputs.extend(readable_outputs)

        demisto.debug(f'ending calls with {multiple_endpoint_outputs=}')

        for index in range(max(map(len, multiple_endpoint_outputs), default=0)):
            unmerged_endpoints = [safe_list_get(l, index, {}) for l in multiple_endpoint_outputs]
            demisto.debug(f'merging endoints {unmerged_endpoints=}, {index=}')
            merged_endpoint = merge_endpoints(unmerged_endpoints) if unmerged_endpoints else None
            if merged_endpoint:
                demisto.debug(f'appending {merged_endpoint=}')
                endpoint_outputs_list.append(merged_endpoint)
            else:
                demisto.debug(f'endpoint not found {merged_endpoint=} {agent_ids=} {agent_ips=} {agent_hostnames=}')
                endpoints_not_found_list.append(
                    safe_list_get(agent_ids, index, '')
                    or safe_list_get(agent_ips, index, '')
                    or safe_list_get(agent_hostnames, index, '')
                )

        if endpoints_not_found_list:
            command_results_list.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) not found",
                        headers=["Endpoint ID/IP/Hostname"],
                        t=endpoints_not_found_list,
                    )
                )
            )
        if endpoint_outputs_list:
            command_results_list.append(
                CommandResults(
                    outputs_prefix="Endpoint",
                    outputs_key_field="Hostname.value",
                    outputs=endpoint_outputs_list,
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) data",
                        t=endpoint_outputs_list,
                        headers=["ID", "Ip", "Hostname", "Groups"],
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
