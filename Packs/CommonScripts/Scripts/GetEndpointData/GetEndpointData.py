from CommonServerPython import *
from typing import Any, Callable
from itertools import zip_longest


class MappedCommand:
    def __init__(
        self,
        brand: str,
        name: str,
        output_keys: List[str],
        args_mapping: dict = None,
        output_mapping: dict | Callable = None,
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
    def __init__(self, module_manager: ModuleManager, arg_free_commands: list[str]) -> None:
        """
        Initializes the instance of CommandRunner.

        Args:
            module_manager (ModuleManager): An instance of ModuleManager used to manage the modules.
            arg_free_commands (List[str]): A list of command strings that don't require additional arguments.

        Attributes:
            module_manager (ModuleManager): Stores the provided ModuleManager instance.
            arg_free_commands (List[str]): Stores the provided list of argument-free commands.
        """
        self.module_manager = module_manager
        self.arg_free_commands = arg_free_commands

    def run_command(self, command: MappedCommand, endpoint_args: dict[str, list[str] | str]) -> tuple[
        list[CommandResults],
        list[dict[str, dict]]
    ]:
        demisto.debug(f'Running {command=} with {endpoint_args=}')
        args = prepare_args(command, endpoint_args)
        demisto.debug(f'run_command::args={args}')

        if not self.is_command_runnable(command, args):
            return [], []

        execute_command_results = self.run_execute_command(command, args)
        entry_context, human_readable, readable_errors = self.get_commands_outputs(command.name,
                                                                                             execute_command_results,
                                                                                             args)

        if not entry_context:
            return readable_errors, []

        hr = prepare_human_readable(command.name, args, human_readable)
        context_outputs = extract_context_outputs(command.output_keys, entry_context)
        demisto.debug(f'run_command::{context_outputs=}')
        raw_endpoints = get_raw_endpoints(context_outputs)
        demisto.debug(f'run_command::{raw_endpoints=}')
        endpoints = create_endpoints(raw_endpoints, command.output_mapping, command.brand)
        demisto.debug(f'run_command::{endpoints=}')
        if command.post_processing:
            endpoints = command.post_processing(endpoints, endpoint_args)

        return hr, endpoints

    def is_command_runnable(self, command: MappedCommand, args: dict[str, Any]) -> bool:
        """
        Executes a command if it is available and returns the results.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the command information.
            args (Dict[str, Any]): A dictionary containing the specific arguments for the command.
        Returns:
            Tuple[List, str, List[CommandResults]]: A tuple containing the command outputs and any relevant results.
        """
        demisto.debug(f'is_command_runnable:: {command=}, args={args}')

        if not self.module_manager.is_brand_available(command):
            demisto.debug(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
            return False

        if not args.values() and command.name not in self.arg_free_commands:
            demisto.debug(f'Skipping command "{command.name}" since the provided arguments does not match the command.')
            return False

        return True

    @staticmethod
    def run_execute_command( command: MappedCommand, args: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Executes a command if the brand is available and returns the results.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the command information.
            args (Dict[str, Any]): A dictionary containing the specific arguments for the command.
        Returns:
            Dict[str, Any]: A dictionary containing the command and its results.
        """

        return to_list(demisto.executeCommand(command.name, args))

    @staticmethod
    def get_commands_outputs(command: str, results: list[dict[str, Any]], args: dict[str, Any]) -> tuple[list,str, list]:
        """
        Processes the results of a previously executed command and extracts relevant outputs.

        Args:
            command (MappedCommand): An instance of MappedCommand that contains the command information.
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
        demisto.debug(f'get_commands_outputs for command "{command}" with result {results}')

        for entry in results:
            demisto.debug(f'entry {json.dumps(entry)}')
            command_context_outputs.append(entry.get("EntryContext", {}))
            if is_error(entry):
                command_error_outputs.extend(
                    prepare_human_readable(
                        command, args, get_error(entry), is_error=True
                    )
                )
            else:
                human_readable_outputs.append(entry.get("HumanReadable") or "")

        human_readable = "\n".join(human_readable_outputs)
        command_outputs = {
            'context': command_context_outputs,
            'hr': human_readable,
            'errors': command_error_outputs
        }
        demisto.debug(f'{command_outputs=}')
        return command_context_outputs, human_readable, command_error_outputs


def to_list(var):
    if not var: return []
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
    demisto.debug(f'creating endpoint with {command_output=}, {output_mapping=}, {source=}')

    if not command_output:
        return {}

    endpoint = {}

    for command_output_key, endpoint_key in output_mapping.items():
        endpoint[endpoint_key] = {'Value': command_output[command_output_key], 'Source': source}
        command_output.pop(command_output_key)

    for key, value in command_output.items():
        endpoint[key] = {'Value': value, 'Source': source}

    demisto.debug(f'created {endpoint=}')
    return endpoint


def prepare_args(command: MappedCommand, endpoint_args: dict[str, Any]) -> dict[str, Any]:
    """
    Prepares the arguments dictionary for the command.
    If the endpoint argument value is an empty string or None, the resulting dictionary will not include
    the argument.

    Args:
        command (MappedCommand): The command to prepare for.
        endpoint_args (dict[str, Any]): The arguments received by this aggregation command.
    Returns:
        dict[str, Any]: The arguments dictionary that's right for the command.
    """
    args = {}
    for command_arg_key, endpoint_arg_key in command.args_mapping.items():
        if endpoint_args.get(endpoint_arg_key):
            args[command_arg_key] = endpoint_args.get(endpoint_arg_key)

    return args


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
                if not key: continue
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
    demisto.debug(f'Starting get_outputs for {output_key=} with {raw_context=}')
    full_output_key = get_output_key(output_key, raw_context)
    demisto.debug(f'{full_output_key=}')
    if not (raw_context and full_output_key):
        return {}
    context = raw_context.get(full_output_key, {})
    demisto.debug(f'{context=}')
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


def extract_context_outputs(output_keys: list[str], raw_context: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    demisto.debug(f'extracting context outputs from {output_keys=} with {raw_context=}')
    normalized_data = []

    for context in raw_context:
        # Convert each key's data to a list using to_list
        lists_of_objects = [to_list(get_outputs(key, context)) for key in output_keys]

        # Use zip to group corresponding elements together
        for grouped_objects in zip(*lists_of_objects):
            demisto.debug(f'{grouped_objects =}')
            normalized_data.append(list(grouped_objects))

    return normalized_data


def get_raw_endpoints(context_outputs: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    raw_endpoints = []
    for data_list in context_outputs:
        raw_endpoint = {}
        for raw_data in data_list:
            raw_endpoint.update(raw_data)
        raw_endpoints.append(raw_endpoint)
    return raw_endpoints


def create_endpoints(raw_endpoints: list[dict[str, Any]], output_mapping: dict | Callable, brand: str) -> list[dict[str, Any]]:
    endpoints =[]
    for raw_endpoint in raw_endpoints:
        if isinstance(output_mapping, dict):
            output_mapping = output_mapping
        else:
            output_mapping = output_mapping(raw_endpoint)
        endpoints.append(create_endpoint(raw_endpoint, output_mapping, brand))
    return endpoints


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
        endpoints_not_found_list: list[dict] = []

        command_runner = CommandRunner(
            module_manager=module_manager,
            arg_free_commands=['cylance-protect-get-devices', 'endpoint']
        )

        single_args_command = [
            MappedCommand(
                brand='VMware Carbon Black EDR v2',
                name='cb-edr-sensors-list',
                output_keys=["CarbonBlackEDR.Sensor"],
                args_mapping={'hostname': 'agent_hostname', 'id': 'agent_id', 'ip': 'agent_ip'},
                output_mapping={'id': 'ID', 'computer_name': 'Hostname', 'status': 'Status'}
            ),
            MappedCommand(
                brand='Cortex Core - IR',
                name='core-get-endpoints',
                output_keys=['Endpoint', 'Account'],
                args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'},
                output_mapping={}
            ),
            MappedCommand(
                brand="",
                name="endpoint",
                output_keys=['Endpoint'],
                args_mapping={"id": "agent_id", "ip": "agent_ip", "name": "agent_hostname"},
                output_mapping={}
            ),
            MappedCommand(
                brand="Active Directory Query v2",
                name="ad-get-computer",
                output_keys=["Endpoint"],
                args_mapping={"name": "agent_hostname"},
                output_mapping={}
            ),
            MappedCommand(
                brand='McAfee ePO v2',
                name='epo-find-system',
                output_keys=["Endpoint"],
                args_mapping={'searchText': 'agent_hostname'},
                output_mapping={}
            ),
            MappedCommand(
                brand='ExtraHop v2',
                name='extrahop-devices-search',
                output_keys=["ExtraHop.Device"],
                args_mapping={'name': 'agent_hostname'},
                output_mapping=extra_hop_mapping
            ),
            MappedCommand(
                brand='Cortex XDR - IR',
                name='xdr-list-risky-hosts',
                output_keys=["PaloAltoNetworksXDR.RiskyHost"],
                args_mapping={'host_id': 'agent_id'},
                output_mapping={'id': 'ID'}
            ),
            MappedCommand(
                brand="Cylance Protect v2",
                name="cylance-protect-get-devices",
                output_keys=["Endpoint"],
                args_mapping={},
                output_mapping={},
                post_processing=cylance_filtering
            )
        ]

        list_args_commands = [
            MappedCommand(
                brand='Cortex XDR - IR',
                name='xdr-get-endpoints',
                output_keys=['Endpoint', 'Account'],
                args_mapping={'endpoint_id_list': 'agent_id', 'ip_list': 'agent_ip', 'hostname': 'agent_hostname'},
                output_mapping={}
            ),
            MappedCommand(
                brand='Cortex Core - IR',
                name='core-list-risky-hosts',
                output_keys=["Endpoint"],
                args_mapping={'host_id': 'agent_id'},
                output_mapping={'id': 'ID'},

            ),
            MappedCommand(
                brand='CrowdstrikeFalcon',
                name='cs-falcon-search-device',
                output_keys=["Endpoint"],
                args_mapping={'ids': 'agent_id', 'hostname': 'agent_hostname'},
                output_mapping={},
            )
        ]

        # Run a loop for commands that do not take an array as an input
        for agent_id, agent_ip, agent_hostname in zip_longest(agent_ids, agent_ips, agent_hostnames, fillvalue=""):
            single_endpoint_outputs = []
            single_endpoint_readable_outputs = []

            for command in single_args_command:
                readable_outputs, endpoint_output = command_runner.run_command(
                    command,
                    {
                        'agent_id': agent_id,
                        'agent_ip': agent_ip,
                        'agent_hostname': agent_hostname
                    }
                )

                if endpoint_output:
                    single_endpoint_outputs.append(endpoint_output)

                else:
                    demisto.debug(f'endpoint not found {agent_ids=} {agent_ips=} {agent_hostnames=}')
                    endpoints_not_found_list.append({
                        'Key': agent_id or agent_ip or agent_hostname,
                        'Source': command.brand
                    })
                single_endpoint_readable_outputs.extend(readable_outputs)

            if verbose:
                command_results_list.extend(single_endpoint_readable_outputs)

            for index in range(max(map(len, single_endpoint_outputs), default=0)):
                unmerged_endpoints = [safe_list_get(l, index, {}) for l in single_endpoint_outputs]
                demisto.debug(f'merging endoints {unmerged_endpoints=}, {index=}')
                merged_endpoint = merge_endpoints(unmerged_endpoints) if unmerged_endpoints else None
                if merged_endpoint:
                    demisto.debug(f'appending {merged_endpoint=}')
                    endpoint_outputs_list.append(merged_endpoint)

        demisto.debug(f'ending loop with {command_results_list=}, {endpoint_outputs_list=}, {endpoints_not_found_list=}')

        multiple_endpoint_outputs = []
        multiple_endpoint_readable_outputs = []

        # Running commands that accept a list as input
        for command in list_args_commands:
            readable_outputs, endpoint_output = command_runner.run_command(
                command,
                {
                    'agent_id': ",".join(agent_ids),
                    'agent_ip': ",".join(agent_ips),
                    'agent_hostname': ",".join(agent_hostnames)
                }
            )

            multiple_endpoint_outputs.append(endpoint_output)
            multiple_endpoint_readable_outputs.extend(readable_outputs)

        for index in range(max(map(len, multiple_endpoint_outputs), default=0)):
            unmerged_endpoints = [safe_list_get(l, index, {}) for l in multiple_endpoint_outputs]
            demisto.debug(f'merging endoints {unmerged_endpoints=}, {index=}')
            merged_endpoint = merge_endpoints(unmerged_endpoints) if unmerged_endpoints else None
            if merged_endpoint:
                demisto.debug(f'appending {merged_endpoint=}')
                endpoint_outputs_list.append(merged_endpoint)
            else:
                demisto.debug(f'endpoint not found {merged_endpoint=} {agent_ids=} {agent_ips=} {agent_hostnames=}')
                for command in list_args_commands:
                    endpoints_not_found_list.append({
                        'Key': safe_list_get(agent_ids, index, '')
                        or safe_list_get(agent_ips, index, '')
                        or safe_list_get(agent_hostnames, index, ''),
                        'Source': command.brand
                    })


        if endpoints_not_found_list:
            command_results_list.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        name="Endpoint(s) not found",
                        headers=["Key", "Source"],
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
