from CommonServerPython import *
from collections.abc import Callable
from itertools import zip_longest

""" COMMAND CLASS """


class Command:
    def __init__(
        self,
        brand: str,
        name: str,
        arg_mapping: dict,
        hard_coded_args: dict = None,
        pre_command_check: Callable = None
    ):
        """
        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            arg_mapping (dict): A dictionary containing the command arguments. The commands in this script must include at
             least one argument from this dictionary.
            hard_coded_args (dict): Additional arguments to add for the command, arguments with hard-coded values.
            pre_command_check (Callable): The function used to check the command before it is executed.
        """
        self.brand = brand
        self.name = name
        self.arg_mapping = arg_mapping
        self.pre_command_check = pre_command_check
        self.hard_coded_args = hard_coded_args


def initialize_commands() -> list:
    """
    Initializes the commands for the Isolate Endpoint.
    """
    commands = [
        Command(
            # Can be used only on XSIAM
            brand='Cortex Core - IR',
            name='core-isolate-endpoint',
            arg_mapping={'endpoint_id': 'agent_id'},
        ),
        # Command(
        #     brand='Cybereason',
        #     name='cybereason-isolate-machine',
        #     arg_mapping={'machine': 'agent_hostname'},
        #     pre_command_check=check_conditions_cybereason_isolate_machine
        # ),
        Command(
            # Can be used only on XSOAR
            brand='Cortex XDR - IR',
            name='xdr-endpoint-isolate',
            arg_mapping={'endpoint_id': 'agent_id'},
        ),
        Command(
            brand='CrowdstrikeFalcon',
            name='cs-falcon-contain-host',
            arg_mapping={'ids': 'agent_id'},
        ),
        Command(
            brand='FireEyeHX v2',
            name='fireeye-hx-host-containment',
            arg_mapping={'agentId': 'agent_id', 'hostName': 'agent_hostname'},  # command can use agentId or hostName
        ),
        Command(
            brand='VMware Carbon Black EDR v2',
            name='cb-edr-quarantine-device',
            arg_mapping={'sensor_id': 'agent_id'},
        ),
        Command(
            brand='Microsoft Defender Advanced Threat Protection',
            name='microsoft-atp-isolate-machine',
            arg_mapping={'machine_id': 'agent_id'},
            hard_coded_args={'isolation_type': 'Full',
                             'comment': 'Isolated endpoint with IsolateEndpoint command.'},
            pre_command_check=check_conditions_microsoft_atp_isolate_machine
        ),
    ]
    return commands


""" MODULE MANAGER CLASS """


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

    def is_brand_in_brands_to_run(self, command: Command) -> bool:
        """
        Checks if the brand associated with the given command is in the list of brands to run.

        Args:
            command (Command): An instance of MappedCommand that contains the brand information.

        Returns:
            bool: True if the brand is in the list of brands to run, or if the list is empty; False otherwise.
        """
        if self._brands_to_run:
            return command.brand in self._brands_to_run
        return True

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
        if not self.is_brand_in_brands_to_run(command):
            return False
        return command.brand in self._enabled_brands


""" PREPROCESS FUNCTIONS """


def check_conditions_cybereason_isolate_machine(endpoint_output: dict, human_readable_outputs: list, args: dict,
                                                endpoint_data: dict) -> bool:
    """
    Validates if the Cybereason isolate machine command can be executed. Checks if required arguments are provided and verifies
    the endpoint's connection using the 'cybereason-is-probe-connected' command..

    Args:
        endpoint_output (dict): Stores endpoint-related data.
        human_readable_outputs (list): Stores human-readable messages.
        args (dict): Command arguments.
        endpoint_data (dict): Contains endpoint details.

    Returns:
        bool: True if execution is allowed, False otherwise.
    """
    cybereason_is_probe_connected_command = Command(
        brand='Cybereason',
        name='cybereason-is-probe-connected',
        arg_mapping={'machine': 'agent_hostname'},
    )
    if are_there_missing_args(cybereason_is_probe_connected_command, args):
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message='Missing args for cybereason-is-probe-connected command',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
        return False
    mapped_args = map_args(cybereason_is_probe_connected_command, args)
    raw_response = execute_command(cybereason_is_probe_connected_command.name, mapped_args)
    demisto.debug(f'Got raw response from cybereason-is-probe-connected command {raw_response}.')
    if is_error(raw_response):
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message='Could not execute cybereason-is-probe-connected command',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
        return False
    if not argToBoolean(raw_response.get('isConnected', {}).get('Value')):
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message='Could not execute cybereason-is-probe-connected command because'
                                                 ' endpoint is not connected.',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
        return False
    return True


def check_conditions_microsoft_atp_isolate_machine(endpoint_output: dict, human_readable_outputs: list, args: dict,
                                                   endpoint_data: dict) -> bool:
    """
    Validates if the Microsoft ATP isolate machine command can be executed.
    The command is allowed only if the endpoint is online and has a valid agent ID. Ensures 'agent_id' is set in args if missing.

    Args:
        endpoint_output (dict): Stores endpoint-related data.
        human_readable_outputs (list): Stores human-readable messages.
        args (dict): Command arguments, possibly updated with 'agent_id'.
        endpoint_data (dict): Contains endpoint status and ID.

    Returns:
        bool: True if execution is allowed, False otherwise.
    """
    status = endpoint_data.get('Status')
    agent_id = endpoint_data.get('ID', {}).get('Value', '')
    if status == 'Offline' or not agent_id:
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message='Can not execute microsoft-atp-isolate-machine command',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
        return False

    if not args.get('agent_id'):  # Appending agent_id as it's required for microsoft-atp-isolate-machine.
        args['agent_id'] = agent_id
    return True


""" HELPER FUNCTIONS """


def check_module_and_args_for_command(module_manager: ModuleManager, command: Command, endpoint_output: dict,
                                      human_readable_outputs: list, args: dict) -> bool:
    """
    Validates whether a command can be executed by checking the brand's availability and required arguments.

    Args:
        module_manager (ModuleManager): The manager responsible for handling integrations and their availability.
        command (Command): An instance containing the command's metadata and argument mapping.
        endpoint_output (dict): The dictionary to store output results.
        human_readable_outputs (list): The list to store human-readable messages.
        args (dict): The dictionary containing the specific arguments for the command.

    Returns:
        bool: True if the command can be executed, False otherwise.
    """
    if not module_manager.is_brand_available(command):  # checks if brand is enable
        demisto.debug(f'Brand {command.brand} is unavailable for command.name')
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message=f'{command.brand} integration is available.',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
        return False

    missing_args = are_there_missing_args(command, args)  # checks if there are missing args
    if missing_args:
        demisto.debug(f'Missing the next args {missing_args} for command.name')
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message=f'Missing the next args: {missing_args} for {command.name}.',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
        return False
    return True


def is_endpoint_isolatable(endpoint_data: dict, args: dict, endpoint_output: dict, human_readable_outputs: list) -> bool:
    """
    Determines whether an endpoint can be isolated based on its current isolation status, and connectivity.

    Args:
        endpoint_data (dict): A dictionary containing endpoint details, including OS version, isolation status, and online status.
        args (dict): The arguments used in the command execution.
        endpoint_output (dict): A list to store structured output results.
        human_readable_outputs (list): A list to store human-readable messages.

    Returns:
        bool: True if the endpoint is eligible for isolation, False otherwise.
    """
    is_isolated = endpoint_data.get('IsIsolated', {}).get('Value', 'No')
    server_status = endpoint_data.get('Status', {}).get('Value', 'Online')

    is_isolation_possible = True
    message = ''

    demisto.debug(f'Checking if endpoint is isolatable with {server_status=}, {is_isolated=}')

    if is_isolated == 'Yes':
        message += 'The endpoint is already isolated.'
        is_isolation_possible = False

    if server_status == 'Offline':
        message += 'The endpoint is offline.'
        is_isolation_possible = False

    if not is_isolation_possible:
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message=message,
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
    return is_isolation_possible


def create_message_to_context_and_hr(args: dict, result: str, message: str, endpoint_output: dict,
                                     human_readable_outputs: list) -> None:
    """
    Generates a structured message for context and human-readable outputs.

    Args:
        args (dict): A dictionary containing endpoint details such as hostname, ID, or IP.
        result (str): The result status, e.g., "Success" or "Fail".
        message (str): A message explaining the result.
        endpoint_output (dict): A list to store the structured output for context.
        human_readable_outputs (list): A list to store human-readable messages.
    """
    endpoint_name = args.get('agent_hostname') or args.get('agent_id') or args.get('agent_ip')
    brand = args.get('agent_brand', '')
    if not endpoint_output:
        endpoint_output['EndpointName'] = endpoint_name
        endpoint_output['Results'] = []

    endpoint_output['Results'].append({
        'Result': result,
        'Brand': brand,
        'Message': message
    })
    human_readable_outputs.append({
        'Result': result,
        'Entity': endpoint_name,
        'Message': message
    })


def are_there_missing_args(command: Command, args: dict) -> bool:
    """
    Checks if all required arguments are missing from the provided arguments.

    Args:
        command (Command): The command to use for checking the required arguments.
        args (dict): A dictionary containing the provided arguments.

    Returns:
        bool: True if all expected arguments are missing, False otherwise.
    """
    if not command.arg_mapping:  # If there are no expected args, return False
        return False
    return all(args.get(key, "") == "" for key in command.arg_mapping.values())  # checks if *all* args are missing


def map_args(command: Command, args: dict) -> dict:
    """
    Maps provided arguments to their expected keys based on a given mapping.

    Args:
        command (Command): The command that its args need to be mapped.
        args (dict): A dictionary containing the provided arguments.

    Returns:
        dict: A dictionary with mapped arguments, using expected keys with corresponding values from args.
    """
    mapped_args = {k: args.get(v, '') for k, v in command.arg_mapping.items()}
    if command.hard_coded_args:
        mapped_args.update(command.hard_coded_args)
    return mapped_args


def map_zipped_args(agent_ids: list, agent_ips: list, agent_hostnames: list) -> list:
    """
    Combines agent IDs, IPs, and hostnames into a list of dictionaries.

    Args:
        agent_ids (list): A list of agent IDs.
        agent_ips (list): A list of agent IPs.
        agent_hostnames (list): A list of agent hostnames.

    Returns:
        list: A list of dictionaries, each containing 'agent_id', 'agent_ip', and 'agent_hostname'.
    """
    return [
        {'agent_id': agent_id, 'agent_hostname': agent_hostname, 'agent_ip': agent_ip}
        for agent_id, agent_ip, agent_hostname in zip_longest(agent_ids, agent_ips, agent_hostnames, fillvalue='')
    ]


def check_which_args_missing_in_output(zipped_args: list, valid_args: list, outputs: list, human_readable_outputs: list) -> None:
    """
    Checks if any of the given agent details (ID, IP, or hostname) exist in a list of valid arguments.
    If no match is found, a failure message is added to the context and human-readable outputs.

    Args:
        zipped_args (list): A list of dictionaries, each containing 'agent_id', 'agent_ip', and 'agent_hostname'.
        valid_args (list): A list of dictionaries representing valid agents with corresponding details.
        outputs (list): A list to store structured output results.
        human_readable_outputs (list): A list to store human-readable messages.
    """
    for args in zipped_args:
        agent_id = args.get('agent_id', '')
        agent_ip = args.get('agent_ip', '')
        agent_hostname = args.get('agent_hostname', '')
        are_args_found = False
        for entry in valid_args:
            if (agent_id and entry.get('agent_id') == agent_id) or \
                (agent_hostname and entry.get('agent_hostname') == agent_hostname) or \
                (agent_ip and entry.get('agent_ip') == agent_ip):  # Checks if any of the args exists in valid_args
                are_args_found = True
        if not are_args_found:
            endpoint_data: dict = {}
            create_message_to_context_and_hr(args=args,
                                             result='Fail',
                                             message='Did not find information on endpoint in any available brand.',
                                             endpoint_output=endpoint_data,
                                             human_readable_outputs=human_readable_outputs)
            outputs.append(endpoint_data)


def get_args_from_endpoint_data(endpoint_data: dict) -> dict:
    """
    Extracts agent details from endpoint data and maps them to a dictionary.

    Args:
        endpoint_data (dict): A dictionary containing endpoint details such as hostname, ID, IP address, and brand.

    Returns:
        dict: A dictionary with extracted values, including 'agent_id', 'agent_hostname', 'agent_ip', and 'agent_brand'.
    """
    agent_hostname = endpoint_data.get('Hostname', {})
    agent_brand = ''
    if isinstance(agent_hostname, dict):
        agent_brand = agent_hostname.get('Source', '')
        agent_hostname = agent_hostname.get('Value', '')
    elif isinstance(agent_hostname, list):
        agent_brand = agent_hostname[0].get('Source', '')
        agent_hostname = agent_hostname[0].get('Value', '')

    agent_id = endpoint_data.get('ID', {})
    if isinstance(agent_id, dict):
        agent_id = agent_id.get('Value', '')
    elif isinstance(agent_id, list):
        agent_id = agent_id[0].get('Value', '')

    agent_ip = endpoint_data.get('IPAddress', {})
    if isinstance(agent_ip, dict):
        agent_ip = agent_ip.get('Value', '')
    elif isinstance(agent_ip, list):
        agent_ip = agent_ip[0].get('Value', '')

    return ({'agent_id': agent_id,
             'agent_hostname': agent_hostname,
             'agent_ip': agent_ip,
             'agent_brand': agent_brand
             })


def structure_endpoints_data(get_endpoint_data_results: dict | list | None) -> list:
    """
    Structures and filters endpoint data, ensuring it is in list format and contains only the entry of the context.

    Args:
        get_endpoint_data_results (dict | list | None): The raw endpoint data, which may be a dictionary, list, or None.

    Returns:
        list: A structured list containing the entry of the context, excluding None values.
    """
    if not get_endpoint_data_results:
        return []

    if not isinstance(get_endpoint_data_results, list):
        get_endpoint_data_results = [get_endpoint_data_results]

    # Remove None values
    structured_list = [item for item in get_endpoint_data_results if item is not None]

    if structured_list and isinstance(structured_list[0], list):
        return structured_list[0]

    return structured_list


def handle_raw_response_results(command: Command, raw_response: dict, args, endpoint_output: dict, human_readable_outputs: list,
                                verbose: bool) -> CommandResults | None:
    """
    Handles the raw response of a command execution by determining success or failure and updating outputs accordingly.

    Args:
        command (Command): The executed command object.
        raw_response (dict): The raw response returned from the command execution.
        args (dict): The arguments used in the command execution.
        endpoint_output (dict): A list to store structured output results.
        human_readable_outputs (list): A list to store human-readable messages.
        verbose (bool): Flag to control verbosity.
    Returns:
        CommandResults | None: If verbose=true, returns the CommandResults for this executed command.
    """
    entry_human_readable = []
    if is_error(raw_response):
        create_message_to_context_and_hr(args=args,
                                         result='Fail',
                                         message=f'Failed to execute command {command.name}.'
                                                 f' Error:{get_error(raw_response)}',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)

    else:
        create_message_to_context_and_hr(args=args,
                                         result='Success',
                                         message=f'Command {command.name} was executed successfully.',
                                         endpoint_output=endpoint_output,
                                         human_readable_outputs=human_readable_outputs)
    if verbose:
        for entry in raw_response:
            entry_human_readable.append(entry.get("HumanReadable") or "")
        command_human_readable = "\n".join(entry_human_readable)
        result_type = EntryType.ERROR if is_error(raw_response) else EntryType.NOTE
        command_title = f'!{command.name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        result_message = f"#### {'Error' if is_error(raw_response) else 'Result'} for {command_title}\n{command_human_readable}"
        return CommandResults(
            readable_output=result_message,
            entry_type=result_type,
            mark_as_note=True
        )
    return None


def run_commands_for_endpoint(commands, args, module_manager, endpoint_data, endpoint_output, human_readable_outputs, results,
                              verbose) -> None:
    """
    Processes an endpoint by executing isolation commands and updating outputs accordingly.

    Args:
        commands (list): A list of available commands for isolation.
        args (dict): The arguments provided for the isolation operation.
        module_manager (ModuleManager): Manages available modules and their execution.
        endpoint_data (dict): The endpoint data retrieved for processing.
        endpoint_output (dict): A dictionary to store structured output results.
        human_readable_outputs (list): A list to store human-readable messages.
        results (list): A list to collect the final results from command execution.
        verbose (bool): Flag to control verbosity of debugging information.
    """
    for command in commands:
        if command.brand != args.get('agent_brand'):
            demisto.debug(f'Skipping command {command.name} with {args=}, as its brand does not match the endpoint brand.')
            continue
        demisto.debug(f'Executing command {command.name} with {args=}')
        if command.pre_command_check and not command.pre_command_check(endpoint_output, human_readable_outputs, args,
                                                                       endpoint_data):
            continue
        if not check_module_and_args_for_command(module_manager, command, endpoint_output, human_readable_outputs, args):
            continue

        mapped_args = map_args(command, args)
        raw_response = demisto.executeCommand(command.name, mapped_args)
        demisto.debug(f'Got raw response for execute_command {command.name} with {args=}: {raw_response=}')
        command_results = handle_raw_response_results(command, raw_response, args, endpoint_output, human_readable_outputs,
                                                      verbose)
        if command_results:
            results.append(command_results)


def search_and_add_endpoint_output(outputs, endpoint_output) -> None:
    """
    Updates the outputs list by adding or merging endpoint results.

    Args:
        outputs (list): A list of dictionaries containing endpoint output records.
        endpoint_output (dict): A dictionary containing an endpoint name and results.

    """
    for output in outputs:
        if output.get('EndpointName') == endpoint_output.get('EndpointName'):
            output.get('Results', []).extend(endpoint_output.get('Results'))
            return
    outputs.append(endpoint_output)


def main():
    try:
        args = demisto.args()
        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_hostnames = argToList(args.get("agent_hostname", []))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get('brands', []))
        module_manager = ModuleManager(demisto.getModules(), brands_to_run)
        commands = initialize_commands()
        zipped_args = map_zipped_args(agent_ids, agent_ips, agent_hostnames)

        # TODO to change
        endpoint_data_results = structure_endpoints_data(
            execute_command(command="get-endpoint-data-modified", args=args)
        )

        demisto.debug(f'These are the results from get_endpoint_data_results execute_command {endpoint_data_results}')

        results: list = []
        outputs: list = []
        human_readable_outputs: list = []
        args_from_endpoint_data: list = []

        for endpoint_data in endpoint_data_results:
            endpoint_output: dict = {}
            args = get_args_from_endpoint_data(endpoint_data)
            args_from_endpoint_data.append(args)

            if not is_endpoint_isolatable(endpoint_data, args, endpoint_output, human_readable_outputs):
                outputs.append(endpoint_output)
                continue
            run_commands_for_endpoint(commands, args, module_manager, endpoint_data, endpoint_output, human_readable_outputs,
                                      results, verbose)
            search_and_add_endpoint_output(outputs, endpoint_output)

        check_which_args_missing_in_output(zipped_args, args_from_endpoint_data, outputs, human_readable_outputs)

        readable_output = tableToMarkdown(name='IsolateEndpoint Results', t=human_readable_outputs, removeNull=True)
        results.append(CommandResults(
            outputs_prefix='IsolateEndpoint',
            outputs_key_field='EndpointName',
            outputs=outputs,
            readable_output=readable_output,
        ))
        return_results(results)

    except Exception as e:
        demisto.debug(f"Failed to execute isolate-endpoint. Error: {str(e)}")
        return_results(CommandResults(
            outputs_prefix='IsolateEndpoint',
            outputs=[],
            readable_output='The Isolate Action did not succeed.'
                            ' Please validate your input or check if the machine is already in an Isolate state.'
                            ' The Device ID/s that were not Isolated',
        ))


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
