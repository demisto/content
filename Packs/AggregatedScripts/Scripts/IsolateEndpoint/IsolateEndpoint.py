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
    ):
        """
        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            arg_mapping (dict): A dictionary containing the command arguments. The commands in this script must include at
             least one argument from this dictionary.
            hard_coded_args (dict): Additional arguments to add for the command, arguments with hard-coded values.
        """
        self.brand = brand
        self.name = name
        self.arg_mapping = arg_mapping
        self.hard_coded_args = hard_coded_args


def initialize_commands() -> list:
    """
    Initializes the commands for the Isolate Endpoint.
    """
    commands = [
        Command(
            # Can be used only in XSIAM
            brand='Cortex Core - IR',
            name='core-isolate-endpoint',
            arg_mapping={'endpoint_id': 'endpoint_id'},
        ),
        Command(
            brand='CrowdstrikeFalcon',
            name='cs-falcon-contain-host',
            arg_mapping={'ids': 'endpoint_id'},
        ),
        Command(
            brand='FireEyeHX v2',
            name='fireeye-hx-host-containment',
            arg_mapping={'agentId': 'endpoint_id', 'hostName': 'endpoint_hostname'},  # command can use agentId or hostName
        ),
        Command(
            brand='Microsoft Defender ATP',
            name='microsoft-atp-isolate-machine',
            arg_mapping={'machine_id': 'endpoint_id'},
            hard_coded_args={'isolation_type': 'Full',
                             'comment': 'Isolated endpoint with IsolateEndpoint script.'},
        ),
    ]
    return commands


""" HELPER FUNCTIONS """


def check_inputs_for_command(command: Command, endpoint_output: dict, args: dict) -> bool:
    """
    Validates whether a command can be executed by checking the required arguments.

    Args:
        command (Command): An instance containing the command's metadata and argument mapping.
        endpoint_output (dict): The dictionary to store output results.
        args (dict): The dictionary containing the specific arguments for the command.

    Returns:
        bool: True if the command can be executed, False otherwise.
    """
    missing_args = are_there_missing_args(command, args)  # checks if there are missing args
    if missing_args:
        demisto.debug(f'Missing the next args {missing_args} for command.name')
        create_message_to_context_and_hr(is_isolated=False,
                                         endpoint_args=args,
                                         result='Fail',
                                         message=f'Missing the next args: {missing_args} for {command.name}.',
                                         endpoint_output=endpoint_output)
        return False
    return True


def is_endpoint_already_isolated(endpoint_data: dict, endpoint_args: dict, endpoint_output: dict) -> bool:
    """
    Checks whether an endpoint is isolated already.

    Args:
        endpoint_data (dict): A dictionary containing endpoint details.
        endpoint_args (dict): The arguments used in the command execution.
        endpoint_output (dict): A list to store structured output results.

    Returns:
        bool: True if the endpoint is isolated, False otherwise.
    """
    demisto.debug(f"Got endpoint {endpoint_data} with field isIsolated{endpoint_data.get('IsIsolated')}")
    is_isolated = endpoint_data.get('IsIsolated', 'No')
    if is_isolated == 'Yes':
        message = 'The endpoint is already isolated.'
        create_message_to_context_and_hr(is_isolated=True,
                                         endpoint_args=endpoint_args,
                                         result='Fail',
                                         message=message,
                                         endpoint_output=endpoint_output)
        return True
    return False


def create_message_to_context_and_hr(is_isolated: bool, endpoint_args: dict, result: str, message: str, endpoint_output: dict) \
    -> None:
    """
    Generates a structured message for context and human-readable outputs.

    Args:
        is_isolated (bool): Whether the endpoint is isolated.
        endpoint_args (dict): A dictionary containing endpoint details such as hostname, ID, or IP.
        result (str): The result status, e.g., "Success" or "Fail".
        message (str): A message explaining the result.
        endpoint_output (dict): A list to store the structured output for context.
    """
    endpoint_hostname = endpoint_args.get('endpoint_id') or endpoint_args.get('endpoint_ip') or endpoint_args.get(
        'endpoint_hostname')
    brand = endpoint_args.get('endpoint_brand', '')

    endpoint_output['Endpoint'] = endpoint_hostname
    endpoint_output['Result'] = result
    endpoint_output['Source'] = brand
    endpoint_output['Message'] = message
    if is_isolated:
        endpoint_output["Isolated"] = 'Yes'
    else:
        endpoint_output["Isolated"] = 'No'


def are_there_missing_args(command: Command, args: dict) -> bool:
    """
    Checks if all required arguments are existing in the provided arguments.

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


def map_zipped_args(endpoint_ids: list, endpoint_ips: list) -> list:
    """
    Combines agent IDs, IPs, and hostnames into a list of dictionaries.

    Args:
        endpoint_ids (list): A list of agent IDs.
        endpoint_ips (list): A list of agent IPs.

    Returns:
        list: A list of dictionaries, each containing 'endpoint_id', 'endpoint_ip', and 'endpoint_hostnames'.
    """
    return [
        {'endpoint_id': endpoint_id, 'endpoint_ip': endpoint_ip}
        for endpoint_id, endpoint_ip in zip_longest(endpoint_ids, endpoint_ips, fillvalue='')
    ]


def check_missing_executed_args_in_output(zipped_args: list, valid_args: list, outputs: list) -> None:
    """
    Checks if any of the given agent details (ID, IP, or hostname) exist in a list of valid arguments.
    If no match is found, a failure message is added to the context and human-readable outputs.

    Args:
        zipped_args (list): A list of dictionaries, each containing 'endpoint_id', 'endpoint_ip', and 'endpoint_hostname'.
        valid_args (list): A list of dictionaries representing valid agents with corresponding details.
        outputs (list): A list to store structured output results.
    """
    for args in zipped_args:
        endpoint_id = args.get('endpoint_id', '')
        endpoint_ip = args.get('endpoint_ip', '')
        are_args_found = False
        for entry in valid_args:
            demisto.debug(f"Got {entry=}, and comparing it to {endpoint_id=} and {endpoint_ip=}")
            # Checks if any of the args exists in valid_args
            if (endpoint_id and entry.get('endpoint_id') == endpoint_id) or (endpoint_ip and entry.get('endpoint_ip')
                                                                             == endpoint_ip):
                are_args_found = True
        if not are_args_found:
            endpoint_context_output: dict = {}

            create_message_to_context_and_hr(is_isolated=False,
                                             endpoint_args=args,
                                             result='Fail',
                                             message='Did not find information on endpoint in any available brand.',
                                             endpoint_output=endpoint_context_output)
            outputs.append(endpoint_context_output)


def get_args_from_endpoint_data(endpoint_data: dict) -> dict:
    """
    Extracts agent details from endpoint data and maps them to a dictionary.

    Args:
        endpoint_data (dict): A dictionary containing endpoint details such as hostname, ID, IP address, and brand.

    Returns:
        dict: A dictionary with extracted values, including 'endpoint_id', 'endpoint_hostname',
         'endpoint_ip', and 'endpoint_brand'.
    """
    return {'endpoint_id': endpoint_data.get("ID", ""),
            'endpoint_ip': endpoint_data.get("IPAddress", ""),
            'endpoint_brand': endpoint_data.get("Brand", ""),
            'endpoint_hostname': endpoint_data.get("Hostname", ""),
            'endpoint_message': endpoint_data.get("Message", "")
            }


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


def handle_raw_response_results(command: Command, raw_response: dict, endpoint_args: dict, endpoint_output: dict,
                                verbose: bool) -> CommandResults | None:
    """
    Handles the raw response of a command execution by determining success or failure and updating outputs accordingly.

    Args:
        command (Command): The executed command object.
        raw_response (dict): The raw response returned from the command execution.
        endpoint_args (dict): The arguments used in the command execution.
        endpoint_output (dict): A list to store structured output results.
        verbose (bool): Flag to control verbosity.
    Returns:
        CommandResults | None: If verbose=true, returns the CommandResults for this executed command.
    """
    entry_human_readable = []
    endpoint_id = endpoint_args.get('endpoint_id', '')
    if is_error(raw_response):
        demisto.debug(f"Got an error from raw_response with {endpoint_args}")
        create_message_to_context_and_hr(is_isolated=False,
                                         endpoint_args=endpoint_args,
                                         result='Fail',
                                         message=f'Failed to isolate {endpoint_id} with command {command.name}.'
                                                 f'Error:{get_error(raw_response)}',
                                         endpoint_output=endpoint_output)

    else:
        create_message_to_context_and_hr(is_isolated=True,
                                         endpoint_args=endpoint_args,
                                         result='Success',
                                         message=f'{endpoint_id} was isolated successfully with command {command.name}.',
                                         endpoint_output=endpoint_output)
    # if verbose:
    #     for entry in raw_response:
    #         entry_human_readable.append(entry.get("HumanReadable") or "")
    #     command_human_readable = "\n".join(entry_human_readable)
    #     result_type = EntryType.ERROR if is_error(raw_response) else EntryType.NOTE
    #     command_title = f'!{command.name} {" ".join([f"{arg}={value}" for arg, value in endpoint_args.items() if value])}'
    #     result_message = f"#### {'Error' if is_error(raw_response) else 'Result'} for {command_title}\n{command_human_readable}"
    #     return CommandResults(
    #         readable_output=result_message,
    #         entry_type=result_type,
    #         mark_as_note=True
    #     )
    return None


def find_command_by_brand(commands: list, brand: str):
    for command in commands:
        if command.brand == brand:
            return command
    return None


def run_commands_for_endpoint(commands: list, endpoint_args: dict, endpoint_output: dict, results: list,
                              verbose) -> None:
    """
    Processes an endpoint by executing isolation commands and updating outputs accordingly.

    Args:
        commands (list): A list of available commands for isolation.
        endpoint_args (dict): The arguments provided for the isolation operation.
        endpoint_output (dict): A dictionary to store structured output results.
        results (list): A list to collect the final results from command execution.
        verbose (bool): Flag to control verbosity of debugging information.
    """
    demisto.debug(f"Got into the run_commands_for_endpoint command with {endpoint_args}")
    command = find_command_by_brand(commands, endpoint_args.get('endpoint_brand', ""))

    missing_args = are_there_missing_args(command, endpoint_args)  # checks if there are missing args
    if missing_args:
        demisto.debug(f'Missing the next args {endpoint_args} for command.name')
        create_message_to_context_and_hr(is_isolated=False,
                                         endpoint_args=endpoint_args,
                                         result='Fail',
                                         message=f'Missing args: {missing_args} for {command.name}.',
                                         endpoint_output=endpoint_output)
        return

    mapped_args = map_args(command, endpoint_args)
    demisto.debug(f'Executing command {command.name} with {endpoint_args=}')
    raw_response = demisto.executeCommand(command.name, mapped_args)
    demisto.debug(f'Got raw response for execute_command {command.name} with {endpoint_args=}: {raw_response=}')
    command_results = handle_raw_response_results(command, raw_response, endpoint_args, endpoint_output, verbose)
    if command_results:
        results.append(command_results)


def main():
    try:
        endpoint_args = demisto.args()
        endpoint_ids = argToList(endpoint_args.get("endpoint_id"))
        endpoint_ips = argToList(endpoint_args.get("endpoint_ip"))
        verbose = argToBoolean(endpoint_args.get("verbose", False))
        # brands_to_run = argToList(endpoint_args.get("brands", []))
        commands = initialize_commands()
        zipped_args = map_zipped_args(endpoint_ids, endpoint_ips)

        executed_command = execute_command(command="get-endpoint-data", args=endpoint_args)

        endpoint_data_results = structure_endpoints_data(executed_command)  # TODO
        demisto.debug(f'These are the structured data from structure_endpoints_data {endpoint_data_results}')

        results: list = []
        context_outputs: list = []
        args_from_endpoint_data: list = []

        for endpoint_data in endpoint_data_results:
            endpoint_context_output: dict = {}

            endpoint_args = get_args_from_endpoint_data(endpoint_data)
            demisto.debug(f"Got args {endpoint_args=}")
            if 'fail' in endpoint_args.get('endpoint_message', '').lower():
                # Skip the failing endpoints from get-data-endpoint
                demisto.debug(f"Skipping endpoint {endpoint_args} because of a failing error from get-endpoint-data.")
                continue

            if is_endpoint_already_isolated(endpoint_data, endpoint_args, endpoint_context_output):
                demisto.debug(f"Skipping endpoint {endpoint_args} because it is already isolated.")
                args_from_endpoint_data.append(endpoint_args)
                context_outputs.append(endpoint_context_output)
                continue

            demisto.debug(f"Continue isolating endpoint {endpoint_args}")
            args_from_endpoint_data.append(endpoint_args)
            run_commands_for_endpoint(commands, endpoint_args, endpoint_context_output, results, verbose)

            context_outputs.append(endpoint_context_output)

        # comparing the executed args for isolated-endpoint with the input args
        check_missing_executed_args_in_output(zipped_args, args_from_endpoint_data, context_outputs)

        readable_output = tableToMarkdown(name='IsolateEndpoint Results', t=context_outputs, removeNull=True)
        results.append(CommandResults(
            outputs_prefix='IsolateEndpoint',
            outputs_key_field='EndpointName',
            outputs=context_outputs,
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
