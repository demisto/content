from CommonServerPython import *
from itertools import zip_longest
from enum import StrEnum


""" BRANDS ENUM """


class Brands(StrEnum):
    """
    Enum representing different integration brands.
    """

    FIREEYE_HX_V2 = "FireEyeHX v2"
    CROWDSTRIKE_FALCON = "CrowdstrikeFalcon"
    CORTEX_CORE_IR = "Cortex Core - IR"
    MICROSOFT_DEFENDER_ADVANCED_THREAT_PROTECTION = "Microsoft Defender Advanced Threat Protection"

    @classmethod
    def get_all_values(cls) -> list[str]:
        """
        Returns a list of all string values defined in the Enum.
        """
        return [member.value for member in cls]


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
            brand=Brands.CORTEX_CORE_IR,
            name="core-isolate-endpoint",
            arg_mapping={"endpoint_id": "endpoint_id"},
        ),
        Command(
            brand=Brands.CROWDSTRIKE_FALCON,
            name="cs-falcon-contain-host",
            arg_mapping={"ids": "endpoint_id"},
        ),
        Command(
            brand=Brands.FIREEYE_HX_V2,
            name="fireeye-hx-host-containment",
            arg_mapping={"agentId": "endpoint_id", "hostName": "endpoint_hostname"},  # command can use agentId or hostName
        ),
        Command(
            brand="Microsoft Defender ATP",  # this name is used in get-endpoint-data script,
            name="microsoft-atp-isolate-machine",
            arg_mapping={"machine_id": "endpoint_id"},
            hard_coded_args={"isolation_type": "Full", "comment": "Isolated endpoint with IsolateEndpoint script."},
        ),
    ]
    return commands


""" HELPER FUNCTIONS """


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
    is_isolated = endpoint_data.get("IsIsolated", "No")
    if is_isolated == "No":
        return False

    message = "The endpoint is already isolated."
    create_message_to_context_and_hr(
        is_isolated=True, endpoint_args=endpoint_args, result="Success", message=message, endpoint_output=endpoint_output
    )
    return True


def create_message_to_context_and_hr(
    is_isolated: bool, endpoint_args: dict, result: str, message: str, endpoint_output: dict
) -> None:
    """
    Generates a structured message for context and human-readable outputs.

    Args:
        is_isolated (bool): Whether the endpoint is isolated.
        endpoint_args (dict): A dictionary containing endpoint details such as hostname, ID, or IP.
        result (str): The result status, e.g., "Success" or "Fail".
        message (str): A message explaining the result.
        endpoint_output (dict): A list to store the structured output for context.
    """
    endpoint_hostname = endpoint_args.get("endpoint_id") or endpoint_args.get("endpoint_ip")
    brand = endpoint_args.get("endpoint_brand", "")
    if brand == "Microsoft Defender ATP":  # convert brand
        brand = Brands.MICROSOFT_DEFENDER_ADVANCED_THREAT_PROTECTION

    endpoint_output["Endpoint"] = endpoint_hostname
    endpoint_output["Result"] = result
    endpoint_output["Source"] = brand
    endpoint_output["Message"] = message
    endpoint_output["Isolated"] = "Yes" if is_isolated else "No"


def are_there_missing_args(command: Command, endpoint_args: dict, endpoint_output: dict) -> bool:
    """
    Checks if all required arguments are existing in the provided arguments.

    Args:
        command (Command): The command to use for checking the required arguments.
        endpoint_args (dict): A dictionary containing the provided arguments.

    Returns:
        bool: True if all expected arguments are missing, False otherwise.
    """
    if not command.arg_mapping:  # If there are no expected args, return False
        return False
    is_missing_args = all(
        endpoint_args.get(key, "") == "" for key in command.arg_mapping.values()
    )  # checks if *all* args are missing
    if is_missing_args:
        demisto.debug(f"Missing the next args {endpoint_args} for command.name")
        create_message_to_context_and_hr(
            is_isolated=False,
            endpoint_args=endpoint_args,
            result="Fail",
            message=f"Missing args for {command.name}.",
            endpoint_output=endpoint_output,
        )
        return True
    return False


def map_args(command: Command, args: dict) -> dict:
    """
    Maps provided arguments to their expected keys based on a given mapping.

    Args:
        command (Command): The command that its args need to be mapped.
        args (dict): A dictionary containing the provided arguments.

    Returns:
        dict: A dictionary with mapped arguments, using expected keys with corresponding values from args.
    """
    mapped_args = {k: args.get(v, "") for k, v in command.arg_mapping.items()}
    if command.hard_coded_args:
        mapped_args.update(command.hard_coded_args)
    return mapped_args


def map_zipped_args(endpoint_ids: list, endpoint_ips: list) -> list:
    """
    Combines agent IDs and IPs into a list of dictionaries.

    Args:
        endpoint_ids (list): A list of agent IDs.
        endpoint_ips (list): A list of agent IPs.

    Returns:
        list: A list of dictionaries, each containing 'endpoint_id' and 'endpoint_ip'.
    """
    return [
        {"endpoint_id": endpoint_id, "endpoint_ip": endpoint_ip}
        for endpoint_id, endpoint_ip in zip_longest(endpoint_ids, endpoint_ips, fillvalue="")
    ]


def check_missing_executed_args_in_output(zipped_args: list, valid_args: list, outputs: list) -> None:
    """
    Checks if any of the given agent details (ID, IP) exist in a list of valid arguments.
    If no match is found, a failure message is added to the context and human-readable outputs.

    Args:
        zipped_args (list): A list of dictionaries, each containing 'endpoint_id', 'endpoint_ip'.
        valid_args (list): A list of dictionaries representing valid agents with corresponding details.
        outputs (list): A list to store structured output results.
    """
    for args in zipped_args:
        endpoint_id = args.get("endpoint_id", "")
        endpoint_ip = args.get("endpoint_ip", "")
        are_args_found = False
        for entry in valid_args:
            demisto.debug(f"Got {entry=}, and comparing it to {endpoint_id=} and {endpoint_ip=}")
            # Checks if any of the args exists in valid_args
            if (endpoint_id and entry.get("endpoint_id") == endpoint_id) or (
                endpoint_ip and entry.get("endpoint_ip") == endpoint_ip
            ):
                are_args_found = True
        if not are_args_found:
            endpoint_context_output: dict = {}

            create_message_to_context_and_hr(
                is_isolated=False,
                endpoint_args=args,
                result="Fail",
                message="Did not find information on endpoint in any available brand.",
                endpoint_output=endpoint_context_output,
            )
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
    return {
        "endpoint_id": endpoint_data.get("ID", ""),
        "endpoint_ip": endpoint_data.get("IPAddress", ""),
        "endpoint_brand": endpoint_data.get("Brand", ""),
        "endpoint_hostname": endpoint_data.get("Hostname", ""),
        "endpoint_message": endpoint_data.get("Message", ""),
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


def handle_raw_response_results(command: Command, raw_response: dict, endpoint_args: dict, endpoint_output: dict) -> None:
    """
    Handles the raw response of a command execution by determining success or failure and updating outputs accordingly.

    Args:
        command (Command): The executed command object.
        raw_response (dict): The raw response returned from the command execution.
        endpoint_args (dict): The arguments used in the command execution.
        endpoint_output (dict): A list to store structured output results.
    """
    endpoint_id = endpoint_args.get("endpoint_id", "")
    if is_error(raw_response):
        demisto.debug(f"Got an error from raw_response with {endpoint_args}")
        create_message_to_context_and_hr(
            is_isolated=False,
            endpoint_args=endpoint_args,
            result="Fail",
            message=f"Failed to isolate {endpoint_id} with command {command.name}." f"Error:{get_error(raw_response)}",
            endpoint_output=endpoint_output,
        )

    else:
        create_message_to_context_and_hr(
            is_isolated=True,
            endpoint_args=endpoint_args,
            result="Success",
            message=f"{endpoint_id} was isolated successfully with command {command.name}.",
            endpoint_output=endpoint_output,
        )


def find_command_by_brand(commands: list[Command], brand: str):
    """
    Finds and returns the command from the list that matches the specified brand.

    Args:
        commands (list): A list of Command objects to search through.
        brand (str): The brand name to match against the command's brand.

    Returns:
        Command: The matching Command object.
    """
    for command in commands:
        if command.brand == brand:
            return command
    return None


def run_commands_for_endpoint(commands: list, endpoint_args: dict, endpoint_output: dict) -> None:  # type: ignore[arg-type,union-attr]
    """
    Processes an endpoint by executing isolation commands and updating outputs accordingly.

    Args:
        commands (list): A list of available commands for isolation.
        endpoint_args (dict): The arguments provided for the isolation operation.
        endpoint_output (dict): A dictionary to store structured output results.
    """
    demisto.debug(f"Got into the run_commands_for_endpoint command with {endpoint_args}")
    command = find_command_by_brand(commands, endpoint_args.get("endpoint_brand", ""))
    if are_there_missing_args(command, endpoint_args, endpoint_output):  # type: ignore[arg-type]
        return
    mapped_args = map_args(command, endpoint_args)
    demisto.debug(f"Executing command {command.name} with {endpoint_args=}")
    raw_response = demisto.executeCommand(command.name, mapped_args)
    demisto.debug(f"Got raw response for execute_command {command.name} with {endpoint_args=}: {raw_response=}")
    handle_raw_response_results(command, raw_response, endpoint_args, endpoint_output)


def prepare_args() -> tuple[dict, list]:
    """
    Prepares and validates the script arguments for endpoint data collection.

    Returns:
        tuple[dict, list]:
            - A dictionary containing the processed endpoint arguments, including a default list of brands if not provided.
            - A list of zipped argument pairs combining endpoint IDs and IPs.
    """
    endpoint_args = demisto.args()
    endpoint_ids = argToList(endpoint_args.get("endpoint_id", []))
    endpoint_ips = argToList(endpoint_args.get("endpoint_ip", []))
    brands_to_run = argToList(endpoint_args.get("brands", []))

    if not any((endpoint_ids, endpoint_ips)):
        raise ValueError("At least one of the following arguments must be specified: endpoint_id or endpoint_ip.")

    if not brands_to_run:
        # In case no brands selected, the default is all brands.
        # We want to send to get-endpoint-data only the brands this script supports.
        endpoint_args["brands"] = Brands.get_all_values()
    zipped_args = map_zipped_args(endpoint_ids, endpoint_ips)
    return endpoint_args, zipped_args


def process_endpoints(endpoint_data_results: list, commands: list[Command]) -> tuple[list, list, list]:
    """
    Processes endpoint data results and executes the appropriate commands for isolation.

    Args:
        endpoint_data_results (list): A list of endpoint data results retrieved from get-endpoint-data.
        commands (list[Command]): A list of Command objects to run on each endpoint.

    Returns:
        tuple[list, list, list]:
            - results (list): A list of command execution results (currently unused).
            - context_outputs (list): A list of context output dictionaries for each processed endpoint.
            - args_from_endpoint_data (list): A list of argument dictionaries built from the endpoint data.
    """
    results: list = []
    context_outputs: list = []
    args_from_endpoint_data: list = []

    for endpoint_data in endpoint_data_results:
        endpoint_context_output: dict = {}

        endpoint_args = get_args_from_endpoint_data(endpoint_data)
        demisto.debug(f"Running with args {endpoint_args=}")
        # Skip the failing endpoints from get-data-endpoint
        if "fail" in endpoint_args.get("endpoint_message", "").lower():
            demisto.debug(f"Skipping endpoint {endpoint_args} because of a failing error from get-endpoint-data.")
            continue

        if is_endpoint_already_isolated(endpoint_data, endpoint_args, endpoint_context_output):
            demisto.debug(f"Skipping endpoint {endpoint_args} because it is already isolated.")
            args_from_endpoint_data.append(endpoint_args)
            context_outputs.append(endpoint_context_output)
            continue

        demisto.debug(f"Continue isolating endpoint {endpoint_args}")
        args_from_endpoint_data.append(endpoint_args)
        run_commands_for_endpoint(commands, endpoint_args, endpoint_context_output)

        context_outputs.append(endpoint_context_output)

    return results, context_outputs, args_from_endpoint_data


def main():  # pragma: no cover
    try:
        endpoint_args, zipped_args = prepare_args()
        commands = initialize_commands()

        executed_command = execute_command(command="get-endpoint-data", args=endpoint_args)
        demisto.debug(f"Response from get-endpoint-data: {executed_command=}")

        endpoint_data_results = structure_endpoints_data(executed_command)

        results, context_outputs, args_from_endpoint_data = process_endpoints(endpoint_data_results, commands)

        # comparing the executed args for isolated-endpoint with the input args
        check_missing_executed_args_in_output(zipped_args, args_from_endpoint_data, context_outputs)

        readable_output = tableToMarkdown(name="IsolateEndpoint Results", t=context_outputs, removeNull=True)
        results.append(
            CommandResults(
                outputs_prefix="IsolateEndpoint",
                outputs_key_field="Endpoint",
                outputs=context_outputs,
                readable_output=readable_output,
            )
        )
        return_results(results)

    except Exception as e:
        return_error(f"Failed to execute isolate-endpoint. Error: {e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
