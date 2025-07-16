from DemistoClassApiModule import *  # type:ignore [no-redef]  # noqa:E402

from typing import Any

import demistomock as demisto
from CommonServerPython import *


""" CONSTANTS """

BRAND_CORE_IR = "Cortex Core - IR"
BRAND_XDR_IR = "Cortex XDR - IR"
BRAND_MDE = "Microsoft Defender for Endpoint"

HASH_SHA1 = "sha1"
HASH_SHA256 = "sha256"

CORE_COMMAND_PREFIX = "core"
XDR_COMMAND_PREFIX = "xdr"

SUPPORTED_HASH = [HASH_SHA1, HASH_SHA256]
INTEGRATION_FOR_SHA1 = [BRAND_MDE]
INTEGRATION_FOR_SHA256 = [BRAND_CORE_IR, BRAND_XDR_IR]

ENDPOINT_IDS = "endpoint_ids"
FILE_HASH = "file_hash"
FILE_PATH = "file_path"
REQUIRED_FIELDS = [ENDPOINT_IDS, FILE_HASH, FILE_PATH]
""" COMMAND CLASS """


class Command:
    def __init__(self, name: str, args: dict, brand: str | None = None) -> None:
        """
        Initializes a Command object.

        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            brand (str | None): Optional brand associated with the command.
        """
        self.brand: str | None = brand
        self.name: str = name
        self.args: dict = args

    def prepare_human_readable(self, human_readable: str, is_error: bool = False) -> CommandResults:
        """
        Prepare human-readable output for a command execution.

        Args:
            human_readable (str): The human-readable output of the command.
            is_error (bool): Whether the command resulted in an error. Defaults to False.

        Returns:
            CommandResults: CommandResult object with the formatted output.
        """
        if not is_error:
            return CommandResults(readable_output=f"Result for {self}\n{human_readable}")

        return CommandResults(readable_output=f"Error for {self}\n{human_readable}", entry_type=EntryType.ERROR)

    def execute(self) -> tuple[list[dict], list[CommandResults]]:
        """
        Executes the specified command with given arguments, handles any errors, and parses the execution results.

        Args:
            name (str): The name of the command to execute.
            args (dict[str, Any]): A dictionary of arguments to pass to the command.

        Returns:
            tuple[list[dict], list[CommandResults]]: A tuple of entry context dictionaries and human-readable CommandResults.
        """
        demisto.debug(f"Starting to execute command: {self}.")
        execution_results = demisto.executeCommand(self.name, self.args)
        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self}")
            error_message = f"No execution response from command: {self}"
            error_result = self.prepare_human_readable(error_message, is_error=True)
            return [], [error_result]

        entry_context: list[dict] = []
        readable_command_results: list[CommandResults] = []

        demisto.debug(f"Parsing execution response of command: {self}.")

        for result in execution_results:
            if is_error(result):
                readable_command_results.append(self.prepare_human_readable(get_error(result), is_error=True))
                continue

            if human_readable := result.get("HumanReadable"):
                readable_command_results.append(self.prepare_human_readable(human_readable))

            if entry_context_item := result.get("EntryContext"):
                if isinstance(entry_context_item, list):
                    entry_context.extend(entry_context_item)
                else:
                    entry_context.append(entry_context_item)

        demisto.debug(f"Finished parsing execution response of command: {self}.")

        return entry_context, readable_command_results

    def execute_polling(self) -> CommandResults:
        """
        Executes the specified polling command with given arguments, handles any errors, and parses the execution results.

        Args:
            name (str): The name of the command to execute.
            args (dict[str, Any]): A dictionary of arguments to pass to the command.

        Returns:
            tuple[list[dict], list[CommandResults]]: A tuple of entry context dictionaries and human-readable CommandResults.
        """
        demisto.debug(f"Starting to execute polling command: {self}.")
        execution_results = execute_polling_command(self.name, self.args)

        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self}")
            error_message = f"No execution response from command: {self}"
            error_result = self.prepare_human_readable(error_message, is_error=True)
            return error_result

        demisto.debug(f"Execution response from command: {execution_results}")
        outputs = []
        if isinstance(execution_results, list):
            outputs = execution_results[-1].outputs
            if isinstance(outputs, dict):
                outputs = list(outputs.values())[0]
        demisto.debug(f"Finish execution of command: {self}.")

        return CommandResults(outputs_prefix="QuarantineFile", outputs=outputs)

    @property
    def as_formatted_string(self) -> str:
        """
        Formats the command and its argument names and values.

        Returns:
            str: A formatted string of the command name and its arguments.
        """
        formatted_args: list[str] = []
        for arg, value in self.args.items():
            if value:
                if isinstance(value, dict):
                    value = json.dumps(value).replace('"', '\\\\"')
                formatted_args.append(f'{arg}="{value}"')
        return f"!{self.name} {' '.join(formatted_args)}"

    def __str__(self) -> str:
        """Formatted string representation for human-readable output and logging"""
        return self.as_formatted_string

    def __repr__(self) -> str:
        """Raw string representation for debugging"""
        return f"Command: {self.as_formatted_string}"


""" HELPER FUNCTIONS FOR MDE"""


def Microsoft_atp_quarantine_file(
    endpoint_ids: list,
    file_hash: str,
    file_path: str,
    timeout: int,
    human_readable: list[dict],
    context: list[dict],
    verbose_command_results: list[CommandResults],
) -> None:
    pass


""" HELPER FUNCTIONS FOR XDR AND CORE"""


def get_connected_xdr_endpoints(
    command_prefix: str,
    endpoint_ids: list,
    file_hash: str,
    file_path: str,
    human_readable: list[dict],
    context: list[dict],
    verbose_command_results: list[CommandResults],
) -> list[str]:
    """
    Finds all the connected endpoints with an XDR agent on the device, returns them as a list and
    updates the human_readable and the context for each unreachable endpoint.

    Args:
        command_prefix (str): the prefix for the get-endpoints command.
        args (dict): the arguments that were given by the user [endpoint_ids, file_hash, file_path].
        human_readable (list[dict]): list of human_readable.
        context (list[dict]): list of context.
        verbose_command_results (list[CommandResults]): List of CommandResults.

    Returns:
        list[str]: List of connected endpoints IDs.
    """
    demisto.debug("Search for connected endpoints")
    brand = BRAND_CORE_IR if command_prefix == CORE_COMMAND_PREFIX else BRAND_XDR_IR

    endpoints_details = Command(
        name=f"{command_prefix}-get-endpoints",
        args={
            "endpoint_id_list": endpoint_ids,
        },
        brand=brand,
    ).execute()
    # add the command result of each endpoint to the verbose var
    for i in range(len(endpoints_details[1])):
        verbose_command_results.append(endpoints_details[1][i])
    pack_prefix = "Core" if command_prefix == CORE_COMMAND_PREFIX else "PaloAltoNetworksXDR"
    e_details = endpoints_details[0][0].get(f"{pack_prefix}.Endpoint(val.endpoint_id == obj.endpoint_id)") or []
    connected_endpoints = []
    for e_detail in e_details:
        if e_detail.get("endpoint_status") == "CONNECTED":
            connected_endpoints.append(e_detail.get("endpoint_id"))
    demisto.debug(f"connected endpoints {connected_endpoints}")

    unreachable_endpoints = [e_id for e_id in endpoint_ids if e_id not in connected_endpoints]
    demisto.debug(f"update message for unreachable endpoints: {unreachable_endpoints}")
    for e_id in unreachable_endpoints:
        message = "Failed to quarantine file. The endpoint is offline or unreachable."
        human_readable.append({"endpoint_id": e_id, "message": message})
        context.append(
            {
                "file_hash": file_hash,
                "file_path": file_path,
                "endpoint_id": e_id,
                "status": "Failed",
                "message": message,
                "brand": brand,
            }
        )
    return connected_endpoints


def get_endpoints_to_quarantine_with_xdr(
    command_prefix: str,
    endpoint_ids: list,
    file_hash: str,
    file_path: str,
    human_readable: list[dict],
    context: list[dict],
    verbose_command_results: list[CommandResults],
) -> tuple[list[str], dict[str, Command]]:
    """
    Gets the quarantine status for each connected endpoint with an XDR agent.
    For the already quarantined file at endpoint update human_readable and context.

    Args:
        command_prefix (str): the prefix for the get-endpoints command.
        args (dict): the arguments that were given by the user [endpoint_ids, file_hash, file_path].
        human_readable (list[dict]): list of human_readable.
        context (list[dict]): list of context.
        verbose_command_results (list[CommandResults]): List of CommandResults.

    Returns:
        list[str]: list of endpoints that are not already quarantined
        dict[str, Command]: for each endpoint save it's get-quarantine-status command
    """
    endpoint_ids = get_connected_xdr_endpoints(
        command_prefix, endpoint_ids, file_hash, file_path, human_readable, context, verbose_command_results
    )
    brand = BRAND_CORE_IR if command_prefix == CORE_COMMAND_PREFIX else BRAND_XDR_IR

    status_commands = {}
    [
        status_commands.update(
            {
                endpoint_id: Command(
                    name=f"{command_prefix}-get-quarantine-status",
                    args={
                        "endpoint_id": endpoint_id,
                        "file_hash": file_hash,
                        "file_path": file_path,
                    },
                    brand=brand,
                )
            }
        )
        for endpoint_id in endpoint_ids
    ]

    endpoints_to_quarantine = []
    for e_id, command in status_commands.items():
        response = command.execute()
        verbose_command_results.append(response[1])  # type: ignore
        quarantine_status = list(response[0][0].values())[0].get("status")
        if quarantine_status:
            message = "Already quarantined."
            human_readable.append({"endpoint_id": e_id, "message": message})
            context.append(
                {
                    "file_hash": file_hash,
                    "file_path": file_path,
                    "endpoint_id": e_id,
                    "status": "Success" if quarantine_status else "Failed",
                    "message": message,
                    "brand": brand,
                }
            )
        else:
            endpoints_to_quarantine.append(e_id)
    return endpoints_to_quarantine, status_commands


def xdr_quarantine_file(
    command_prefix: str,
    endpoint_ids: list,
    file_hash: str,
    file_path: str,
    timeout: int,
    human_readable: list[dict],
    context: list[dict],
    verbose_command_results: list[CommandResults],
) -> None:
    """
    Quarantines a file and updates the human_readable and the context to contain the status of the file's quarantine.

    Args:
        command_prefix (str): the prefix for the get-endpoints command.
        args (dict): the arguments that were given by the user [endpoint_ids, file_hash, file_path].
        human_readable (list[dict]): list of human_readable.
        context (list[dict]): list of context.
        verbose_command_results (list[CommandResults]): List of CommandResults.
    """
    brand = BRAND_CORE_IR if command_prefix == CORE_COMMAND_PREFIX else BRAND_XDR_IR
    endpoints_to_quarantine, status_commands = get_endpoints_to_quarantine_with_xdr(
        command_prefix, endpoint_ids, file_hash, file_path, human_readable, context, verbose_command_results
    )

    quarantine_results = Command(
        name="core-quarantine-files" if command_prefix == CORE_COMMAND_PREFIX else "xdr-file-quarantine",
        args={
            "endpoint_id_list": endpoints_to_quarantine,
            "file_hash": file_hash,
            "file_path": file_path,
            "timeout_in_seconds": timeout,
        },
        brand=brand,
    ).execute_polling()
    verbose_command_results.append(quarantine_results)
    outputs = quarantine_results.outputs or []
    message = ""
    for res in outputs:  # type: ignore
        quarantine_status = False
        e_id = res.get("endpoint_id")
        status = res.get("status")
        if status == "COMPLETED_SUCCESSFULLY":
            status_command = status_commands.get(e_id)
            if status_command:
                # check the file's quarantine status after attempting to quarantine it
                response = status_command.execute()
                verbose_command_results.append(response[1])  # type: ignore
                val = list(response[0][0].values())[0]
                quarantine_status = val.get("status")
                if quarantine_status:
                    message = "File successfully quarantined."
                else:
                    message = f"Failed to quarantine file. {val.get('error_description')}"
        else:
            message = f"Failed to quarantine file. {res.get('error_description')}"

        if not message:
            message = f"Failed to quarantine file. Failed to execute command for {e_id}"
        human_readable.append({"endpoint_id": e_id, "message": message})
        context.append(
            {
                "file_hash": file_hash,
                "file_path": file_path,
                "endpoint_id": e_id,
                "status": "Success" if quarantine_status else "Failed",
                "message": message,
                "brand": brand,
            }
        )


""" SCRIPT FUNCTION """


def quarantine_file_script(args: dict[str, Any]) -> list[CommandResults]:
    """
    Implements the !quarantine-file command:
     - Selects which integration to use.
     - Runs the quarantine-file command of the selected integration.
     - Reflects the result of the quarantine status to the user.

    Args:
        args (dict): the arguments that were given by the user: endpoint_ids, file_hash, file_path, timeout,
        verbose and quarantine_brands.

    Returns:
        list[CommandResults]: List of CommandResults objects.

    Raises:
        ValueError: If there is missing required args or the file hash is not valid.
        DemistoException: If none of the quarantine_brands has an enabled integration instance.
    """
    demisto.debug(f"Parsing and validating script args: {args}.")
    endpoint_ids: list = remove_duplicates_from_list_arg(args, "endpoint_ids")
    file_hash: str = args.get("file_hash", "")
    file_path: str = args.get("file_path", "")
    timeout: int = arg_to_number(args.get("timeout")) or 300

    quarantine_brands: list = argToList(args.get("quarantine_brands"))
    verbose: bool = argToBoolean(args.get("verbose", False))
    context: list[dict] = []  # data as requested
    human_readable: list = []  # endpoint, message
    verbose_command_results: list[CommandResults] = []

    demisto.debug(f"Check required fields {endpoint_ids=}, {file_hash=}, {file_path=}")
    required_fields = {
        ENDPOINT_IDS: endpoint_ids,
        FILE_HASH: file_hash,
        FILE_PATH: file_path,
    }
    missing_fields = [field for field, value in required_fields.items() if not value]
    if missing_fields:
        raise ValueError(f"Please provide the following missing fields {missing_fields}. Aborting command.")

    hash_type: str = get_hash_type(file_hash).casefold()
    demisto.debug(f"hash type is {hash_type}")

    if hash_type not in SUPPORTED_HASH:
        raise ValueError("A valid file hash must be provided. Supported types are: SHA1 and SHA256")

    enabled_brands = list({module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"})
    demisto.debug(f"Validating overlap between {quarantine_brands=} and {enabled_brands=}.")
    if quarantine_brands and not set(quarantine_brands).intersection(enabled_brands):
        demisto.debug(f"Could not found overlap between {quarantine_brands=} and {enabled_brands=}.")
        raise DemistoException(
            "None of the quarantine brands has an enabled integration instance. Ensure valid integration IDs are specified."
        )

    integration_for_hash = INTEGRATION_FOR_SHA256 if hash_type == HASH_SHA256 else INTEGRATION_FOR_SHA1
    supported_brands = list(set(quarantine_brands) & set(integration_for_hash)) if quarantine_brands else integration_for_hash
    quarantine_brands = list(set(supported_brands) & set(enabled_brands))
    if not quarantine_brands:
        raise DemistoException(
            "Could not find enabled integrations for the requested hash type.\n"
            f"For hash_type {hash_type.upper()} please use {integration_for_hash}."
        )
    if hash_type == HASH_SHA1:
        # supported only by MDE
        Microsoft_atp_quarantine_file(
            endpoint_ids, file_hash, file_path, timeout, human_readable, context, verbose_command_results
        )

    elif hash_type == HASH_SHA256:  # noqa: SIM102
        # supported by Core or XDR
        command_prefix = CORE_COMMAND_PREFIX if BRAND_CORE_IR in quarantine_brands else XDR_COMMAND_PREFIX
        xdr_quarantine_file(
            command_prefix, endpoint_ids, file_hash, file_path, timeout, human_readable, context, verbose_command_results
        )

    summary_command_results = CommandResults(
        outputs_prefix="QuarantineFile",
        outputs_key_field=["endpoint_id", "file_hash"],
        readable_output=tableToMarkdown(
            name=f"Quarantine File Results for: {file_hash}", headers=["endpoint_id", "message"], t=human_readable
        ),
        outputs=context,
    )

    # Create a list of CommandResults objects to return to the incident war room
    command_results = [summary_command_results]
    if verbose:
        # If `verbose` argument is True, CommandResults are returned for every executed command in the script
        command_results.extend(verbose_command_results)

    return command_results


""" MAIN FUNCTION """


def main():  # pragma: no cover
    demisto.debug("Stating to run quarantine-file script.")
    try:
        args = demisto.args()
        command_results = quarantine_file_script(args)
        return_results(command_results)
        demisto.debug(f"Finish running the quarantine-file script. Got context output: {command_results[0].outputs}.")

    except Exception as e:
        demisto.error(f"Encountered error during execution of quarantine-file script: {traceback.format_exc()}.")
        return_error(f"Failed to execute quarantine-file script. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
