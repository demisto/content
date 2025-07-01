from DemistoClassApiModule import *  # type:ignore [no-redef]  # noqa:E402


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

    def has_specified_quarantine_brand(self, quarantine_brands: list[str]) -> bool:
        """
        Checks if command source brand is in the list of quarantine brands.

        Args:
            quarantine_brands (list[str]): List of brand names to run, as given in the `quarantine_brands` argument.

        Returns:
            bool: True if the command brand is in the quarantine brands list. Otherwise, False.
        """
        if not self.brand:
            demisto.debug(f"Command: {self} is not associated with any integration brand.")
            return True

        if not quarantine_brands:
            demisto.debug(f"No specified quarantine brands. Command {self} can run if it has an enabled integration instance.")
            return True

        if self.brand in quarantine_brands:
            demisto.debug(f"Command: {self} with brand {self.brand} is in quarantine brands.")
            return True

        demisto.debug(f"Command: {self} with brand {self.brand} is not in quarantine brands.")
        return False

    def has_enabled_instance(self, enabled_brands: list[str]) -> bool:
        """
        Checks if command source brand has an enabled integration instance.

        Args:
            enabled_brands (list[str]): Set of enabled integration brands.

        Returns:
            bool: True if the command brand has an enabled instance. Otherwise, False.
        """
        if not self.brand:
            demisto.debug(f"Command: {self} is not associated with any integration brand.")
            return True

        if self.brand in enabled_brands:
            demisto.debug(f"Command: {self} with brand {self.brand} has an enabled instance.")
            return True

        demisto.debug(f"Command: {self} with brand {self.brand} has an no enabled instance.")
        return False

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
            return CommandResults(readable_output=f"#### Result for {self}\n{human_readable}")

        return CommandResults(readable_output=f"#### Error for {self}\n{human_readable}", entry_type=EntryType.ERROR)

    def execute(self) -> tuple[list[dict], list[CommandResults]]:
        """
        Executes the specified command with given arguments, handles any errors, and parses the execution results.

        Args:
            command_name (str): The name of the command to execute.
            args (dict[str, Any]): A dictionary of arguments to pass to the command.

        Returns:
            tuple[list[dict], list[CommandResults]]: A tuple of entry context dictionaries and human-readable CommandResults.
        """
        demisto.debug(f"Stating to execute command: {self}.")
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
        demisto.debug(f"Stating to execute command: {self}.")
        execution_results = execute_polling_command(self.name, self.args)

        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self}")
            error_message = f"No execution response from command: {self}"
            error_result = self.prepare_human_readable(error_message, is_error=True)
            return error_result

        outputs = []
        if isinstance(execution_results, list):
            outputs = execution_results[-1].outputs
            if isinstance(outputs, dict):
                outputs = list(outputs.values())[0]

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


""" COMMAND EXECUTION FUNCTIONS """


def Microsoft_atp_stop_and_quarantine_file():
    pass  # not polling


""" HELPER FUNCTIONS """
def get_connected_endpoints(command_prefix: str, args: dict, readable_context: list[dict], context: list[dict],
                               verbose_command_results: list[CommandResults]) -> list[str]:
    # extract invalid or offline endpoints from endpoint_ids and add an error for them
    endpoint_ids: list = argToList(args.get("endpoint_ids"))
    file_hash: str = args.get("file_hash", "")
    file_path: str = args.get("file_path", "")
    
    endpoints_details = Command(
        name=f"{command_prefix}-get-endpoints",
        args={
            "endpoint_id_list": endpoint_ids,
        },
        brand=BRAND_CORE_IR,
    ).execute()
    verbose_command_results.append(endpoints_details)
    pack_prefix = "Core" if command_prefix == CORE_COMMAND_PREFIX else "PaloAltoNetworksXDR"
    e_details = endpoints_details[0][0].get(f"{pack_prefix}.Endpoint(val.endpoint_id == obj.endpoint_id)")
    connected_endpoints = []
    for e_detail in e_details:
        if e_detail.get("endpoint_status") == "CONNECTED":
            connected_endpoints.append(e_detail.get("endpoint_id"))
    
    unrteachable_endpoints = [e_id for e_id in endpoint_ids if e_id not in connected_endpoints]
    for e_id in unrteachable_endpoints:
        message = "Failed to quarantine file. The endpoint is offline or unreachacle"
        readable_context.append({"endpoint_id": e_id, "message": message})
        context.append(
            {
                "file_hash": file_hash,
                "file_path": file_path,
                "endpoint_id": e_id,
                "status": False,
                "result": "Failed",
                "message": message,
                "brand": BRAND_CORE_IR,
            }
        )
    return connected_endpoints

def quarantine_file(command_prefix: str, args: dict, readable_context: list[dict], context: list[dict],
                    verbose_command_results: list[CommandResults]) -> None:
    endpoint_ids: list = argToList(args.get("endpoint_ids"))
    file_hash: str = args.get("file_hash", "")
    file_path: str = args.get("file_path", "")
    timeout: int = arg_to_number(args.get("timeout")) or 300
    endpoint_ids = get_connected_endpoints(command_prefix, args , readable_context, context, verbose_command_results)
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
                    brand=BRAND_CORE_IR,
                )
            }
        )
        for endpoint_id in endpoint_ids
    ]
    for e_id, command in status_commands.items():
        response = command.execute()
        verbose_command_results.append(response)
        for val in response[0][0].values():
            quarantine_status = val.get("status")
        if quarantine_status:
            message = "already quarantined"
        else:
            quarantine_command = Command(
                name=f"core-quarantine-files" if command_prefix==CORE_COMMAND_PREFIX else "xdr-file-quarantine",
                args={
                    "endpoint_id_list": endpoint_ids,
                    "file_hash": file_hash,
                    "file_path": file_path,
                    "timeout_in_seconds": timeout,
                },
                brand=BRAND_CORE_IR,
            )
            quarantine_results = quarantine_command.execute_polling()
            verbose_command_results.append(quarantine_results)
            outputs = quarantine_results.outputs or []
            for res in outputs:
                status = res.get("status")
                if status == "COMPLETED_SUCCESSFULLY":
                    response = command.execute()
                    verbose_command_results.append(response)
                    for val in response[0][0].values():
                        quarantine_status = val.get("status")
                        if quarantine_status:
                            message = "File successfully quarantined"
                        else:
                            message = f"Failed to quarantine file. {val.get('error_description')}"
                else:
                    message = f"Failed to quarantine file. {res.get('error_description')}"
        readable_context.append({"endpoint_id": e_id, "message": message})
        context.append(
            {
                "file_hash": file_hash,
                "file_path": file_path,
                "endpoint_id": e_id,
                "status": quarantine_status,
                "result": "Success" if quarantine_status else "Failed",
                "message": message or "",
                "brand": BRAND_CORE_IR,
            }
        )



""" SCRIPT FUNCTION """


def quarantine_file_script(args: Dict[str, Any]) -> list[CommandResults]:
    demisto.debug(f"Parsing and validating script args: {args}.")
    endpoint_ids: list = argToList(args.get("endpoint_ids"))
    file_hash: str = args.get("file_hash", "")
    file_path: str = args.get("file_path", "")

    if not (endpoint_ids and file_hash and file_path):
        raise ValueError(f"Missing required fields {endpoint_ids=} {file_hash=}, {file_path=}")

    hash_type: str = get_hash_type(file_hash).casefold()

    if not file_hash or hash_type not in SUPPORTED_HASH:
        raise ValueError("A valid file hash must be provided. Supported types are: SHA1 and SHA256")
    quarantine_brands: list = argToList(args.get("quarantine_brands"))
    verbose: bool = argToBoolean(args.get("verbose", False))

    context: list[dict] = []  # data as requested
    readable_context: list = []  # endpoint, message
    verbose_command_results: list[CommandResults] = []
    demisto.debug("Check there is at least one relevant integration configured by hash or brands")
    demisto.debug("Getting integration brands on tenant")
    enabled_brands = list({module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"})
    demisto.debug(f"Found {len(enabled_brands)} enabled integration brands.")
    demisto.debug(f"Validating overlap between quarantine brands: {quarantine_brands} and enabled integration brands.")
    if quarantine_brands and not set(quarantine_brands).intersection(enabled_brands):
        raise DemistoException(
            "None of the enrichment brands has an enabled integration instance." "Ensure valid integration IDs are specified."
        )

    if hash_type == HASH_SHA1:
        # supported only by MDE
        if quarantine_brands and BRAND_MDE not in quarantine_brands:
            demisto.error(f"Hash_type {HASH_SHA1} supported only by {INTEGRATION_FOR_SHA1} integration.")
            # TODO: return error
        elif BRAND_MDE not in enabled_brands:
            demisto.error(
                f"Hash_type {HASH_SHA1} supported only by {INTEGRATION_FOR_SHA1} integration."
                "Please enable the required integratoin"
            )
            # TODO: return error
        # TODO: define command

    elif hash_type == HASH_SHA256:  # noqa: SIM102
        # supported by Core or XDR
        if not quarantine_brands:
            if BRAND_CORE_IR in enabled_brands:
                quarantine_brands = [BRAND_CORE_IR]
            elif BRAND_XDR_IR in enabled_brands:
                #TODO: check why not work
                quarantine_brands = [BRAND_XDR_IR]
            else:
                demisto.error(
                    f"Hash_type {HASH_SHA256} supported by {INTEGRATION_FOR_SHA256} integrations."
                    "Please enable the required integratoin"
                )
                # return error
        if BRAND_CORE_IR in quarantine_brands and BRAND_CORE_IR in enabled_brands:
            quarantine_file(CORE_COMMAND_PREFIX, args, readable_context, context, verbose_command_results)
        elif BRAND_XDR_IR in quarantine_brands and BRAND_XDR_IR in enabled_brands:
            quarantine_file(XDR_COMMAND_PREFIX, args, readable_context, context, verbose_command_results)
        else:
            demisto.error(f"Hash_type {HASH_SHA256} supported only by {INTEGRATION_FOR_SHA256} integration.")

    summary_command_results = CommandResults(
        outputs_prefix="QuarantineFile",
        outputs_key_field=["endpoint_id", "file_path"],
        readable_output=tableToMarkdown(
            name=f"File Quarantine result for file {file_path}", headers=["endpoint_id", "message"], t=readable_context
        ),
        outputs=context,
    )

    demisto.debug("Validate Result")
    # Create a list of CommandResults objects to return to the incident war room
    command_results = [summary_command_results]
    if verbose:
        # If `verbose` argument is True, CommandResults are returned for every executed command in the script
        command_results.extend(verbose_command_results)  # TODO: fill this var

    return command_results


""" MAIN FUNCTION """


def main():  # pragma: no cover
    demisto.debug("Stating to run quarantine-file script.")
    try:
        args = demisto.args()
        command_results = quarantine_file_script(args)
        return_results(command_results)
        demisto.debug(f"Finishing running quarantine-file script. Got context output: {command_results[0].outputs}.")

    except Exception as e:
        demisto.error(f"Encountered error during execution of quarantine-file script: {traceback.format_exc()}.")
        return_error(f"Failed to execute quarantine-file script. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
