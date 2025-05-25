import demistomock as demisto
from CommonServerPython import *

from enum import Enum
from typing import Any
from collections.abc import Callable


""" CONSTANTS """


class Brands(Enum):
    FILE_REPUTATION = "Reputation"  # [Built-in command] `!file` command
    TIM = "TIM"  # [Built-in component] Threat Intelligence Module
    WILDFIRE_V2 = "WildFire-v2"  # [Installable integration] Palo Alto Networks WildFire v2
    CORE_IR = "Cortex Core - IR"  # [Installable integration] Core - Investigation & Response

    def __str__(self):
        """Formatted string representation for context output"""
        return self.value


# All File indicator context fields in CommonServerPython
INDICATOR_FIELD_CLI_NAME_TO_CONTEXT_PATH_MAPPING = {
    "name": "Name",
    "hashes": "Hashes",
    "entryid": "EntryID",
    "size": "Size",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "sha512": "SHA512",
    "ssdeep": "SSDeep",
    "fileextension": "Extension",
    "filetype": "Type",
    "hostname": "Hostname",
    "path": "Path",
    "company": "Company",
    "actor": "Actor",
    "tags": "Tags",
    "feedrelatedindicators": "FeedRelatedIndicators",
    "malwarefamily": "MalwareFamily",
    "campaign": "Campaign",
    "trafficlightprotocol": "TrafficLightProtocol",
    "communitynotes": "CommunityNotes",
    "publications": "Publications",
    "threattypes": "ThreatTypes",
    "imphash": "Imphash",
    "quarantined": "Quarantined",
    "organization": "Organization",
    "associatedfilenames": "AssociatedFileNames",
    "behavior": "Behavior",
    "organizationprevalence": "OrganizationPrevalence",
    "globalprevalence": "GlobalPrevalence",
    "organizationfirstseen": "OrganizationFirstSeen",
    "organizationlastseen": "OrganizationLastSeen",
    "firstseenbysource": "FirstSeenBySource",
    "lastseenbysource": "LastSeenBySource",
    "signatureauthentihash": "Signature.Authentihash",
    "signaturecopyright": "Signature.Copyright",
    "signaturedescription": "Signature.Description",
    "signaturefileversion": "Signature.FileVersion",
    "signatureinternalname": "Signature.InternalName",
    "signatureoriginalname": "Signature.OriginalName",
}


class ContextPaths(Enum):
    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    FILE = Common.File.CONTEXT_PATH
    WILDFIRE_V2_VERDICT = "WildFire.Verdicts(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5)"
    CORE_IR_HASH_ANALYTICS = "Core.AnalyticsPrevalence.Hash"
    VIRUS_TOTAL_FILE = "VirusTotal.File(val.id && val.id == obj.id)"


""" COMMAND CLASS """


class Command:
    def __init__(self, name: str, args: dict, brand: Brands | None = None) -> None:
        """
        Initializes a Command object.

        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            brand (str | None): Optional brand associated with the command.
        """
        self.brand: Brands | None = brand
        self.name: str = name
        self.args: dict = args

    def has_enabled_instance(self, modules: dict) -> bool:
        """
        Checks if command source brand has an enabled integration instance.

        Args:
            modules (dict[str, Any]): Modules context from `demisto.getModules()`.

        Returns:
            bool: True if the command brand has an enabled instance. Otherwise, False.
        """
        if not self.brand:
            demisto.debug(f"Command: {self} is not associated with any integration brand. Command will be executed.")
            return True

        enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}
        demisto.debug(f"Found {len(enabled_brands)} enabled integration brands.")

        if self.brand.value in enabled_brands:
            demisto.debug(f"Command: {self} has an enabled instance of {self.brand}. Command will be executed.")
            return True

        demisto.debug(f"Command: {self} has an no enabled instance of {self.brand}. Command will be skipped.")
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


""" HELPER FUNCTIONS """


def get_file_from_ioc_custom_fields(ioc_custom_fields: dict[str, Any]) -> dict[str, Any]:
    """
    Gets the `File` context dictionary using the `CustomFields` value in the Indicator of Compromise (IOC) record.
    Maps indicator fields in the 'connectedlowercase' format (CLI name) to nested context paths in the 'UpperCamelCase' format.
    Fields not in the `INDICATOR_FIELD_CLI_NAME_TO_CONTEXT_PATH_MAPPING` are mapped to `AdditionalFields.{field_cli_name}`.

    Args:
        ioc_custom_fields (dict[str, Any]): The IOC `CustomFields` dictionary.

    Returns:
        dict: Transformed `File` indicator dictionary.
    """
    mapping = INDICATOR_FIELD_CLI_NAME_TO_CONTEXT_PATH_MAPPING
    output: dict[str, Any] = {}

    for field_cli_name, field_value in ioc_custom_fields.items():
        if field_value in (None, "", [], {}, ()):
            demisto.debug(f"Ignoring IOC custom field: {field_cli_name} with empty value: {field_value}")
            continue

        field_context_path = mapping.get(field_cli_name, f"AdditionalFields.{field_cli_name}")
        if "." not in field_context_path:
            output[field_context_path] = field_value
            continue

        # Handle nested fields like "Signature.Copyright"
        path_parts = field_context_path.split(".")
        current_level = output
        for i, part in enumerate(path_parts, start=1):
            is_last_part: bool = i == len(path_parts)
            if is_last_part:
                current_level[part] = field_value
            else:
                if part not in current_level:
                    current_level[part] = {}
                current_level = current_level[part]

    return assign_params(**output)


def get_from_context(entry_context_item: dict, context_path: ContextPaths) -> list:
    """
    Gets an item from the entry context by key. If the value is not a list, it is converted into a list of one item.

    Args:
        entry_context_item (dict): The entry context item in the command response.
        context_path (ContextPaths): Key of the item in the context dictionary.

    Returns:
        dict: Value from the context.
    """
    value = entry_context_item.get(context_path.value) or []

    return value if isinstance(value, list) else [value]


def flatten_list(nested_list: list[Any]) -> list[Any]:
    """
    Flattens a nested list of lits.

    Args:
        nested_list (list): A list of that could have lists nested inside.

    Returns:
        list: A flattened list.
    """
    flattened: list[Any] = []

    for item in nested_list:
        if isinstance(item, list):
            flattened.extend(flatten_list(item))  # Recursive call for nested lists
        else:
            flattened.append(item)

    return flattened


def add_source_brand_to_values(mapping: dict[str, Any], brand: Brands | str) -> dict:
    """
    Recursively creates nested dictionaries under the mapping key where each dictionary has `Value` and `Source` keys.

    Args:
        mapping (dict[str, Any]): Dictionary containing key-value pairs that need to be transformed.
        brand (Brands | str): The source brand to be added under the `Source` key in the nested dictionaries.

    Returns:
        dict: Dictionary without excluded keys where each key has a dictionary value that contains:
            `Value` - holding the original value from `mapping`
            `Source` - holding the source brand's name.
    """
    demisto.debug(f"Adding Value and Source fields to values in {mapping}.")
    result: dict = {}

    for key, value in mapping.items():
        if isinstance(value, list) and len(value) == 1:
            value = value[0]

        if isinstance(value, dict):
            result[key] = add_source_brand_to_values(value, brand)
        else:
            result[key] = {"Value": value, "Source": str(brand)}

    return result


def merge_context_outputs(per_command_context: dict[str, Any]) -> dict[str, Any]:
    """
    Merges multiple dictionaries into a single `File` indicator dictionary.
    It handles nested dictionaries and special cases where a value is a dictionary with `Value` and `Source` keys.

    Args:
        per_command_context (dict[str, Any]): Dictionary of the entry context (value) of each command name (key).

    Returns:
        dict[str, Any]: A merged `File` indicator dictionary.
    """

    def recursive_merge(target: dict, source: dict):
        for key, value in source.items():
            if isinstance(value, dict) and "Value" in value and "Source" in value:
                demisto.debug(f"Key: {key} has 'Value' and 'Source' fields. Appending to list.")
                if key not in target:
                    target[key] = []
                target[key].append(value)

            elif isinstance(value, dict):
                demisto.debug(f"Key: {key} is of type dictionary. Recursively calling function on its value.")
                if key not in target:
                    target[key] = {}
                recursive_merge(target[key], value)

            elif key == "DBotScore":
                demisto.debug(f"Key: {key} is of type list. Extending list.")
                if key not in target:
                    target[key] = []
                target[key].extend(value)

            else:
                demisto.debug(f"Key: {key} has value: {value}. Writing to merged dictionary.")
                target[key] = value

    merged_context_output: dict[str, Any] = {}
    for command_name, command_context_output in per_command_context.items():
        demisto.debug(f"Merging context output of command: {command_name} context: {command_context_output}.")
        recursive_merge(merged_context_output, command_context_output)

    return {ContextPaths.FILE.value: assign_params(**merged_context_output)}


""" COMMAND EXECUTION FUNCTIONS """


def execute_file_reputation(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    Executes the `!file` command and transforms the entry context into a standard context output by extracting the `File` and
    `DBotScore` dictionaries. It also adds `File.VTFileVerdict` field to denote whether the file is malicious or benign.

    Args:
        command (Command): The `!file` command to be executed.

    Returns:
        tuple[dict, list[CommandResults]]: A tuple of the transformed context output, and human-readable command results.
    """
    demisto.debug(f"Starting to execute file reputation command with args: {command.args}.")
    entry_context, readable_command_results = command.execute()

    demisto.debug(
        "Extracting File and DBotScore from file reputation entry context. "
        f"Command returned {len(entry_context)} items in entry context and {len(readable_command_results)} command results."
    )
    context_output: dict[str, Any] = {"DBotScore": []}

    for context_item in entry_context:
        if files := get_from_context(context_item, ContextPaths.FILE):
            for _file in files:
                context_output.update(_file)

        if dbot_scores := get_from_context(context_item, ContextPaths.DBOT_SCORE):
            for dbot_score in dbot_scores:
                dbot_score_brand = dbot_score.get("Vendor", "Unknown")
                context_output["DBotScore"].append(add_source_brand_to_values(dbot_score, brand=dbot_score_brand))

    return assign_params(**context_output), readable_command_results


def execute_wildfire_verdict(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    Executes the `!wildfire-get-verdict` command and transforms the entry context into a standard context output by extracting
    the `File` and `DBotScore` dictionaries. It also adds source brand fields to additional entry context items.

    Args:
        command (Command): The `!wildfire-get-verdict` command to be executed.

    Returns:
        tuple[dict, list[CommandResults]]: A tuple of the transformed context output, and human-readable command results.
    """
    demisto.debug(f"Starting to execute Wildfire verdict command with args: {command.args}.")
    entry_context, readable_command_results = command.execute()

    demisto.debug(
        "Extracting DBotScore and Verdict from Wildfire verdict entry context. "
        f"Command returned {len(entry_context)} items in entry context and {len(readable_command_results)} command results."
    )
    context_output: dict[str, Any] = {"DBotScore": []}

    for context_item in entry_context:
        if dbot_scores := get_from_context(context_item, ContextPaths.DBOT_SCORE):
            for dbot_score in dbot_scores:
                context_output["DBotScore"].append(add_source_brand_to_values(dbot_score, brand=Brands.WILDFIRE_V2))

        # Add additional brand fields to context
        if wild_fire_verdict := get_from_context(context_item, ContextPaths.WILDFIRE_V2_VERDICT):
            context_output["Verdicts"] = add_source_brand_to_values(wild_fire_verdict[0], brand=Brands.WILDFIRE_V2)

    return assign_params(**context_output), readable_command_results


def execute_ir_hash_analytics(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    Executes the `!core-get-hash-analytics-prevalence` command and transforms the entry context into a standard context output by
    extracting the `File` and `DBotScore` dictionaries. It also adds source brand fields to additional entry context items.

    Args:
        command (Command): The `!core-get-hash-analytics-prevalence` command to be executed.

    Returns:
        tuple[dict, list[CommandResults]]: A tuple of the transformed context output, and human-readable command results.
    """
    demisto.debug(f"Starting to execute IR hash analytics command with args: {command.args}.")
    entry_context, readable_command_results = command.execute()

    demisto.debug(
        "Extracting AnalyticsPrevalence from IR hash analytics entry context. "
        f"Command returned {len(entry_context)} items in entry context and {len(readable_command_results)} command results."
    )
    context_output: dict[str, Any] = {}  # No DBotScore in entry context

    # Add brand fields to context
    for context_item in entry_context:
        if hash_analytics := get_from_context(context_item, ContextPaths.CORE_IR_HASH_ANALYTICS):
            context_output["Hash"] = add_source_brand_to_values(hash_analytics[0], brand=Brands.CORE_IR)

    return assign_params(**context_output), readable_command_results


def enrich_with_command(
    command: Command,
    modules: dict[str, Any],
    per_command_context: dict[str, Any],
    verbose_command_results: list[CommandResults],
) -> None:
    """
    Calls the relevant file enrichment command execution function if the command brand has an enabled integration
    instance and adds the context output to the `per_command_context` dictionary and the human-readable CommandResults
    objects to the `verbose_command_results` list.

    Args:
        command (Command): The command to be executed.
        modules (dict[str, Any]): Modules context from `demisto.getModules()`.
        per_command_context (dict[str, Any]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    if not command.has_enabled_instance(modules):
        demisto.debug(f"Skipping command '{command.name}'. The brand '{command.brand}' has no enabled instance.")
        return

    command_execution_function_mapping: dict[str, Callable] = {
        "file": execute_file_reputation,
        "wildfire-get-verdict": execute_wildfire_verdict,
        "core-get-hash-analytics-prevalence": execute_ir_hash_analytics,
    }

    execution_function = command_execution_function_mapping.get(command.name)
    if not execution_function:
        raise ValueError(f"Unknown command: {command.name}.")

    demisto.debug(f"Running enrichment flow with command {command}.")
    context, readable_command_results = execution_function(command)

    per_command_context[command.name] = context
    verbose_command_results.extend(readable_command_results)


""" FLOW STAGES FUNCTIONS """


def search_file_indicator(file_hash: str, per_command_context: dict[str, Any], verbose_command_results: list) -> None:
    """
    Searches for the file indicator using the file hash value in the Thread Intelligence Module (TIM). If found, it transforms
    the Indicator of Compromise (IOC) into a standard context output by extracting the `File` dictionary. It also adds source
    brand fields to additional context items.

    Args:
        file_hash (str): The hash of the file.
        per_command_context (dict[str, Any]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    demisto.debug(f"Starting to search for File indicator with value: {file_hash}.")
    try:
        search_results = IndicatorsSearcher(query=f"type:File and {file_hash}", size=1)

    except Exception as e:
        demisto.debug(f"Error searching for File indicator with value: {file_hash}. Error: {str(e)}.\n{traceback.format_exc()}")
        readable_command_results = CommandResults(
            readable_output=f"#### Error for Search Indicators\n{str(e)}", entry_type=EntryType.ERROR
        )
        verbose_command_results.append(readable_command_results)
        return

    iocs = flatten_list([result.get("iocs") or [] for result in search_results])
    if not iocs:
        demisto.debug(f"Could not find File indicator with value: {file_hash}.")
        readable_command_results = CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
        verbose_command_results.append(readable_command_results)
        return

    demisto.debug(f"Found {len(iocs)} File indicators with value: {file_hash}.")

    ioc_custom_fields = iocs[0].get("CustomFields", {})

    # Handle context output
    file_context = get_file_from_ioc_custom_fields(ioc_custom_fields)
    context_output = add_source_brand_to_values(file_context, brand=Brands.TIM)
    per_command_context["findIndicators"] = assign_params(**context_output)

    # Prepare human-readable output
    table = tableToMarkdown(name="Found Indicators", t=ioc_custom_fields)
    readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")
    verbose_command_results.append(readable_command_results)


def run_external_enrichment(
    file_hash: str,
    hash_type: str,
    modules: dict,
    file_reputation_brands: list[str],
    per_command_context: dict[str, Any],
    verbose_command_results: list,
) -> None:
    """
    Runs the external file enrichment flow by executing the relevant commands from multiple source brands.

    Args:
        file_hash (str): The hash of the file.
        hash_type (str): The type of file hash normalized to lower case; can be 'md5', 'sha1', 'sha256', or 'sha512'.
        modules (dict): Modules context from `demisto.getModules()`.
        file_reputation_brands (list[str]): List of brand names to run, as given in the `enrichment_brands` argument.
        per_command_context (dict[str, Any]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    demisto.debug(f"Starting to run external enrichment flow on file hash: {file_hash}.")

    # A. Run file reputation command - using all relevant brands or according to `enrichment_brands` argument
    file_reputation_command = Command(
        name="file",
        args=assign_params(**{"file": file_hash, "using-brand": ",".join(file_reputation_brands)}),
    )
    enrich_with_command(file_reputation_command, modules, per_command_context, verbose_command_results)

    # B. Run Wildfire Verdict command
    wildfire_verdict_command = Command(
        name="wildfire-get-verdict",
        args={"hash": file_hash},
        brand=Brands.WILDFIRE_V2,
    )
    enrich_with_command(wildfire_verdict_command, modules, per_command_context, verbose_command_results)

    # C. Run Core IR Hash Analytics command - only works with SHA256 hashes
    if hash_type == "sha256":
        hash_analytics_command = Command(
            name="core-get-hash-analytics-prevalence",
            args={"sha256": file_hash},
            brand=Brands.CORE_IR,
        )
        enrich_with_command(hash_analytics_command, modules, per_command_context, verbose_command_results)
    else:
        demisto.debug(f"Skipping running command 'core-get-hash-analytics-prevalence'. Unsupported file hash type: {hash_type}.")

    demisto.debug(f"Finished running external enrichment flow on file hash: {file_hash}.")


def summarize_command_results(
    file_hash: str,
    per_command_context: dict[str, Any],
    verbose_command_results: list[CommandResults],
    external_enrichment: bool,
) -> CommandResults:
    """
    Summarizes the results from all the executed commands.

    Args:
        file_hash (str): The hash of the file.
        per_command_context (dict): A dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
        external_enrichment (bool): Whether to enrich the file indicator from external source brands.

    Returns:
        CommandResults: The CommandResults with a human-readable output summary.
    """
    demisto.debug("Starting to summarize results from all executed commands.")

    summary = {"File": file_hash}

    # Write summary Result
    errors_count = len([result for result in verbose_command_results if result.entry_type == EntryType.ERROR])
    demisto.debug(f"Found {errors_count} errors in command results.")
    if errors_count:
        if errors_count == len(verbose_command_results):
            summary["Result"] = "Failed"  # All results are errors
        else:
            summary["Result"] = "Partial Success"  # Some results are errors
    else:
        summary["Result"] = "Success"  # No errors

    # Write summary Status
    file_found_count = len([value for value in per_command_context.values() if value])
    demisto.debug(f"Found information on file {file_hash} from {file_found_count} sources.")
    summary["Status"] = "Done" if file_found_count > 0 else "Not Found"

    # Write summary Message
    if file_found_count > 0:
        summary["Message"] = f"Found data on file from {file_found_count} sources."
    else:
        summary["Message"] = "Could not find data on file."
        if external_enrichment is False:
            summary["Message"] += " Consider setting external_enrichment=true."

    demisto.debug(f"Summarized results from all executed commands: {summary}.")

    return CommandResults(
        readable_output=tableToMarkdown(name=f"File Enrichment result for {file_hash}", t=summary),
        outputs=merge_context_outputs(per_command_context),
    )


""" SCRIPT FUNCTION """


def file_enrichment_script(args: dict[str, Any]) -> list[CommandResults]:
    """
    Implements `!file-enrichment` script by searching for the File indicator in TIM and (optionally) running external enrichment.
    It then outputs a human-readable summary of the command execution results and returns a consolidated merged `File` context.

    Args:
        args (dict): Script arguments.

    Returns:
        list[CommandResults]: List of CommandResults objects.
    """
    demisto.debug(f"Parsing and validating script args: {args}.")

    external_enrichment: bool = argToBoolean(args.get("external_enrichment", False))
    verbose: bool = argToBoolean(args.get("verbose", False))
    file_reputation_brands: list = argToList(args.get("enrichment_brands"))  # brands to use for `!file` reputation command
    # additional_field: bool = argToBoolean(args.get("additional_fields", False))

    file_hash: str = args.get("file_hash", "")
    hash_type: str = get_hash_type(file_hash).casefold()

    if not file_hash or hash_type == "unknown":
        raise ValueError("A valid file hash must be provided. Supported types are: MD5, SHA1, SHA256, and SHA512.")

    per_command_context: dict = {}
    verbose_command_results: list[CommandResults] = []

    demisto.debug(f"Running Step 1: Search File indicator in TIM with value {file_hash}.")
    search_file_indicator(
        file_hash=file_hash,
        per_command_context=per_command_context,
        verbose_command_results=verbose_command_results,
    )

    if external_enrichment:
        demisto.debug("Getting integration instances on tenant.")
        modules = demisto.getModules()

        demisto.debug(f"Running Step 2: External enrichment commands on {file_hash} using brands: {file_reputation_brands}.")
        run_external_enrichment(
            file_hash=file_hash,
            hash_type=hash_type,
            modules=modules,
            file_reputation_brands=file_reputation_brands,
            per_command_context=per_command_context,
            verbose_command_results=verbose_command_results,
        )

    demisto.debug(f"Running Step 3: Summarizing command results on {file_hash} and consolidating context output.")
    summary_command_results = summarize_command_results(
        file_hash=file_hash,
        per_command_context=per_command_context,
        verbose_command_results=verbose_command_results,
        external_enrichment=external_enrichment,
    )

    # Create a list of CommandResults objects to return to the incident war room
    command_results = [summary_command_results]
    if verbose:
        # If `verbose` argument is True, CommandResults are returned for every executed command in the script
        command_results.extend(verbose_command_results)

    return command_results


""" MAIN FUNCTION """


def main():  # pragma: no cover
    demisto.debug("Stating to run file-enrichment script.")
    try:
        args = demisto.args()
        command_results = file_enrichment_script(args)
        return_results(command_results)
        demisto.debug(f"Finishing running file-enrichment script. Got context output: {command_results[0].outputs}.")

    except Exception as e:
        demisto.error(f"Encountered error during execution of file-enrichment script: {traceback.format_exc()}.")
        return_error(f"Failed to execute file-enrichment script. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
