import demistomock as demisto
from CommonServerPython import *

from enum import Enum
from typing import Any
from collections.abc import Callable
import itertools


""" CONSTANTS """


class Brands(Enum):
    TIM = "TIM"  # Threat Intelligence Module
    VIRUS_TOTAL_V3 = "VirusTotal (API v3)"  # VirusTotal (API v3) (Partner Contribution)
    WILDFIRE_V2 = "WildFire-v2"  # Palo Alto Networks WildFire v2
    CORE_IR = "Cortex Core - IR"  # Core - Investigation & Response

    def __str__(self):
        """Formatted string representation for context output"""
        return self.value


class ContextPaths(Enum):
    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    FILE = Common.File.CONTEXT_PATH
    WILDFIRE_V2_REPORT = (
        "WildFire.Report(val.SHA256 && val.SHA256 == obj.SHA256 || "
        "val.MD5 && val.MD5 == obj.MD5 || val.URL && val.URL == obj.URL)"
    )
    WILDFIRE_V2_VERDICT = "WildFire.Verdicts(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5)"
    CORE_IR_HASH_ANALYTICS = "Core.AnalyticsPrevalence.Hash"
    VIRUS_TOTAL_FILE = "VirusTotal.File(val.id && val.id == obj.id)"


VIRUS_TOTAL_MALICIOUS_DETECTION_THRESHOLD = 5

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
        enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}

        if self.brand and self.brand.value not in enabled_brands:
            demisto.debug(f"Skipping command '{self.name}'. The brand '{self.brand}' has no enabled instance.")
            return False

        return True

    def prepare_human_readable(self, human_readable: str, is_error: bool = False) -> CommandResults:
        """
        Prepare human-readable output for a command execution.

        Args:
            human_readable (str): The human-readable output of the command.
            is_error (bool): Whether the command resulted in an error. Defaults to False.

        Returns:
            CommandResults: CommandResult object with the formatted output.
        """
        title = f"Result for {self}" if not is_error else f"Error for {self}"

        return CommandResults(
            readable_output=f"#### {title}\n{human_readable}",
            entry_type=EntryType.NOTE if not is_error else EntryType.ERROR,
            mark_as_note=True,
        )

    def execute(self) -> tuple[list[dict], list[CommandResults]]:
        """
        Executes the specified command with given arguments, handles any errors, and parses the execution results.

        Args:
            command_name (str): The name of the command to execute.
            args (dict[str, Any]): A dictionary of arguments to pass to the command.

        Returns:
            tuple[list[dict], list[CommandResults]]: A tuple of entry context dictionaries and human-readable CommandResults.
        """
        demisto.debug(f"Stating to execute command: {self}")
        execution_results = demisto.executeCommand(self.name, self.args)

        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self}")
            error_message = f"No execution response from command: {self}"
            error_result = self.prepare_human_readable(error_message, is_error=True)
            return [], [error_result]

        entry_context: list[dict] = []
        readable_command_results: list[CommandResults] = []

        demisto.debug(f"Parsing execution response of command: {self}")

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

        demisto.debug(f"Finished parsing execution response of command: {self}")

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
        """Formatted string representation for human-readable output"""
        return self.as_formatted_string

    def __repr__(self) -> str:
        """Raw string representation for debugging"""
        return f"Command: {self.as_formatted_string}"


""" HELPER FUNCTIONS """


def get_file_from_ioc_custom_fields(ioc_custom_fields: dict[str, Any]) -> dict:
    """
    Gets the `File` context dictionary using the `CustomFields` value in the Indicator of Compromise (IOC) record.
    Maps indicator fields in the 'connectedlowercase' format to context paths in the 'UpperCamelCase' format.

    Args:
        ioc_custom_fields (dict[str, Any]): The IOC `CustomFields` dictionary.

    Returns:
        dict: Transformed `File` indicator dictionary.
    """
    return assign_params(
        Name=next(iter(ioc_custom_fields.get("associatedfilenames", [])), None),
        AssociatedFileNames=ioc_custom_fields.get("associatedfilenames"),
        Extension=ioc_custom_fields.get("fileextension"),
        Type=ioc_custom_fields.get("filetype"),
        MD5=ioc_custom_fields.get("md5"),
        SHA1=ioc_custom_fields.get("sha1"),
        SHA256=ioc_custom_fields.get("sha256"),
        SHA512=ioc_custom_fields.get("sha512"),
        Size=ioc_custom_fields.get("size"),
        Signature=assign_params(
            Authentihash=ioc_custom_fields.get("signatureauthentihash"),
            Copyright=ioc_custom_fields.get("signaturecopyright"),
            Description=ioc_custom_fields.get("signaturedescription"),
            FileVersion=ioc_custom_fields.get("signaturefileversion"),
            InternalName=ioc_custom_fields.get("signatureinternalname"),
            OriginalName=ioc_custom_fields.get("signatureoriginalname"),
        ),
        SSDeep=ioc_custom_fields.get("ssdeep"),
        Tags=ioc_custom_fields.get("tags"),
    )


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


def get_file_and_dbot_scores_from_context(entry_context: list[dict], brand: Brands | None = None) -> dict:
    """
    Gets the `File` indicator and `DBotScore` objects from the entry context, if present.
    Since the `file_hash` script argument is not a list, only one `File` indicator object is retrieved.
    However, since the `enrichment_brand` argument can accept multiple values, there could be several `DBotScore` objects.

    Args:
        entry_context (list): List of entry context items in the command response.
        brand (Brands | None): Optional source brand to be added under the `Source` key in the `DBotScore` dictionaries.

    Returns:
        dict: Context output dictionary with the `File` indicator and `DBotScore` objects, if found.
    """
    context_output = {}

    for context_item in entry_context:
        if files := get_from_context(context_item, ContextPaths.FILE):
            context_output.update(files[0])

        if dbot_scores := get_from_context(context_item, ContextPaths.DBOT_SCORE):
            if "DBotScore" not in context_output:
                context_output["DBotScore"] = []

            for dbot_score in dbot_scores:
                dbot_score_brand = brand or dbot_score.get("Vendor", "Unknown")
                context_output["DBotScore"].append(add_source_brand_to_values(dbot_score, brand=dbot_score_brand))

    return context_output


def flatten_list(nested_list: list) -> list:
    """
    Flattens a nested list of lits.

    Args:
        nested_list (list): A list of that could have lists nested inside.

    Returns:
        list: A flattened list.
    """
    return list(itertools.chain.from_iterable(nested_list))


def add_source_brand_to_values(mapping: dict[str, Any], brand: Brands | str, excluded_keys: list[str] | None = None) -> dict:
    """
    Recursively creates nested dictionaries under the mapping key where each dictionary has `Value` and `Source` keys.

    Args:
        mapping (dict[str, Any]): Dictionary containing key-value pairs that need to be transformed.
        brand (Brands | str): The source brand to be added under the `Source` key in the nested dictionaries.
        excluded_keys (list[str] | None): Optional list of keys to be excluded from the transformed output.

    Returns:
        dict: Dictionary without excluded keys where each key has a dictionary value that contains:
            `Value` - holding the original value from `mapping`
            `Source` - holding the source brand's name.
    """
    result: dict = {}

    for key, value in mapping.items():
        if excluded_keys and key in excluded_keys:
            continue

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
                if key not in target:
                    target[key] = []
                target[key].append(value)

            elif isinstance(value, dict):
                if key not in target:
                    target[key] = {}
                recursive_merge(target[key], value)

            elif key == "DBotScore":
                if key not in target:
                    target[key] = []
                target[key].extend(value)

            else:
                target[key] = value

    merged_file_context: dict[str, Any] = {}
    for context in per_command_context.values():
        recursive_merge(merged_file_context, context)

    return {ContextPaths.FILE.value: assign_params(**merged_file_context)}


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
    entry_context, readable_command_results = command.execute()

    context_output: dict[str, Any] = get_file_and_dbot_scores_from_context(entry_context)

    return assign_params(**context_output), readable_command_results


def execute_wildfire_report(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    Executes the `!wildfire-report` command and transforms the entry context into a standard context output by extracting the
    `File` and `DBotScore` dictionaries. It also adds source brand fields to additional entry context items.

    Args:
        command (Command): The `!wildfire-report` command to be executed.

    Returns:
        tuple[dict, list[CommandResults]]: A tuple of the transformed context output, and human-readable command results.
    """
    entry_context, readable_command_results = command.execute()

    context_output: dict[str, Any] = get_file_and_dbot_scores_from_context(entry_context, brand=Brands.WILDFIRE_V2)

    # Add additional brand fields to context
    for context_item in entry_context:
        if wild_fire_report := get_from_context(context_item, ContextPaths.WILDFIRE_V2_REPORT):
            context_output["Report"] = add_source_brand_to_values(wild_fire_report[0], brand=Brands.WILDFIRE_V2)

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
    entry_context, readable_command_results = command.execute()

    context_output: dict[str, Any] = get_file_and_dbot_scores_from_context(entry_context, brand=Brands.WILDFIRE_V2)

    # Add additional brand fields to context
    for context_item in entry_context:
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
    entry_context, readable_command_results = command.execute()

    context_output: dict[str, Any] = {}  # No File indicator and no DBotScore in entry context

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
        return

    command_execution_function_mapping: dict[str, Callable] = {
        "file": execute_file_reputation,
        "wildfire-report": execute_wildfire_report,
        "wildfire-get-verdict": execute_wildfire_verdict,
        "core-get-hash-analytics-prevalence": execute_ir_hash_analytics,
    }

    execution_function = command_execution_function_mapping.get(command.name)

    if not execution_function:
        raise ValueError(f"Unknown command: {command.name}")

    context, readable_command_results = execution_function(command)

    per_command_context[command.name] = context
    verbose_command_results.extend(readable_command_results)


""" FLOW STAGES FUNCTIONS """


def search_file_indicator(
    file_hash: str,
    per_command_context: dict[str, Any],
    verbose_command_results: list,
    external_enrichment: bool,
) -> None:
    """
    Searches for the file indicator using the file hash value in the Thread Intelligence Module (TIM). If found, it transforms
    the Indicator of Compromise (IOC) into a standard context output by extracting the `File` dictionary. It also adds source
    brand fields to additional context items.

    Args:
        file_hash (str): The hash of the file.
        per_command_context (dict[str, Any]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
        external_enrichment (bool): Whether to enrich the file indicator from external source brands.
    """
    demisto.debug(f"Starting to search for File indicator with value: {file_hash}.")
    try:
        search_results = IndicatorsSearcher(query=f"type:File and {file_hash}", size=1)

    except Exception as e:
        demisto.debug(f"Error searching for File indicator with value: {file_hash}. Error: {str(e)}.")
        readable_command_results = CommandResults(
            readable_output=f"#### Error for Search Indicators\n{str(e)}",
            entry_type=EntryType.ERROR,
        )
        verbose_command_results.append(readable_command_results)
        return

    iocs = flatten_list([result.get('iocs') or [] for result in search_results])
    if not iocs:
        demisto.debug(f"Could not find File indicator with value: {file_hash}.")
        readable_command_results = CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
        return

    demisto.debug(f"Found {len(iocs)} File indicators with value: {file_hash}.")

    ioc_custom_fields = iocs[0].get("CustomFields", {})

    # Handle context output
    file_context = get_file_from_ioc_custom_fields(ioc_custom_fields)
    context_output = add_source_brand_to_values(file_context, brand=Brands.TIM) if external_enrichment else file_context
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

    # B. Run Wildfire Report command - only works with SHA256 and MD5 hashes
    if hash_type in ("sha256", "md5"):
        wildfire_report_command = Command(
            name="wildfire-report",
            args={"sha256": file_hash} if hash_type == "sha256" else {"md5": file_hash},
            brand=Brands.WILDFIRE_V2,
        )
        enrich_with_command(wildfire_report_command, modules, per_command_context, verbose_command_results)
    else:
        demisto.debug(f"Skipping running command 'wildfire-report'. Unsupported file hash type: {hash_type}.")

    # C. Run Wildfire Verdict command
    wildfire_verdict_command = Command(
        name="wildfire-get-verdict",
        args={"hash": file_hash},
        brand=Brands.WILDFIRE_V2,
    )
    enrich_with_command(wildfire_verdict_command, modules, per_command_context, verbose_command_results)

    # D. Run Core IR Hash Analytics command - only works with SHA256 hashes
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
    demisto.debug("Starting to summarize results from all executed commands")

    file_found_count = len([value for value in per_command_context.values() if value])
    are_all_results_errors = (
        bool(verbose_command_results)
        and all(result.entry_type == EntryType.ERROR for result in verbose_command_results)
    )

    summary = {
        "File": file_hash,
        "Status": "Done" if file_found_count > 0 else "Not Found",
        "Result": "Failed" if are_all_results_errors else "Success",
    }
    if file_found_count > 0:
        summary["Message"] = f"Found data on file from {file_found_count} sources."
    else:
        summary["Message"] = "Could not find data on file."
        if external_enrichment is False:
            summary["Message"] += " Consider setting external_enrichment=true."

    demisto.debug(f"Summarized results from all executed commands: {summary}")

    return CommandResults(
        readable_output=tableToMarkdown(name=f"File Enrichment result for {file_hash}", t=summary),
        outputs=merge_context_outputs(per_command_context),
    )


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()

        external_enrichment: bool = argToBoolean(args.get("external_enrichment", False))
        verbose: bool = argToBoolean(args.get("verbose", False))
        file_reputation_brands: list = argToList(args.get("enrichment_brands"))  # brands to use for `!file` reputation command

        file_hash: str = args.get("file_hash", "")
        hash_type: str = get_hash_type(file_hash).casefold()

        if not file_hash or hash_type == "unknown":
            raise ValueError("A valid file hash must be provided. Supported types are: MD5, SHA1, SHA256, and SHA512.")

        per_command_context: dict = {}
        verbose_command_results: list[CommandResults] = []

        # 1. Search indicators in TIM
        search_file_indicator(
            file_hash=file_hash,
            per_command_context=per_command_context,
            verbose_command_results=verbose_command_results,
            external_enrichment=external_enrichment,
        )

        if external_enrichment:
            modules = demisto.getModules()

            # 2. Run external enrichment using various source brand commands
            run_external_enrichment(
                file_hash=file_hash,
                hash_type=hash_type,
                modules=modules,
                file_reputation_brands=file_reputation_brands,
                per_command_context=per_command_context,
                verbose_command_results=verbose_command_results,
            )

        # 3. Summarize all command results
        summary_command_results = summarize_command_results(
            file_hash=file_hash,
            per_command_context=per_command_context,
            verbose_command_results=verbose_command_results,
            external_enrichment=external_enrichment,
        )

        command_results = [summary_command_results]
        if verbose:
            command_results.extend(verbose_command_results)

        return_results(command_results)

    except Exception as e:
        return_error(f"Failed to execute file-enrichment command. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
