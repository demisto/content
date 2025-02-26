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

    @classmethod
    def values(cls, brands_to_exclude: tuple[str] = ("TIM",)) -> list[str]:
        """
        Returns a list of brand names (values of the enum members).

        Args:
            brands_to_exclude (tuple[str], optional): Brand names to exclude from the list.

        Returns:
            list[str]: List of string brand names.
        """
        return [member.value for member in cls if member.value not in brands_to_exclude]


class ContextPaths(Enum):
    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    FILE = Common.File.CONTEXT_PATH
    WILDFIRE_V2_REPORT = (
        "WildFire.Report(val.SHA256 && val.SHA256 == obj.SHA256 || "
        "val.MD5 && val.MD5 == obj.MD5 || val.URL && val.URL == obj.URL)"
    )
    WILDFIRE_V2_INFO_FILE = "InfoFile"
    WILDFIRE_V2_VERDICT = "WildFire.Verdicts(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5)"
    CORE_IR_HASH_ANALYTICS = "Core.AnalyticsPrevalence.Hash"
    VIRUS_TOTAL_FILE = "VirusTotal.File(val.id && val.id == obj.id)"


VIRUS_TOTAL_MALICIOUS_DETECTION_THRESHOLD = 5

""" COMMAND CLASS """


class Command:
    def __init__(self, brand: Brands, name: str, args: dict) -> None:
        """
        Initializes a Command object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
        """
        self.brand: Brands = brand
        self.name: str = name
        self.args: dict = args

    @property
    def _has_required_args(self) -> bool:
        """
        Validates if the command has all the required arguments. If the command has no arguments, it is considered valid.

        Args:
            command (Command): The command object to validate.

        Returns:
            bool: True if the command has all the required arguments, False otherwise.
        """
        is_valid = any(self.args.values()) if self.args else True

        if not is_valid:
            demisto.debug(f"Skipping command '{self.name}' since no required arguments were provided.")

        return is_valid

    def _should_brand_run(self, modules: dict, brands_to_run: list[str]) -> bool:
        """
        Checks if command source brand is in the specified list of brands to run and has an enabled integration instance.

        Args:
            modules (dict[str, Any]): Modules context from `demisto.getModules()`.
            brands_to_run (list[str]): List of brand names to run, as given in the `brands` argument.

        Returns:
            bool: True if the command brand is in the list of brands to run and is enabled. Otherwise, False.
        """
        is_in_brands_to_run = self.brand.value in brands_to_run if brands_to_run else True
        if not is_in_brands_to_run:
            demisto.debug(f"Skipping command '{self.name}'. The brand '{self.brand.value}' is not in the list of brands to run.")
            return False

        enabled_brands = {module.get("brand") for module in modules.values() if module.get("state") == "active"}
        if self.brand.value not in enabled_brands:
            demisto.debug(f"Skipping command '{self.name}'. The brand '{self.brand.value}' is not enabled.")
            return False

        return True

    def can_be_run(self, modules: dict, brands_to_run: list[str]) -> bool:
        """
        Checks if the command has all the required arguments, If true, it then checks if its source brand is in the specified
        list of brands to run and has an enabled integration instance.

        Args:
            modules (dict[str, Any]): Modules context from `demisto.getModules()`.
            brands_to_run (list[str]): List of brand names to run, as given in the `brands` argument.

        Returns:
            bool: True if the command has all the required arguments and its source brand should run.
        """
        return self._has_required_args and self._should_brand_run(modules, brands_to_run)

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
        """Formatted string representation for logging"""
        return self.as_formatted_string

    def __repr__(self) -> str:
        """Raw string representation for debugging"""
        return f"Command: {self.as_formatted_string} with brand: '{self.brand.value}'"


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


def get_file_from_context(context: dict) -> dict:
    """
    Gets the `File` indicator dictionary from the entry context, if found.

    Args:
        context (dict): `EntryContext` from the command execution response.

    Returns:
        dict: `File` indicator dictionary.
    """
    file_indicator = context.get(ContextPaths.FILE.value)

    if not file_indicator:
        return {}

    return file_indicator[0] if isinstance(file_indicator, list) else file_indicator


def get_dbot_scores_from_context(context: dict) -> list[dict]:
    """
    Gets the `DBotScore` list from the entry context, if found.

    Args:
        context (dict): `EntryContext` from the command execution response.

    Returns:
        dict: List of `DBotScore` dictionaries.
    """
    dbot_score = context.get(ContextPaths.DBOT_SCORE.value)

    if not dbot_score:
        return []

    return dbot_score if isinstance(dbot_score, list) else [dbot_score]


def flatten_list(nested_list: list) -> list:
    """
    Flattens a nested list of lits.

    Args:
        nested_list (list): A list of that could have lists nested inside.

    Returns:
        list: A flattened list.
    """
    return list(itertools.chain.from_iterable(nested_list))


def add_source_brand_to_values(
    mapping: dict[str, Any],
    brand: Brands,
    key_prefix: str = "",
    excluded_keys: list[str] | None = None
) -> dict:
    """
    Creates nested dictionaries under the mapping key and an optional prefix, where each dictionary has `value` and `source`
    keys.

    Args:
        mapping (dict[str, Any]): Dictionary containing key-value pairs that need to be transformed.
        brand (Brands): The source brand to be added under the `source` key in the nested dictionaries.
        key_prefix (str): Optional string to be prefixed to the keys of the output dictionary.
        excluded_keys (list[str] | None): Optional list of keys to be excluded from the transformed output.

    Returns:
        dict: Dictionary where each key appears with the optional prefix (unless the key is excluded), and each value is a
        dictionary containing `value` (holding the original value from `mapping`) and `source` (holding the brand's value).
    """
    excluded_keys = excluded_keys or []
    return {
        f"{key_prefix}{key}": {"value": value, "source": brand.value}
        for key, value in list(mapping.items())
        if key not in excluded_keys and value is not None
    }


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

    context_output: dict[str, Any] = {"_DBotScore": [], "_File": {}}
    for context_item in entry_context:
        context_output["_DBotScore"].extend(get_dbot_scores_from_context(context_item))
        context_output["_File"].update(get_file_from_context(context_item))

        # Add additional brand field to "_File" object
        malicious_detections_count: int | None = (
            context_item
            .get(ContextPaths.VIRUS_TOTAL_FILE.value, {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious")
        )

        if malicious_detections_count is None:
            file_verdict = "Unknown"
        elif malicious_detections_count > VIRUS_TOTAL_MALICIOUS_DETECTION_THRESHOLD:
            file_verdict = "Malicious"
        else:
            file_verdict = "Benign"

        context_output["_File"]["VTFileVerdict"] = file_verdict

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

    brand = command.brand
    report_excluded_keys = ["MD5", "SHA1", "SHA256", "SHA512"]

    context_output: dict[str, Any] = {"_DBotScore": [], "_File": {}}
    for context_item in entry_context:
        context_output["_DBotScore"].extend(get_dbot_scores_from_context(context_item))
        context_output["_File"].update(get_file_from_context(context_item))

        # Add additional brand fields to "_File" object
        wild_fire_report: dict = context_item.get(ContextPaths.WILDFIRE_V2_REPORT.value, {})
        wild_fire_info_file: dict = context_item.get(ContextPaths.WILDFIRE_V2_INFO_FILE.value, {})

        context_output["_File"].update(add_source_brand_to_values(wild_fire_report, brand, excluded_keys=report_excluded_keys))
        context_output["_File"].update(add_source_brand_to_values(wild_fire_info_file, brand, key_prefix="Info"))

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

    brand = command.brand
    verdict_excluded_keys = ["MD5", "SHA1", "SHA256", "SHA512"]

    context_output: dict[str, Any] = {"_DBotScore": [], "_File": {}}
    for context_item in entry_context:
        context_output["_DBotScore"].extend(get_dbot_scores_from_context(context_item))
        context_output["_File"].update(get_file_from_context(context_item))

        wild_fire_verdict: dict = context_item.get(ContextPaths.WILDFIRE_V2_VERDICT.value, {})
        context_output["_File"].update(add_source_brand_to_values(wild_fire_verdict, brand, excluded_keys=verdict_excluded_keys))

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

    brand = command.brand
    context_output: dict[str, Any] = {"_File": {}}
    for context_item in entry_context:
        hash_analytics = context_item.get(ContextPaths.CORE_IR_HASH_ANALYTICS.value, [])
        hash_analytics = hash_analytics[0] if hash_analytics and isinstance(hash_analytics, list) else hash_analytics
        context_output["_File"].update(add_source_brand_to_values(hash_analytics, brand))

    return context_output, readable_command_results


def enrich_with_command(
    command: Command,
    modules: dict[str, Any],
    brands_to_run: list[str],
    per_command_context: dict[str, Any],
    verbose_command_results: list[CommandResults],
) -> None:
    """
    Calls the file enrichment command execution function if the command brand is available and adds the context output to
    the `per_command_context` dictionary and the human-readable command results to the `verbose_command_results` list.

    Args:
        command (Command): The command to be executed.
        modules (dict[str, Any]): Modules context from `demisto.getModules()`.
        brands_to_run (list[str]): List of brand names to run, as given in the `brands` argument.
        per_command_context (dict[str, Any]): Dictionary of the context output (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    if not command.can_be_run(modules, brands_to_run):
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
) -> None:
    """
    Searches for the file indicator using the file hash value in the Thread Intelligence Module (TIM). If found, it transforms
    the Indicator of Compromise (IOC) into a standard context output by extracting the `File` dictionary. It also adds source
    brand fields to additional context items.

    Args:
        file_hash (str): The hash of the file.
        per_command_context (dict[str, Any]): Dictionary of the context output (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
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

    brand = Brands.TIM
    ioc_excluded_keys = [
        "cacheVersn", "insightCache", "moduleToFeedMap", "source", "sourceBrands",
        "sourceInstances", "CustomFields", "indicator_type", "value"
    ]

    context_output: dict[str, Any] = {"_File": {}}
    iocs = flatten_list([result.get('iocs') or [] for result in search_results])

    for ioc in iocs:
        file_indicator = get_file_from_ioc_custom_fields(ioc.get("CustomFields", {}))
        context_output["_File"].update(file_indicator)
        context_output["_File"].update(add_source_brand_to_values(ioc, brand, excluded_keys=ioc_excluded_keys))

    per_command_context["findIndicators"] = assign_params(**context_output)

    table = tableToMarkdown(name="Found Indicators", t=iocs)
    readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")
    verbose_command_results.append(readable_command_results)


def run_external_enrichment(
    file_hash: str,
    hash_type: str,
    modules: dict,
    brands_to_run: list[str],
    per_command_context: dict[str, Any],
    verbose_command_results: list,
) -> None:
    """
    Runs the external file enrichment flow by executing the relevant commands from multiple source brands.

    Args:
        file_hash (str): The hash of the file.
        hash_type (str): The type of file hash normalized to lower case; can be 'md5', 'sha1', 'sha256', or 'sha512'.
        modules (dict): Modules context from `demisto.getModules()`.
        brands_to_run (list[str]): List of brand names to run, as given in the `brands` argument.
        per_command_context (dict[str, Any]): Dictionary of the context output (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    demisto.debug(f"Starting to run external enrichment flow on file hash: {file_hash} using brands: {brands_to_run}.")

    # A. Run file reputation command - using VirusTotal (API v3)
    file_reputation_command = Command(
        brand=Brands.VIRUS_TOTAL_V3,
        name="file",
        args={"file": file_hash, "using-brand": ",".join(brands_to_run)},
    )
    enrich_with_command(file_reputation_command, modules, brands_to_run, per_command_context, verbose_command_results)

    # B. Run Wildfire Report command - only works with SHA256 and MD5 hashes
    if hash_type in ("sha256", "md5"):
        wildfire_report_command = Command(
            brand=Brands.WILDFIRE_V2,
            name="wildfire-report",
            args={"sha256": file_hash} if hash_type == "sha256" else {"md5": file_hash},
        )
        enrich_with_command(wildfire_report_command, modules, brands_to_run, per_command_context, verbose_command_results)
    else:
        demisto.debug(f"Skipping running command 'wildfire-report'. Unsupported file hash type: {hash_type}.")

    # C. Run Wildfire Verdict command
    wildfire_verdict_command = Command(
        brand=Brands.WILDFIRE_V2,
        name="wildfire-get-verdict",
        args={"hash": file_hash},
    )
    enrich_with_command(wildfire_verdict_command, modules, brands_to_run, per_command_context, verbose_command_results)

    # D. Run Core IR Hash Analytics command - only works with SHA256 hashes
    if hash_type == "sha256":
        hash_analytics_command = Command(
            brand=Brands.CORE_IR,
            name="core-get-hash-analytics-prevalence",
            args={"sha256": file_hash},
        )
        enrich_with_command(hash_analytics_command, modules, brands_to_run, per_command_context, verbose_command_results)
    else:
        demisto.debug(f"Skipping running command 'core-get-hash-analytics-prevalence'. Unsupported file hash type: {hash_type}.")

    demisto.debug(f"Finished running external enrichment flow on file hash: {file_hash} using brands: {brands_to_run}.")


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
        per_command_context (dict): A dictionary of the context output (value) of each command name (key).
        verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
        external_enrichment (bool): Whether to enrich the file indicator from external source brands.

    Returns:
        CommandResults: The CommandResults with a human-readable output summary.
    """
    demisto.debug("Starting to summarize results from all executed commands")

    file_found_count = len([value for value in per_command_context.values() if value.get("_File")])
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

    table = tableToMarkdown(name=f"File Enrichment result for {file_hash}", t=summary)

    demisto.debug(f"Summarized results from all executed commands: {summary}")

    output: dict[str, Any] = {ContextPaths.FILE.value: {}, ContextPaths.DBOT_SCORE.value: []}
    for value in per_command_context.values():
        output[ContextPaths.FILE.value].update(value.get("_File", {}))
        output[ContextPaths.DBOT_SCORE.value].extend(value.get("_DBotScore", []))

    return CommandResults(readable_output=table, outputs=output)


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()

        external_enrichment: bool = argToBoolean(args.get("external_enrichment", False))
        verbose: bool = argToBoolean(args.get("verbose", False))
        brands_to_run: list = argToList(args.get("brands", Brands.values()))

        file_hash: str = args.get("file_hash", "")
        hash_type: str = get_hash_type(file_hash).casefold()

        if not file_hash or hash_type == "unknown":
            raise ValueError("A valid file hash must be provided. Supported types are: MD5, SHA1, SHA256, and SHA512.")

        per_command_context: dict = {}
        verbose_command_results: list[CommandResults] = []

        # 1. Search indicators in TIM
        search_file_indicator(file_hash, per_command_context, verbose_command_results)

        if external_enrichment:
            modules = demisto.getModules()

            # 2. Run external enrichment using various source brand commands
            run_external_enrichment(
                file_hash=file_hash,
                hash_type=hash_type,
                modules=modules,
                brands_to_run=brands_to_run,
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
