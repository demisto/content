import demistomock as demisto
from CommonServerPython import *

from enum import Enum
from typing import Any
from collections import defaultdict
from collections.abc import Callable

""" CONSTANTS """


class Brands(Enum):
    TIM = "TIM"  # [Built-in component] Threat Intelligence Module
    WILDFIRE_V2 = "WildFire-v2"  # [Installable integration] Palo Alto Networks WildFire v2
    CORE_IR = "Cortex Core - IR"  # [Installable integration] Core - Investigation & Response

    def __str__(self):
        """Formatted string representation for context output"""
        return self.value


HASH_TYPES = ["MD5", "SHA1", "SHA256", "SHA512"]

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

DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}


class ContextPaths(Enum):
    FILE_ENRICHMENT = (
        "FileEnrichment("
        "val.Brand && val.Brand == obj.Brand && ("
        "val.MD5 && val.MD5 == obj.MD5 || "
        "val.SHA1 && val.SHA1 == obj.SHA1 || "
        "val.SHA256 && val.SHA256 == obj.SHA256 || "
        "val.SHA512 && val.SHA512 == obj.SHA512"
        "))"
    )
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

    def has_specified_enrichment_brand(self, enrichment_brands: list[str]):
        """
        Checks if command source brand has is in the list of enrichment brands.

        Args:
            enrichment_brands (list[str]): List of brand names to run, as given in the `enrichment_brands` argument.

        Returns:
            bool: True if the command brand is in the enrichment brands list. Otherwise, False.
        """
        if not self.brand:
            demisto.debug(f"Command: {self} is not associated with any integration brand.")
            return True

        if not enrichment_brands:
            demisto.debug(f"No specified enrichment brands. Command {self} can run if it has an enabled integration instance.")
            return True

        if self.brand.value in enrichment_brands:
            demisto.debug(f"Command: {self} with brand {self.brand} is in enrichment brands.")
            return True

        demisto.debug(f"Command: {self} with brand {self.brand} is not in enrichment brands.")
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

        if self.brand.value in enabled_brands:
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


def classify_hashes_by_type(file_hashes: list[str]) -> dict[str, list[str]]:
    """Creates a dictionary of hash type (key) and hashes list (value)

    Args:
        file_hashes (list[str]): A list of file hashes.

    Returns:
        dict[str, list[str]]: Classified file hashes.
    """
    hashes_by_type: dict[str, list] = defaultdict(list)

    for file_hash in file_hashes:
        hash_type = get_hash_type(file_hash).upper()
        if file_hash not in hashes_by_type.get(hash_type, []):
            hashes_by_type[hash_type].append(file_hash)

    return hashes_by_type


def set_dict_value(d: dict[str, Any], path: str, value: Any):
    """
    Sets a value in a nested dictionary given a dot-separated path.
    Creates dictionaries along the path if they do not exist.

    Args:
        mapping (dict[str, Any]): Dictionary to set nested key in.
        path (str): A dot-separated key path (e.g "Signature.Copyright")
        value (Any): Value to set in the dictionary.
    """
    # Field in root
    if "." not in path:
        d[path] = value
        return

    # Field nested
    parts = path.split(".")
    current = d
    for i, part in enumerate(parts):
        if i == len(parts) - 1:  # Last part of the path
            current[part] = value
        else:
            if part not in current:
                current[part] = {}
            current = current[part]


def get_file_from_ioc_custom_fields(ioc_custom_fields: dict[str, Any]) -> dict[str, Any]:
    """
    Gets the `File` context dictionary using the `CustomFields` value in the Indicator of Compromise (IOC) record.

    Maps indicator fields in the `connectedlowercase` format (CLI name) to nested context paths in the `UpperCamelCase` format.
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
            demisto.debug(f"Ignoring IOC custom field: {field_cli_name}. Field has empty value: {field_value}.")
            continue

        # Define fallback path "AdditionalFields.{field_cli_name}" in case mapping is not found
        field_context_path = mapping.get(field_cli_name, f"AdditionalFields.{field_cli_name}")

        # Handle both root fields (e.g. "Name") and nested fields (e.g. "Signature.Copyright")
        set_dict_value(output, path=field_context_path, value=field_value)

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
    value = entry_context_item.get(context_path.value) or {}

    return value if value and isinstance(value, list) else [value]


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


def merge_context_outputs(per_command_context: dict[str, dict], include_additional_fields: bool) -> dict[str, list]:
    """
    Merges multiple dictionaries into a single `FileEnrichment` context dictionary.

    Args:
        per_command_context (dict[str, dict]): Dictionary of the entry context (value) of each command name (key).
        include_additional_fields (bool): Whether to ...

    Returns:
        dict[str, list]: A merged `File` indicator dictionary.
    """
    merged_context_output: dict[str, list] = {ContextPaths.DBOT_SCORE.value: [], ContextPaths.FILE_ENRICHMENT.value: []}

    for command_name, command_context_output in per_command_context.items():
        demisto.debug(f"Merging transformed context output of command: {command_name} into unified context.")
        merged_context_output[ContextPaths.DBOT_SCORE.value].extend(command_context_output.get("DBotScore", []))

        for file_context in command_context_output.get("FileEnrichment", []):
            if not include_additional_fields:
                file_context.pop("AdditionalFields", {})
            merged_context_output[ContextPaths.FILE_ENRICHMENT.value].append(file_context)

    return assign_params(**merged_context_output)


def find_matching_dbot_score(dbot_scores: list[dict], file_context: dict[str, Any]) -> dict:
    """
    Finds the associated "DBotScore" object whose indicator value matches any of the hashes if the "File" Context.
    This is needed since multiple "DBotScore" and "File" objects can be returned if more than one file hash is specified.

    Args:
        dbot_scores (list[dict]): List of "DBotScore" objects.
        file_context (dict[str, Any]): Context output from a single war room result entry.

    Returns:
        dict: The matching "DBotScore" object if found, otherwise an empty dictionary.
    """
    hashes_in_context = {(file_context.get(hash_type) or "").casefold() for hash_type in HASH_TYPES if hash_type in file_context}

    for dbot_score in dbot_scores:
        indicator = dbot_score.get("Indicator")
        if indicator and indicator.casefold() in hashes_in_context:
            return dbot_score

    demisto.debug(f"Could not find matching DBotScore for hashes: {hashes_in_context}.")
    return {}


""" COMMAND EXECUTION FUNCTIONS """


def execute_file_reputation(command: Command) -> tuple[dict[str, list], list[CommandResults]]:
    """
    Executes the `!file` command and transforms the entry context into a standard context output by extracting the `File` and
    `DBotScore` dictionaries.

    Args:
        command (Command): The `!file` command to be executed.

    Returns:
        tuple[dict[str, list], list[CommandResults]]: The transformed context output and human-readable command results.
    """
    demisto.debug(f"Starting to execute file reputation command with args: {command.args}.")
    entry_context, readable_command_results = command.execute()

    demisto.debug(
        "Extracting File and DBotScore from file reputation entry context. "
        f"Command returned {len(entry_context)} items in entry context and {len(readable_command_results)} command results."
    )
    context_output: dict[str, list] = defaultdict(list)

    for context_item in entry_context:
        if dbot_scores := get_from_context(context_item, ContextPaths.DBOT_SCORE):
            context_output["DBotScore"].extend(dbot_scores)

        if files_context := get_from_context(context_item, ContextPaths.FILE):
            for file_context in files_context:
                dbot_score = find_matching_dbot_score(dbot_scores, file_context)
                file_context["Brand"] = dbot_score.get("Vendor", "Unknown")
                file_context["Score"] = dbot_score.get("Score", Common.DBotScore.NONE)
                context_output["FileEnrichment"].append(file_context)

    return context_output, readable_command_results


def execute_wildfire_verdict(command: Command) -> tuple[dict[str, list], list[CommandResults]]:
    """
    Executes the `!wildfire-get-verdict` command and transforms the entry context into a standard context output by extracting
    the `File` and `DBotScore` dictionaries.

    Args:
        command (Command): The `!wildfire-get-verdict` command to be executed.

    Returns:
        tuple[dict[str, list], list[CommandResults]]: The transformed context output and human-readable command results.
    """
    demisto.debug(f"Starting to execute Wildfire verdict command with args: {command.args}.")
    entry_context, readable_command_results = command.execute()

    demisto.debug(
        "Extracting DBotScore and Verdict from Wildfire verdict entry context. "
        f"Command returned {len(entry_context)} items in entry context and {len(readable_command_results)} command results."
    )
    context_output: dict[str, list] = defaultdict(list)

    for context_item in entry_context:
        if dbot_scores := get_from_context(context_item, ContextPaths.DBOT_SCORE):
            context_output["DBotScore"].extend(dbot_scores)

        if wild_fire_verdicts_context := get_from_context(context_item, ContextPaths.WILDFIRE_V2_VERDICT):
            for wild_fire_verdict_context in wild_fire_verdicts_context:
                dbot_score = find_matching_dbot_score(dbot_scores, wild_fire_verdict_context)
                file_context = assign_params(
                    Brand=Brands.WILDFIRE_V2.value,
                    Score=dbot_score.get("Score", Common.DBotScore.NONE),
                    Verdict=wild_fire_verdict_context.pop("Verdict", None),
                    VerdictDescription=wild_fire_verdict_context.pop("VerdictDescription", None),
                    MD5=wild_fire_verdict_context.pop("MD5", None),
                    SHA1=wild_fire_verdict_context.pop("SHA1", None),
                    SHA256=wild_fire_verdict_context.pop("SHA256", None),
                    SHA512=wild_fire_verdict_context.pop("SHA512", None),
                    AdditionalFields=wild_fire_verdict_context,  # remaining fields after "popping" mapped fields
                )
                context_output["FileEnrichment"].append(file_context)

    return context_output, readable_command_results


def execute_ir_hash_analytics(command: Command) -> tuple[dict[str, list], list[CommandResults]]:
    """
    Executes the `!core-get-hash-analytics-prevalence` command and transforms the entry context into a standard context output by
    extracting the `File` and `DBotScore` dictionaries. It also adds source brand fields to additional entry context items.

    Args:
        command (Command): The `!core-get-hash-analytics-prevalence` command to be executed.

    Returns:
        tuple[dict[str, list], list[CommandResults]]: The transformed context output and human-readable command results.
    """
    demisto.debug(f"Starting to execute IR hash analytics command with args: {command.args}.")
    entry_context, readable_command_results = command.execute()

    demisto.debug(
        "Extracting AnalyticsPrevalence from IR hash analytics entry context. "
        f"Command returned {len(entry_context)} items in entry context and {len(readable_command_results)} command results."
    )
    context_output: dict[str, list] = defaultdict(list)

    for context_item in entry_context:
        if hashes_analytics_context := get_from_context(context_item, ContextPaths.CORE_IR_HASH_ANALYTICS):
            for hash_analytics_context in hashes_analytics_context:
                file_context = assign_params(
                    Brand=Brands.CORE_IR.value,
                    SHA256=hash_analytics_context.get("sha256"),
                    GlobalPrevalence=demisto.get(hash_analytics_context, "data.global_prevalence.value"),
                    LocalPrevalence=demisto.get(hash_analytics_context, "data.local_prevalence.value"),
                    AdditionalFields=hash_analytics_context,
                )
                context_output["FileEnrichment"].append(file_context)

    return context_output, readable_command_results


def enrich_with_command(
    command: Command,
    enabled_brands: list[str],
    enrichment_brands: list[str],
    per_command_context: dict[str, dict],
    verbose_command_results: list[CommandResults],
) -> None:
    """
    Calls the relevant file enrichment command execution function if the command brand has an enabled integration
    instance and adds the context output to the `per_command_context` dictionary and the human-readable CommandResults
    objects to the `verbose_command_results` list.

    Args:
        command (Command): The command to be executed.
        enabled_brands (list[str]): Set of enabled integration brands.
        enrichment_brands (list[str]): List of brand names to run, as given in the `enrichment_brands` argument.
        per_command_context (dict[str, dict]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    if not command.has_specified_enrichment_brand(enrichment_brands):
        demisto.debug(f"Skipping command {command.name}. The brand {command.brand} is not in the enrichment brands.")
        return

    if not command.has_enabled_instance(enabled_brands):
        demisto.debug(f"Skipping command {command.name}. The brand {command.brand} has no enabled instance.")
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


def search_file_indicator(
    file_hashes: list[str],
    per_command_context: dict[str, dict],
    verbose_command_results: list,
) -> None:
    """
    Searches for the file indicator using the file hash value in the Thread Intelligence Module (TIM). If found, it transforms
    the Indicator of Compromise (IOC) into a standard context output by extracting the `File` dictionary. It also adds source
    brand fields to additional context items.

    Args:
        file_hashes (list[str]): List of file hashes.
        per_command_context (dict[str, dict]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    demisto.debug(f"Starting to search for File indicator with values: {file_hashes}.")
    try:
        value_in_hashes = " or ".join({f"value: {file_hash}" for file_hash in file_hashes})
        search_results = IndicatorsSearcher(query=f"type:File and ({value_in_hashes})", size=len(file_hashes))

    except Exception as e:
        demisto.debug(
            f"Error searching for File indicator with values: {file_hashes}. Error: {str(e)}.\n{traceback.format_exc()}"
        )
        readable_command_results = CommandResults(
            readable_output=f"#### Error for Search Indicators\n{str(e)}", entry_type=EntryType.ERROR
        )
        verbose_command_results.append(readable_command_results)
        return

    iocs = flatten_list([result.get("iocs") or [] for result in search_results])
    if not iocs:
        demisto.debug(f"Could not find File indicator with values: {file_hashes}.")
        readable_command_results = CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
        verbose_command_results.append(readable_command_results)
        return

    context_output: dict[str, list] = defaultdict(list)

    demisto.debug(f"Found {len(iocs)} File indicators with values: {file_hashes}.")
    for ioc in iocs:
        ioc_custom_fields = ioc.get("CustomFields", {})

        # Prepare context output
        if file_context := get_file_from_ioc_custom_fields(ioc_custom_fields):
            file_context["Brand"] = Brands.TIM.value
            file_context["Score"] = ioc.get("score", Common.DBotScore.NONE)
            context_output["FileEnrichment"].append(file_context)

            # Prepare human-readable output
            table = tableToMarkdown(name="Found Indicators", t=ioc_custom_fields)
            readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")
            verbose_command_results.append(readable_command_results)

    per_command_context["findIndicators"] = context_output


def run_external_enrichment(
    hashes_by_type: dict[str, list],
    enabled_brands: list[str],
    enrichment_brands: list[str],
    per_command_context: dict[str, dict],
    verbose_command_results: list,
) -> None:
    """
    Runs the external file enrichment flow by executing the relevant commands from multiple source brands.

    Args:
        hashes_by_type (dict[str, list]): Dictionary of file hashes (value) classified by the hash type (key).
        enabled_brands (list[str]) : List of enabled integration brands.
        enrichment_brands (list[str]): List of brand names to run, as given in the `enrichment_brands` argument.
        per_command_context (dict[str, dict]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    file_hashes = flatten_list(list(hashes_by_type.values()))

    demisto.debug(f"Starting to run external enrichment flow on file hashes: {file_hashes}.")

    # Run file reputation command - using all relevant brands or according to `enrichment_brands` argument
    file_reputation_command = Command(
        name="file",
        args=assign_params(**{"file": ",".join(file_hashes), "using-brand": ",".join(enrichment_brands)}),
    )
    enrich_with_command(
        command=file_reputation_command,
        enabled_brands=enabled_brands,
        enrichment_brands=enrichment_brands,
        per_command_context=per_command_context,
        verbose_command_results=verbose_command_results,
    )

    demisto.debug(f"Finished running external enrichment flow on file hashes: {file_hashes}.")


def run_internal_enrichment(
    hashes_by_type: dict[str, list],
    enabled_brands: list[str],
    enrichment_brands: list[str],
    per_command_context: dict[str, dict],
    verbose_command_results: list,
) -> None:
    """
    Runs the internal file enrichment flow by executing the relevant commands from internal source brands.

    Args:
        hashes_by_type (dict[str, list]): Dictionary of file hashes (value) classified by the hash type (key).
        enabled_brands (list[str]) : List of enabled integration brands.
        enrichment_brands (list[str]): List of brand names to run, as given in the `enrichment_brands` argument.
        per_command_context (dict[str, dict]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): : List of CommandResults with human-readable output.
    """
    # A. Run Wildfire Verdict command -  only works with SHA256 and MD5 hashes
    if wildfire_hashes := (hashes_by_type.get("SHA256", []) + hashes_by_type.get("MD5", [])):
        wildfire_verdict_command = Command(
            name="wildfire-get-verdict",
            args={"hash": ",".join(wildfire_hashes)},
            brand=Brands.WILDFIRE_V2,
        )
        enrich_with_command(
            command=wildfire_verdict_command,
            enabled_brands=enabled_brands,
            enrichment_brands=enrichment_brands,
            per_command_context=per_command_context,
            verbose_command_results=verbose_command_results,
        )
    else:
        demisto.debug("Skipping running command 'wildfire-get-verdict'. Found no SHA256 and MD5 hashes.")

    # B. Run Core IR Hash Analytics command - only works with SHA56 hashes
    if analytics_hashes := hashes_by_type.get("SHA256", []):
        hash_analytics_command = Command(
            name="core-get-hash-analytics-prevalence",
            args={"sha256": ",".join(analytics_hashes)},
            brand=Brands.CORE_IR,
        )
        enrich_with_command(
            command=hash_analytics_command,
            enabled_brands=enabled_brands,
            enrichment_brands=enrichment_brands,
            per_command_context=per_command_context,
            verbose_command_results=verbose_command_results,
        )
    else:
        demisto.debug("Skipping running command 'core-get-hash-analytics-prevalence'. Found no SHA256 hashes.")


def summarize_command_results(
    hashes_by_type: dict[str, list],
    per_command_context: dict[str, dict],
    verbose_command_results: list[CommandResults],
    external_enrichment: bool,
    include_additional_fields: bool,
) -> CommandResults:
    """
    Summarizes the results from all the executed commands.

    Args:
        hashes_by_type (dict[str, list]): Dictionary of file hashes (value) classified by the hash type (key).
        per_command_context (dict[str, dict]): A dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
        external_enrichment (bool): Whether to enrich the file indicator from external source brands.
        include_additional_fields (bool): Whether to ...

    Returns:
        CommandResults: The CommandResults with a human-readable output summary.
    """
    demisto.debug("Starting to summarize results from all executed commands.")

    # Write summary Result
    errors_count = len([result for result in verbose_command_results if result.entry_type == EntryType.ERROR])
    demisto.debug(f"Found {errors_count} errors in command results.")
    if errors_count:
        if errors_count == len(verbose_command_results):
            result = "Failed"  # All results are errors
        else:
            result = "Partial Success"  # Some results are errors
    else:
        result = "Success"  # No errors

    # Write summary Status
    merged_context = merge_context_outputs(per_command_context, include_additional_fields)
    merged_file_context = merged_context.get(ContextPaths.FILE_ENRICHMENT.value, [])

    demisto.debug(f"Found information on hashes from {len(merged_file_context)} sources.")

    summaries: list[dict] = []
    # Write summary Message
    for hash_type, file_hashes in hashes_by_type.items():
        for file_hash in file_hashes:
            file_context_for_hash = [
                d for d in merged_file_context if hash_type in d and d[hash_type].casefold() == file_hash.casefold()
            ]

            summary = {"File": file_hash}
            summary["Status"] = "Done" if file_context_for_hash else "Not Found"
            summary["Result"] = result
            tim_score = next(
                iter(context.get("Score") for context in file_context_for_hash if context.get("Brand") == Brands.TIM.value),
                Common.DBotScore.NONE,
            )
            summary["TIM Verdict"] = DBOT_SCORE_TO_VERDICT.get(tim_score, "Unknown")

            if file_context_for_hash:
                brands = {file_context.get("Brand") for file_context in file_context_for_hash}
                summary["Message"] = f"Found data on file from {len(brands)} brands."
                summary["Brands"] = ", ".join(sorted(brands))
            else:
                summary["Message"] = "Could not find data on file."
                if external_enrichment is False:
                    summary["Message"] += " Consider setting external_enrichment=true."

            summaries.append(summary)

    demisto.debug(f"Summarized results from all executed commands: {summaries}.")

    return CommandResults(
        outputs=merged_context,
        readable_output=tableToMarkdown(name=f"File Enrichment result for {', '.join(file_hashes)}", t=summaries),
    )


def warn_about_invalid_args(
    invalid_hashes: list[str], enrichment_brands: list[str], executed_brands: list[str]
) -> CommandResults | None:
    """
    Returns a warning war room entry about invalid `file_hash` and `enrichment_brands` argument values, if found.

    Args:
        invalid_hashes (list[str]): List of file hashes where the type was classified as "UNKNOWN".
        enrichment_brands (list[str]): List of brand names to run, as given in the `enrichment_brands` argument.
        executed_brands (list[str]): List of brand names that returned execution results with context outputs.

    Returns:
        CommandResults | None: Warning command results if any invalid arguments, None otherwise.
    """
    warnings: dict[str, str] = {}
    if invalid_hashes:
        warnings["Skipped Hashes"] = ", ".join(invalid_hashes)

    if skipped_brands := (set(enrichment_brands) - set(executed_brands)):
        warnings["Skipped Brands"] = ", ".join(skipped_brands)

    if not warnings:
        return None

    demisto.debug(f"Found {len(invalid_hashes)} invalid hashes and {len(skipped_brands)} invalid source brands.")
    return CommandResults(readable_output=tableToMarkdown("Invalid inputs skipped", t=warnings), entry_type=EntryType.WARNING)


""" SCRIPT FUNCTION """


def file_enrichment_script(args: dict[str, Any]) -> list[CommandResults]:
    """
    Implements `!file-enrichment` script by searching for the File indicator in TIM and (optionally) running external enrichment.
    It then outputs a human-readable summary of the command execution results and returns a consolidated merged `File` context.

    Args:
        args (dict): Script arguments.

    Returns:
        list[CommandResults]: List of CommandResults objects.

    Raises:
        ValueError: If the file hash is not valid.
        DemistoException: If none of the enrichment brands has an enabled integration instance.
    """
    demisto.debug(f"Parsing and validating script args: {args}.")

    file_hashes: list = argToList(args.get("file_hash", ""))
    external_enrichment: bool = argToBoolean(args.get("external_enrichment", False))
    enrichment_brands: list = argToList(args.get("brands"))  # brands to use for external enrichment
    verbose: bool = argToBoolean(args.get("verbose", False))
    include_additional_fields: bool = argToBoolean(args.get("additional_fields", False))

    # Classify hashes by type to check validity and handle commands that only support specific types
    hashes_by_type: dict[str, list] = classify_hashes_by_type(file_hashes)
    invalid_hashes = hashes_by_type.pop("UNKNOWN", [])
    demisto.debug(f"Found {len(invalid_hashes)} invalid file hashes: {invalid_hashes}.")
    if len(invalid_hashes) == len(file_hashes):  # If all hashes are of an unknown type, throw an error!
        raise ValueError("None of the file hashes are valid. Supported types are: MD5, SHA1, SHA256, and SHA512.")

    per_command_context: dict[str, dict] = {}
    verbose_command_results: list[CommandResults] = []

    demisto.debug(f"Running Step 1: Search File indicator in TIM with value {file_hashes}.")
    search_file_indicator(
        file_hashes=file_hashes,
        per_command_context=per_command_context,
        verbose_command_results=verbose_command_results,
    )

    demisto.debug("Getting integration brands on tenant.")
    enabled_brands = list({module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"})
    demisto.debug(f"Found {len(enabled_brands)} enabled integration brands.")

    demisto.debug(f"Running Step 2: Internal enrichment commands on {file_hashes} ")

    # Run internal enrichment commands unless:
    # "enrichment_brands" exists and the internal enrichment brands are not included in "enrichment_brands"
    run_internal_enrichment(
        hashes_by_type=hashes_by_type,
        enabled_brands=enabled_brands,
        enrichment_brands=enrichment_brands,
        per_command_context=per_command_context,
        verbose_command_results=verbose_command_results,
    )

    if external_enrichment or enrichment_brands:
        demisto.debug(f"Validating overlap between enrichment brands: {enrichment_brands} and enabled integration brands.")
        if enrichment_brands and not set(enrichment_brands).intersection(enabled_brands):
            raise DemistoException(
                "None of the enrichment brands has an enabled integration instance. "
                f"Ensure valid integration IDs are specified. For example: '{Brands.CORE_IR},{Brands.WILDFIRE_V2.value}'"
            )

        demisto.debug(f"Running External enrichment commands on {file_hashes} using brands: {enrichment_brands}.")
        run_external_enrichment(
            hashes_by_type=hashes_by_type,
            enabled_brands=enabled_brands,
            enrichment_brands=enrichment_brands,
            per_command_context=per_command_context,
            verbose_command_results=verbose_command_results,
        )

    demisto.debug(f"Running Step 3: Summarizing command results on {file_hashes} and consolidating context output.")
    summary_command_results = summarize_command_results(
        hashes_by_type=hashes_by_type,
        per_command_context=per_command_context,
        verbose_command_results=verbose_command_results,
        external_enrichment=external_enrichment,
        include_additional_fields=include_additional_fields,
    )

    # Create a list of CommandResults objects to return to the incident war room
    command_results = [summary_command_results]
    if verbose:
        # If `verbose` argument is True, CommandResults are returned for every executed command in the script
        command_results.extend(verbose_command_results)

        executed_brands = [
            file_context.get("Brand")
            for file_context in summary_command_results.outputs.get(ContextPaths.FILE_ENRICHMENT.value, [])  # type: ignore [attr-defined]
        ]
        # Warn about partially invalid `file_hash` and `enrichment_brands` argument values
        warning_command_results = warn_about_invalid_args(
            invalid_hashes=invalid_hashes,
            enrichment_brands=enrichment_brands,
            executed_brands=executed_brands,
        )
        if warning_command_results:
            command_results.append(warning_command_results)

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
