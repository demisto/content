import demistomock as demisto
from CommonServerPython import *

from enum import Enum
from typing import Any


class Brands(Enum):
    TIM = "TIM"  # Threat Intelligence Module
    VIRUS_TOTAL_V3 = "VirusTotal (API v3)"  # VirusTotal (API v3) (Partner Contribution)
    WILDFIRE_V2 = "WildFire-v2"  # Palo Alto Networks WildFire v2
    CORE_IR = "Cortex Core - IR"  # Core - Investigation & Response

    @classmethod
    def values(cls) -> list[str]:
        return [member.value for member in cls]


class ContextPaths(Enum):
    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    FILE_INDICATOR = Common.File.CONTEXT_PATH
    WILDFIRE_V2_REPORT = (
        "WildFire.Report(val.SHA256 && val.SHA256 == obj.SHA256 || "
        "val.MD5 && val.MD5 == obj.MD5 || val.URL && val.URL == obj.URL)"
    )
    WILDFIRE_V2_INFO_FILE = "InfoFile"
    WILDFIRE_V2_VERDICT = "WildFire.Verdicts(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5)"
    CORE_IR_HASH_PREVALENCE = "Core"
    VIRUS_TOTAL_FILE = "VirusTotal.File(val.id && val.id == obj.id)"


VIRUS_TOTAL_MALICIOUS_DETECTION_THRESHOLD = 5


class Command:
    def __init__(self, brand: Brands, name: str, args: dict) -> None:
        """
        Initialize a Command object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
        """
        self.brand: str = brand.value
        self.name: str = name
        self.args: dict = args

    @property
    def has_required_args(self) -> bool:
        """
        Validate if the command has all the required arguments.
        If the command has no arguments, it is considered valid.

        Args:
            command (Command): The command object to validate.

        Returns:
            bool: True if the command has all the required arguments, False otherwise.
        """
        is_valid = any(self.args.values()) if self.args else True
        if not is_valid:
            demisto.debug(
                f"Skipping command '{self.name}' since no required arguments were provided."
            )

        return is_valid

    def prepare_human_readable(self, human_readable: str, is_error: bool = False) -> CommandResults:
        """
        Prepare human-readable output for a command execution.

        Args:
            command_name (str): The name of the command executed.
            args (dict): The arguments passed to the command.
            human_readable (str): The human-readable output of the command.
            is_error (bool): Whether the command resulted in an error. Defaults to False.

        Returns:
            CommandResults: CommandResult object with the formatted output.
        """
        formatted_args: list[str] = []
        for arg, value in self.args.items():
            if value:
                if isinstance(value, dict):
                    value = json.dumps(value).replace('"', '\\\\"')
                formatted_args.append(f'{arg}="{value}"')
        command = f"!{self.name} {' '.join(formatted_args)} using brands: **{self.args.get('using-brand', self.brand)}**"

        if not is_error:
            result_message = f"#### Result for {command}\n{human_readable}"
            entry_type = EntryType.NOTE
        else:
            result_message = f"#### Error for {command}\n{human_readable}"
            entry_type = EntryType.ERROR

        return CommandResults(
            readable_output=result_message,
            entry_type=entry_type,
            mark_as_note=True,
        )

    def execute(self, data_path: str) -> tuple[list[dict], list[CommandResults]]:
        """
        Executes the specified command with given arguments, handles any errors, and parses the execution results.

        Args:
            command_name (str): The name of the command to execute.
            args (dict[str, Any]): A dictionary of arguments to pass to the command.

        Returns:
            tuple[list[dict], list[CommandResults]]: A tuple of data, human readable results, and error messages.
        """
        demisto.debug(f"Executing command: {self.name}")
        execution_results = demisto.executeCommand(self.name, self.args)

        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self.name}")
            error_message = f"No execution response from command: {self.name}"
            error_result = self.prepare_human_readable(error_message, is_error=True)
            return [], [error_result]

        data_list: list[dict] = []
        human_readable_results: list[CommandResults] = []

        for result in execution_results:

            if is_error(result):
                human_readable_results.append(self.prepare_human_readable(get_error(result), is_error=True))

            elif isinstance(result, dict):
                if human_readable := result.get("HumanReadable"):
                    human_readable_results.append(self.prepare_human_readable(human_readable))

                if data := result.get(data_path):
                    data_list.extend(data) if isinstance(data, list) else data_list.append(data)

        demisto.debug(f"Finished parsing execution response of command: {self.name}")

        return data_list, human_readable_results


class Modules:
    def __init__(self, modules: dict[str, Any], brands_to_run: list[str]) -> None:
        """
        Initialize the Modules instance.

        Args:
            modules (dict[str, Any]): A dictionary containing module information.
            brands_to_run (list[str]): A list of brands to run.

        Attributes:
            modules_context (dict[str, Any]): The modules dictionary.
            _brands_to_run (list[str]): The list of brands to run.
            _enabled_brands (set[str]): A set of active brands extracted from the modules.
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
        Check if a brand is in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is in the list of brands to run, False otherwise.
        """
        is_in_brands_to_run = (
            command.brand in self._brands_to_run if self._brands_to_run else True
        )

        if not is_in_brands_to_run:
            demisto.debug(
                f"Skipping command '{command.name}' since the brand '{command.brand}' is not in the list of brands to run."
            )

        return is_in_brands_to_run

    def is_brand_available(self, command: Command) -> bool:
        """
        Check if a brand is available and in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is available and in the list of brands to run, False otherwise.
        """
        is_available = command.brand in self._enabled_brands
        if not is_available:
            demisto.debug(
                f"Skipping command '{command.name}' since the brand '{command.brand}' is not available."
            )
        elif not self.is_brand_in_brands_to_run(command):
            is_available = False

        return is_available


def search_file_indicator(file_hash: str) -> dict:
    """
    """
    query_results = demisto.searchIndicators(query=f"type:File and {file_hash}")

    brand = Brands.TIM
    tim_excluded_keys = [
        "cacheVersn", "insightCache", "moduleToFeedMap", "source", "sourceBrands",
        "sourceInstances", "CustomFields", "indicator_type", "value"
    ]

    file_context: dict[str, Any] = {"File": {}}
    for ioc in query_results.get("iocs", []):

        file_indicator = get_file_context_from_ioc_custom_fields(ioc.get("CustomFields", {}))

        file_context["File"].update(file_indicator)

        # Add additional brand fields to "File" object
        file_context["File"].update(add_source_brand_to_values(ioc, brand, excluded_keys=tim_excluded_keys))

    return assign_params(**file_context)


def execute_file_reputation(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    """
    entry_context, readable_command_results = command.execute(data_path="EntryContext")

    file_context: dict[str, Any] = {"DBotScore": {}, "File": {}}
    for context_item in entry_context:
        dbot_score, file_indicator = get_dbot_and_file_from_context(context_item)

        file_context["DBotScore"].update(dbot_score)
        file_context["File"].update(file_indicator)

        # Add additional brand field to "File" object
        malicious_detections_count: int | None = (
            entry_context[0]
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

        file_context["File"]["VTFileVerdict"] = file_verdict

    return assign_params(**file_context), readable_command_results


def add_source_brand_to_values(
    mapping: dict[str, Any],
    brand: Brands,
    key_prefix: str = "",
    excluded_keys: list[str] | None = None
) -> dict:
    """_summary_

    Args:
        mapping (dict[str, Any]): _description_
        brand (Brands): _description_
        key_prefix (str, optional): _description_. Defaults to "".
        excluded_keys (list[str] | None, optional): _description_. Defaults to None.

    Returns:
        dict: _description_
    """
    excluded_keys = excluded_keys or []
    return {
        f"{key_prefix}{key}": {"value": value, "source": brand.value}
        for key, value in list(mapping.items())
        if key not in excluded_keys and value is not None
    }


def execute_wildfire_report(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    """
    entry_context, readable_command_results = command.execute(data_path="EntryContext")

    brand = Brands.WILDFIRE_V2
    report_excluded_keys = ["MD5", "SHA1", "SHA256", "SHA512"]

    file_context: dict[str, Any] = {"DBotScore": {}, "File": {}}
    for context_item in entry_context:
        dbot_score, file_indicator = get_dbot_and_file_from_context(context_item)

        file_context["DBotScore"].update(dbot_score)
        file_context["File"].update(file_indicator)

        wild_fire_report: dict = context_item.get(ContextPaths.WILDFIRE_V2_REPORT.value, {})
        wild_fire_info_file: dict = context_item.get(ContextPaths.WILDFIRE_V2_INFO_FILE.value, {})

        # Add additional brand fields to "File" object
        file_context["File"].update(add_source_brand_to_values(wild_fire_report, brand, excluded_keys=report_excluded_keys))
        file_context["File"].update(add_source_brand_to_values(wild_fire_info_file, brand, key_prefix="Info"))

    return assign_params(**file_context), readable_command_results


def execute_wildfire_verdict(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    """
    entry_context, readable_command_results = command.execute(data_path="EntryContext")

    brand = Brands.WILDFIRE_V2
    verdict_excluded_keys = ["MD5", "SHA1", "SHA256", "SHA512"]

    file_context: dict[str, Any] = {"DBotScore": {}, "File": {}}
    for context_item in entry_context:
        dbot_score, file_indicator = get_dbot_and_file_from_context(context_item)

        file_context["DBotScore"].update(dbot_score)
        file_context["File"].update(file_indicator)

        wild_fire_verdict: dict = context_item.get(ContextPaths.WILDFIRE_V2_VERDICT.value, {})

        file_context["File"].update(add_source_brand_to_values(wild_fire_verdict, brand, excluded_keys=verdict_excluded_keys))

    return file_context, readable_command_results


def execute_ir_hash_analytics(command: Command) -> tuple[dict, list[CommandResults]]:
    """
    """
    entry_context, readable_command_results = command.execute(data_path="EntryContext")

    file_context = entry_context[0] if entry_context else {}

    return file_context, readable_command_results


def summarize_command_results(
    file_hash: str,
    file_context: dict[str, Any],
    verbose_command_results: list[CommandResults],
    external_enrichment: bool,
) -> CommandResults:
    """
    """
    file_found_count = len([value for value in file_context.values() if value])
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
            summary["Message"] += "Consider setting external_enrichment=true."

    table = tableToMarkdown(name=f"File Enrichment result for {file_hash}", t=summary)

    return CommandResults(readable_output=table, outputs=file_context, outputs_prefix="MyOutput")


def get_file_context_from_ioc_custom_fields(ioc_custom_fields: dict) -> dict:
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


def get_dbot_and_file_from_context(context: dict) -> tuple[dict, dict]:
    dbot_score = context.get(ContextPaths.DBOT_SCORE.value, {})
    file_indicator = context.get(ContextPaths.FILE_INDICATOR.value, {})

    return (
        dbot_score[0] if dbot_score and isinstance(dbot_score, list) else dbot_score,
        file_indicator[0] if file_indicator and isinstance(file_indicator, list) else file_indicator,
    )


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

        per_command_file_context: dict = {}
        verbose_command_results: list[CommandResults] = []
        modules = Modules(modules=demisto.getModules(), brands_to_run=brands_to_run)

        # 1. Search indicators in TIM
        ioc_file_context = search_file_indicator(file_hash)
        per_command_file_context["findIndicators"] = ioc_file_context

        if external_enrichment:
            # 2. Run file reputation command - using VirusTotal (API v3)
            file_reputation_command = Command(
                brand=Brands.VIRUS_TOTAL_V3,
                name="file",
                args={"file": file_hash, "using-brand": ",".join(brands_to_run)},
            )
            if modules.is_brand_available(file_reputation_command) and file_reputation_command.has_required_args:
                vt_file_context, readable_command_results = execute_file_reputation(file_reputation_command)

                per_command_file_context[file_reputation_command.name] = vt_file_context
                verbose_command_results.extend(readable_command_results)

            # 3. Run Wildfire Report command - only works with SHA256 and MD5 hashes
            if hash_type in ("sha256", "md5"):
                wildfire_report_command = Command(
                    brand=Brands.WILDFIRE_V2,
                    name="wildfire-report",
                    args={"sha256": file_hash} if hash_type == "sha256" else {"md5": file_hash},
                )
                if modules.is_brand_available(wildfire_report_command) and wildfire_report_command.has_required_args:
                    wf_file_context, readable_command_results = execute_wildfire_report(wildfire_report_command)

                    per_command_file_context[wildfire_report_command.name] = wf_file_context
                    verbose_command_results.extend(readable_command_results)

            # 4. Run Wildfire Verdict command
            wildfire_verdict_command = Command(
                brand=Brands.WILDFIRE_V2,
                name="wildfire-get-verdict",
                args={"hash": file_hash},
            )
            if modules.is_brand_available(wildfire_verdict_command) and wildfire_verdict_command.has_required_args:
                wf_file_context, readable_command_results = execute_wildfire_verdict(wildfire_verdict_command)

                per_command_file_context[wildfire_verdict_command.name] = wf_file_context
                verbose_command_results.extend(readable_command_results)

            # 5. Run Core IR Hash Analytics command - only works with SHA256 hashes
            if hash_type == "sha256":
                ir_hash_analytics_command = Command(
                    brand=Brands.CORE_IR,
                    name="core-get-hash-analytics-prevalence",
                    args={"sha256": file_hash},
                )
                if modules.is_brand_available(ir_hash_analytics_command) and ir_hash_analytics_command.has_required_args:
                    ir_file_context, readable_command_results = execute_ir_hash_analytics(ir_hash_analytics_command)

                    per_command_file_context[ir_hash_analytics_command.name] = ir_file_context
                    verbose_command_results.extend(readable_command_results)

        # 6. Summarize all command results
        summary_command_results = summarize_command_results(
            file_hash=file_hash,
            file_context=per_command_file_context,
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


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
