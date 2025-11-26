from abc import ABC
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
import traceback
from typing import Any
from datetime import datetime, timedelta

from CommonServerPython import *
import demistomock as demisto

# Type alias for complex dictionary structures to improve readability
ContextResult = dict[str, Any]
DBotScoreList = list[ContextResult]
CommandProcessResults = list[tuple[ContextResult, str, str]]

# Calculating time interval for indicators freshness
STATUS_FRESHNESS_WINDOW = timedelta(weeks=1)

DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}


# --- Core Enumerations and Data Classes ---
class Status(Enum):
    """Enum for command status."""

    SUCCESS = "Success"
    FAILURE = "Failure"


class IndicatorStatus(Enum):
    """Enum for indicator status.
    - FRESH: If the indicator modifiedTime is within the freshness window (default is one week).
    - STALE: If the indicator modifiedTime is outside the freshness window.
    - MANUAL: If the indicator was manually added.
    """

    FRESH = "Fresh"
    STALE = "Stale"
    MANUAL = "Manual"


class EntryResult:
    """
    Captures a single command's summarized outcome for the final HR table.

    Attributes:
        command_name (str): Executed command name. (Not visible in HR)
        args (Any): The args passed (dict or string); kept for HR visibility.
        brand (str): Integration brand (or TIM/Core/VirusTotal).
        status (Status): Success/Failure.
        message (str): Short message (e.g., error text or brand summary).
    """

    def __init__(self, command_name: str, args: Any, brand: str, status: Status, message: str):
        self.command_name = command_name
        self.args = args
        self.brand = brand
        self.status = status
        self.message = message

    def to_entry(self) -> dict[str, Any]:
        return {
            "Arguments": self.args,
            "Brand": self.brand,
            "Status": self.status.value,
            "Message": self.message,
        }


@dataclass
class IndicatorSchema:
    """
    Indicator schema + mapping rules.

    Attributes:
        type (str): Indicator type (e.g., "url", "ip", "cve").
        value_field (str | list[str]): Field name/ list of field name holding the indicator's value
        (e.g., "Data", "Address", ["MD5","SHA256"]).
        context_path_prefix (str): Context key prefix to extract (e.g., "URL(" or "IP(").
        context_output_mapping (dict[str, str]):
            Mapping rules from source context to target; the separator is `".."`.
            - {"Name": "Value"}             -> flat key rename.
            - {"Name..Value": "Value"}      -> nested extract {"Name":{"Value":x}} -> {"Value":x}.
            - Append "[]" to make the destination a list.
            - If "Score" is among mapped keys, we compute MaxScore/MaxVerdict/TIMScore.
            - If "CVSS" is among mapped keys, we Extract TIMCVSS.
    """

    type: str
    value_field: str | list[str]
    context_path_prefix: str
    context_output_mapping: dict[str, str]

    def get_all_values_from(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Collects all value fields from the given context entry based on this object's
        `value_field` definition. Supports single-field (e.g., "Address") and multi-field
        types (e.g., File hashes: ["MD5","SHA256"]).

        - For a single value_field (string), returns {"Value": <extracted_value>} using that key.
        - For multiple value_fields (list), returns only the matching fields with their original names.

        Example:
            get_all_values_from({"MD5": "aaa", "SHA256": "bbb", "Address": "ccc"})
            self.value_field = ["MD5", "SHA256"]
            → {"MD5": "aaa", "SHA256": "bbb"}

            get_all_values_from({"MD5": "aaa", "SHA256": "bbb", "Address": "ccc"})
            self.value_field = "Address"
            → {"Value": "ccc"}

        Args:
            data: The context dictionary to extract from.

        Returns:
            A dictionary of all found value fields.
        """
        out: dict[str, Any] = {}
        if isinstance(self.value_field, str):
            val = data.get(self.value_field)
            if val:
                out["Value"] = val
            return out

        lower_data = {k.lower(): v for k, v in data.items()}
        for candidate in self.value_field:
            if val := lower_data.get(candidate.lower()):
                out[candidate] = val
        return out


@dataclass
class IndicatorInstance:
    """
    Represents a single indicator undergoing the full enrichment pipeline.

    This object tracks the state of one input value across all stages of the
    enrichment flow (extract → create → enrich → TIM → final context).
    It centralizes the status, errors, enrichment results, and final outcome,
    making it easier to build the final context entries and human-readable output.

    Attributes:
        raw_input (str): The original input string provided by the user.
        extracted_value (str | None): The indicator value extracted by `extractIndicators`.
            None if extraction failed or returned no value of the expected type.
        created (bool): Whether the indicator was successfully created by `CreateNewIndicatorsOnly`.
        enriched (bool): Whether external enrichment (`enrichIndicators` or internal commands) succeeded for this indicator.
        tim_context (list[ContextResult] | None): List of TIM results (standardized enrichment results) returned from TIM search.
            None if no TIM results were found.
        hr_message (str | None): Message for human readable.
        context_message (str | None): Small message for Context, relevant for failures.
        final_status (Status): The computed status of the indicator after all enrichment stages.
            Typically SUCCESS unless any stage failed or an invalid input was detected.
    """

    raw_input: str
    extracted_value: str | None = None
    created: bool = False
    enriched: bool = False
    tim_context: list[ContextResult] | None = None
    hr_message: str | None = None
    context_message: str | None = None
    final_status: Status = Status.SUCCESS

    def compute_status(self) -> None:
        """
        Evaluates the instance's internal state to determine the final verdict (SUCCESS/FAILURE)
        and generates the appropriate Human Readable/ Context message.
        """
        # Case 1 – Invalid indicator (highest priority)
        valid = bool(self.extracted_value)
        found = bool(self.tim_context)

        if not valid:
            self.final_status = Status.FAILURE
            self.context_message = "Invalid"
            return

        elif self.enriched and found:
            self.final_status = Status.SUCCESS
            return

        # --- Failure Scenarios ---
        self.final_status = Status.FAILURE
        # Case 3 – valid, not created, not enriched, not found -> Probably creation Failed
        if not self.created and not self.enriched and not found:
            self.context_message = "Failed To Create Indicator using CreateNewIndicatorsOnly."

        # Case 4 – valid, not created, not enriched, found
        # if found -> exists so enrich failed (this it the interesting failure)
        elif not self.created and not self.enriched and found:
            self.context_message = "Failed to Enrich using enrichIndicator."

        # Case 5 – valid, created, not enriched, does not matter if found or not, enrichment failed
        elif self.created and not self.enriched:
            self.context_message = "Failed to Enrich using enrichIndicator."

        # Case 6 – valid, enriched (created or already exists), not found -> Extraction Failed
        elif self.enriched and not found:
            self.context_message = "Enrichment succeeded but extracting from TIM failed."


class CommandType(Enum):
    """
    Execution policy category:
      - INTERNAL: runs when no brands specified, or if its brand is requested (e.g., wildfire-get-verdict).
      - EXTERNAL: runs only if `external_enrichment` is True or specific brands were provided (e.g., enrichIndicator).
      - BUILTIN: server builtins (e.g., createNewIndicator) always run regardless of flags.
    """

    INTERNAL = "Internal"
    EXTERNAL = "External"
    BUILTIN = "Builtin"


class Command:
    """
    A single command spec for batch execution.
    Args:
        name (str): The command name (e.g., 'enrichIndicators', 'url').
        args (dict[str, Any]): Arguments for the command.
        brand (str): The specific integration brand to use. leave empty to exclude the command from the human readable entries.
        command_type (CommandType): The type of the command.
        ignore_using_brand (bool): Whether to add the using-brand parameter to the args.
        is_multi_input (bool): Whether the command accepts multiple inputs. Relevant for HumanReadable output.
        is_aggregated_output (bool): Whether the command return one output for multiple inputs. Relevant for HumanReadable output.
            When is_multi_input is True and not is_aggregated_output is True, will split the data list one per result entry.
        context_output_mapping (dict[str, str]):
            Mapping rules from source context to target; the separator is `".."`.
            - {"Name": "Value"}             -> flat key rename.
            - {"Name..Value": "Value"}      -> nested extract {"Name":{"Value":x}} -> {"Value":x}.
            - Append "[]" to make the destination a list.
            - If "Score" is among mapped keys, we compute MaxScore/MaxVerdict/TIMScore.
            - If "CVSS" is among mapped keys, we extract TIMCVSS.
    """

    def __init__(
        self,
        name: str,
        args: dict | None = None,
        brand: str = "",
        command_type: CommandType = CommandType.EXTERNAL,
        context_output_mapping: dict[str, str] | None = None,
        ignore_using_brand: bool = False,
        is_multi_input: bool = False,
        is_aggregated_output: bool = False,
    ):
        self.name = name
        self.args = args
        self.brand = brand
        self.command_type = command_type
        self.context_output_mapping = context_output_mapping
        self.ignore_using_brand = ignore_using_brand
        self.is_multi_input = is_multi_input
        self.is_aggregated_output = False if not is_multi_input else is_aggregated_output

    def __str__(self) -> str:
        """
        Returns a string representation of the Command object.
        """
        return f"Command(name='{self.name}', args={self.args}, type={self.command_type.value})"

    def to_batch_item(self, brands_to_run: list[str] | None = None) -> dict[str, dict[str, Any]]:
        """
        Converts the command object to the format required by `executeCommandBatch`.
        inject using-brand to args if brands_to_run is not empty and ignore_using_brand is False.
        """
        final_args = self.args.copy() if self.args else {}
        if brands_to_run and not self.ignore_using_brand:
            final_args["using-brand"] = ",".join(brands_to_run)
        return {self.name: final_args}

    def execute(self) -> list[dict[str, Any]]:
        """Executes the command and returns the results."""
        demisto.debug(f"[Command.execute] Executing command {self.name} with args: {self.args}")
        is_failed, results = execute_command(self.name, self.args, fail_on_error=False)
        if is_failed:
            demisto.debug(f"[Command.execute] Command {self.name} execution failed with error: {results}")

        demisto.debug(f"[Command.execute] Command {self.name} execution completed with {len(results)} results")
        return results


class BatchExecutor:
    """
    Executes commands in batch/batches and performs minimal, uniform result processing.
    """

    def process_results(
        self,
        results: list[list[ContextResult]],
        commands_list: list[Command],
        verbose: bool = False,
    ) -> list[CommandProcessResults]:
        """
        Normalize command results into `(result, hr_output, error_message)` tuples, skipping debug entries.

        Args:
            results (list[list[ContextResult]]): The results of the batch of commands.
            commands_list (list[Command]): The list of commands that were executed.
            verbose (bool): Whether to print verbose output.

        Returns:
            list[CommandProcessResults]: List of lists of tuples (result, hr_output, error_message).
        """
        demisto.debug("[BatchExecutor.process_results]")
        final_results = []
        for results_list, command in zip(results, commands_list):
            demisto.debug(f"Processing results for command {command.name} with {len(results_list)} results")
            processed_command_results = []
            for i, result in enumerate(results_list):
                if is_debug_entry(result):
                    demisto.debug(f"Result #{i+1} is debug")
                    continue
                hr_output = ""
                error_message = ""
                brand = result.get("Metadata", {}).get("brand") or command.brand or "Unknown"
                if is_error(result):
                    demisto.debug(f"Result #{i+1} is error")
                    error_message = get_error(result)
                    if verbose:
                        hr_output = (
                            f"#### Error for name={command.name} args={command.args} current brand={brand}\n{error_message}"
                        )
                    if human_readable := result.get("HumanReadable"):
                        hr_output += f"\n\n{human_readable}"

                elif verbose:
                    if human_readable := result.get("HumanReadable"):
                        hr_output = (
                            f"#### Result for name={command.name} args={command.args} current brand={brand}\n{human_readable}"
                        )
                demisto.debug(f"Result #{i+1} processed")
                processed_command_results.append((result, hr_output, error_message))
            final_results.append(processed_command_results)
        return final_results

    def execute_batch(
        self,
        commands: list[Command],
        brands_to_run: list[str] | None = None,
        verbose: bool = False,
    ) -> list[CommandProcessResults]:
        """
        Execute one batch (list of Command). Returns a list aligned to `commands`,
        where each item is a list of `(result, hr_output, error_message)` tuples.
        Args:
            commands (list[Command]): List of commands to execute.
            brands_to_run (list[str]): List of brands to run on.
            verbose (bool): Whether to print verbose output.
        Returns:
            list[CommandProcessResults]: List of lists of tuples (result, hr_output, error_message).
        """
        brands_to_run = brands_to_run or []
        commands_to_execute = [command.to_batch_item(brands_to_run) for command in commands]
        demisto.debug(f"Executing batch: {len(commands_to_execute)} commands; using-brands={brands_to_run or 'all'}")
        results = demisto.executeCommandBatch(commands_to_execute)  # Results is list of lists, for each command list of results
        demisto.debug("Batch returned [" + ", ".join(str(len(r)) for r in results) + "] results before processing")
        return self.process_results(results, commands, verbose)

    def execute_list_of_batches(
        self,
        list_of_batches: list[list[Command]],
        brands_to_run: list[str] | None = None,
        verbose: bool = False,
    ) -> list[list[CommandProcessResults]]:
        """
        Execute batches in order. See `execute_batch` for inner tuple shape.

        Args:
            list_of_batches (list[list[Command]]): A list of batches to execute. each batch is list of commands.
            brands_to_run (list[str]): A list of brands to run on.
            verbose (bool): Whether to print verbose output.

        Returns:
            List of corresponding results for each batch.
            Foreach batch list of results list per commands.
            Foreach command list of tuples (ContextResult, str, str) corresponding to (result, hr_output, error_message).
            Example:
            [
                [  # batch 0
                    [ (result, hr_output, error), ... ],  # command 0 results
                    [ (result, hr_output, error), ... ],  # command 1 results
                ],
                [  # batch 1
                    ...
                ]
            ]

        """
        out: list[list[list[tuple[ContextResult, str, str]]]] = []
        for i, batch in enumerate(list_of_batches):
            if not batch:
                demisto.debug(f"Skipping empty batch #{i+1} (no commands).")
                out.append([])  # keep alignment; process_results will just see nothing
                continue
            demisto.debug(f"Executing batch #{i+1} with {len(batch)} commands")
            out.append(self.execute_batch(batch, brands_to_run or [], verbose))
        return out


# --- Context Builder ---
class ContextBuilder:
    """
    A builder class to handle the aggregation and merging of context data.
    TIM data will be added under final_context_path(val.Value && val.Value == obj.Value) after some enrichments.
    DBot scores will be added to context under Common.DBotScore.CONTEXT_PATH.
    Other commands results will be added to context as is.
    Args:
        indicator (Indicator): The indicator object.
        final_context_path (str): The final context path.
    """

    def __init__(self, indicator_schema: IndicatorSchema, final_context_path: str):
        self.indicator_schema = indicator_schema
        self.final_context_path = final_context_path

        self.indicator_instances: list[IndicatorInstance] = []
        self.other_context: ContextResult = {}

    def add_indicator_instances(self, indicator_instances: list[IndicatorInstance]):
        """
        Adds TIM context to the final context.
        TIM context expected format:
        {"https://example.com": [{}, {}]}.
        Adds DBot scores to the final context.
        Args:
            tim_ctx (ContextResult): The TIM context.
            dbot_scores (DBotScoreList): The DBot scores.
        """
        self.indicator_instances.extend(indicator_instances)

    def add_other_commands_results(self, commands_ctx: ContextResult):
        """
        Adds context from non enrichment commands.
        Will be added to the final context as is.
        Args:
            commands_ctx (ContextResult): The commands context.
        """
        self.other_context.update(commands_ctx or {})

    def build(self) -> ContextResult:
        """
        Builds the final context by merging context and adding fields to indicators.
        TIM Context will be constructed as follows:
        {
            self.final_context_path(val.Value && val.Value == obj.Value):[
                {
                    "Value":"Example",
                    "MaxScore":1, //Optional
                    "MaxVerdict":"Malicious", //Optional
                    "TIMScore":1, //Optional
                    "TIMCVSS":1, //Optional
                    "Status": "Stale"/"Fresh"/"Manual",
                    "ModifiedTime": "2022-01-01T00:00:00Z",
                    "Results": [{
                        "Brand": "Brand1",
                        "Score": 1,
                        "DetectionEngines": 1,
                        "PositiveDetections": 1,
                        "Data": "Example",
                        "additionalFields": {}, //Optional
                        },
                        {
                        "Brand": "Brand2",
                        "Score": 2,
                        "DetectionEngines": 2,
                        "PositiveDetections": 2,
                        "Data": "Example",
                        }]
                },
            ],
            "OtherCommandsResults": ContextResult,
            }
        Returns:
            ContextResult: The final context.
        """
        final_context: ContextResult = {}
        if self.indicator_instances:
            indicator_list = self.create_indicator()
            self.enrich_final_indicator(indicator_list)
            final_context[f"{self.final_context_path}(val.Value && val.Value == obj.Value)"] = indicator_list
        final_context.update(self.other_context)

        return remove_empty_elements_with_exceptions(final_context, exceptions={"TIMCVSS", "Status", "ModifiedTime"})

    def create_indicator(self) -> list[dict]:
        """
        Constructs the final indicator list from the reputation context as follows:
        Input:
        {"https://example.com": [{"Brand": "Brand1","Data": "Example"},{"Brand": "Brand2","Data": "Example"}]}
        Result:
        [{
            "Value": "https://example.com",
            "Other Fields": ...
            "Results": [{"Brand": "Brand1","Data": "Example"},
                        {"Brand": "Brand2","Data": "Example"}]
        }]
        Returns:
            list[dict]: The final list structure.
        """
        results: list[dict] = []
        for indicator_instance in self.indicator_instances:
            # 1. Compute status based on internal state
            indicator_instance.compute_status()

            value = indicator_instance.extracted_value
            raw = indicator_instance.raw_input

            # 2. Handle Failure Case (Logic extracted from original Case 1, 3, 4, 5, 6)
            if indicator_instance.final_status == Status.FAILURE:
                results.append({"Value": value or raw, "Status": "Error", "Message": indicator_instance.context_message})
                continue

            # 3. Handle Success Case (Logic extracted from original Case 2)
            # If we are here, we know it is valid, enriched, and found.
            current_indicator: dict[str, Any] = {"Value": value}

            # TIM section
            if indicator_instance.tim_context and (
                tim_indicator := [indicator for indicator in indicator_instance.tim_context if indicator.get("Brand") == "TIM"]
            ):
                tim_obj = tim_indicator[0]
                # Extract File hashing if file is hash
                if self.indicator_schema.type == "file":
                    hashes_dict = self.indicator_schema.get_all_values_from(tim_obj) or build_hash_dict(value)
                    current_indicator["Hashes"] = hashes_dict
                # Main Indicator Fields
                current_indicator["Status"] = pop_dict_value(tim_obj, "Status")
                current_indicator["ModifiedTime"] = pop_dict_value(tim_obj, "ModifiedTime")

                if "Score" in self.indicator_schema.context_output_mapping:
                    current_indicator["TIMScore"] = tim_obj.get("Score")

                if "CVSS" in self.indicator_schema.context_output_mapping:
                    current_indicator["TIMCVSS"] = tim_obj.get("CVSS")

            current_indicator["Results"] = indicator_instance.tim_context
            results.append(current_indicator)
            continue

        return results

    def enrich_final_indicator(self, indicator_list: list[dict]):
        """
        Adds enrichment fields to the final indicator objects depending on the context output mapping.
        Args:
            indicator_list (list[dict]): The list of indicators to enrich.
        """
        for indicator in indicator_list:
            if "Score" in self.indicator_schema.context_output_mapping and indicator.get("Status") != "Error":
                all_scores = [res.get("Score", 0) for res in indicator.get("Results", [])] + [indicator.get("TIMScore", 0)]
                max_score = max(all_scores or [0])
                indicator["MaxScore"] = max_score
                indicator["MaxVerdict"] = DBOT_SCORE_TO_VERDICT.get(max_score, "Unknown")


class BrandManager:
    """
    Centralizes brand management.
    - requested: brands the user asked for
    - enabled: brands with active instances
    - to_run: [] => all brands, else intersection(requested, enabled)
    - missing: requested but not enabled
    - unsupported_external(...): requested brands that are only meaningful via EXTERNAL enrichment
      but currently not enabled
    """

    def __init__(self, requested: list[str] | None):
        self.requested = requested
        demisto.debug(f"[BrandManager] requested={self.requested}")

    @cached_property
    def enabled(self) -> set[str]:
        """Return set of active integration brands."""
        return BrandManager.enabled_brands()

    @staticmethod
    def enabled_brands() -> set[str]:
        """Return set of active integration brands."""
        all_modules = demisto.getModules()
        enabled_brands = {module.get("brand") for module in all_modules.values() if module.get("state") == "active"}
        demisto.debug(f"[BrandManager] enabled={enabled_brands}")
        return enabled_brands

    @staticmethod
    def get_brands_by_type(command_batches: list[list[Command]] | None, command_type: CommandType) -> list[str]:
        """
        Returns all unique brands that appear in the given command batches
        for the specified command type.
        Help getting all Internal command brands to inject them to the brand variable.
        For example when WildFire-v2 is internal enrichment brand, we will add it to brands (when external_enrichment
        is false and no brands is given). in order to not skip other Internal commands such as core-get-hash-analytics-prevalence,
        we will call this function to append the internal brands to run them as well.
        Args:
            command_batches: A list of batches containing `Command` objects.
            command_type: The command type to filter by.

        Returns:
            A list of unique brand names.

        Example:
            Input: All command batches, one of them is Internal with brand 'Cortex Core-IR'.
            Calling: get_brands_by_type(batches, CommandType.INTERNAL)
            Returns: ['Cortex Core-IR']
        """
        if not command_batches:
            return []
        brands: set[str] = set()
        for batch in command_batches:
            for command in batch:
                if command.command_type == command_type:
                    brands.add(command.brand)
        return list(brands)

    @cached_property
    def to_run(self) -> list[str]:
        """
        Active brands to run based on user input.
        If none provided, returns empty -> means "all".
        """
        if not self.requested:
            demisto.debug("No specific brands provided; will run on all available brands.")
            return []

        brands_to_execute = list(set(self.requested) & set(self.enabled))
        if not brands_to_execute:
            raise DemistoException(
                "None of the provided brands correspond to an enabled integration instance. "
                "Please ensure brand names are correct and instances are enabled."
            )
        demisto.debug(f"[BrandManager] to_run={brands_to_execute}")
        return brands_to_execute

    @cached_property
    def missing(self) -> list[str]:
        """
        Returns a list of missing brands from the given brands.
        If no brands are given, returns empty list.
        Caches the result to avoid redundant calculations.
        """
        if not self.requested:
            return []

        missing_brands = list(set(self.requested) - self.enabled)
        demisto.debug(f"[BrandManager] missing={missing_brands}")
        return missing_brands

    def unsupported_external(self, commands: list[list["Command"]]) -> list[str]:
        """
        Returns a list of unsupported enrichment brands to run on from the given brands.
        If no brands are given, returns empty list.
        Caches the result to avoid redundant calculations.
        """
        if not self.requested:
            demisto.debug("No specific brands provided; will run on all available brands.")
            return []
        non_external_brands = {
            command.brand
            for command_list in commands
            for command in command_list
            if command.command_type != CommandType.EXTERNAL and command.command_type != CommandType.BUILTIN
        }
        demisto.debug(f"[BrandManager] non_external_brands={non_external_brands}")
        external_brands = set(self.requested) - non_external_brands
        demisto.debug(f"[BrandManager] external_brands={external_brands}")
        return list(external_brands - set(self.enabled))


# --- Main Framework Abstraction ---
class AggregatedCommand(ABC):
    def __init__(
        self,
        args: dict,
        brands: list[str],
        verbose: bool,
        commands: list[list[Command]] | None = None,
    ):
        """
        Initializes the module.

        Args:
            args (dict[str, Any]): The arguments from `demisto.args()`.
            brands (list[str]): A list of specific integration brands to run.
            verbose (bool): If True, include detailed command outputs.
            commands (list[list[Command]]): List of batches of commands to run.
        """
        self.args = args
        self.brands = brands
        self.verbose = verbose
        self.commands = commands or []
        self.brand_manager = BrandManager(brands)


class ReputationAggregatedCommand(AggregatedCommand):
    def __init__(
        self,
        args: dict[str, Any],
        brands: list[str],
        indicator_schema: IndicatorSchema,
        indicator_instances: list[IndicatorInstance],
        final_context_path: str,
        external_enrichment: bool = False,
        additional_fields: bool = False,
        internal_enrichment_brands: list[str] | None = None,
        verbose: bool = False,
        commands: list[list[Command]] | None = None,
        verbose_outputs: list[str] | None = None,
    ):
        """
        Initializes the reputation aggregated command.

        Args:
            args (dict[str, Any]): The arguments from `demisto.args()`.
            brands (list[str]): List of brands to run on.
            indicator_schema (IndicatorSchema): IndicatorSchema object to use for reputation.
            indicator_instances (list[IndicatorInstance]): list of all indicator we are going to enrich, both valid and invalid.
                will hold all information on the enrichment steps.
            data (list[str]): Data to enrich Example: ["https://example.com"].
            final_context_path (str): Path to the context to extract to for the indicators, will be added to the path
                                      ExampleEnrichment(val.Value && val.Value == obj.Value).
            external_enrichment (bool): Whether to run external enrichment (e.g enrichIndicators).
            additional_fields (bool): Whether to include additional fields in the output.
            internal_enrichment_brands (list[str]): A list of internal brands to use for enrichment when no brands are provided
                                                    and external_enrichment is False. Applied only if those brands are available;
                                                    ignored otherwise.
            verbose (bool): Whether to add verbose outputs.
            commands (list[list[Command]]): List of batches of commands to run.
            verbose_outputs (list[str]): verbose outputs to add to this current verbose.
        """
        self.external_enrichment = external_enrichment
        self.final_context_path = final_context_path
        self.additional_fields = additional_fields
        self.indicator_instances = indicator_instances
        # Help to find the instance from the value itself, relevant only for extracted (valid) which we will enrich
        self.indicator_mapping = {
            indicator_instance.extracted_value: indicator_instance
            for indicator_instance in indicator_instances
            if indicator_instance.extracted_value
        }
        self.valid_inputs = [
            indicator_instance.extracted_value for indicator_instance in indicator_instances if indicator_instance.extracted_value
        ]
        self.indicator_schema = indicator_schema
        self.internal_enrichment_brands = internal_enrichment_brands or []
        self.entry_results: list[EntryResult] = []
        self.verbose_outputs = verbose_outputs or []
        # If no brands and external_enrichment is false, will insert internal enrichment if available
        # Addes internal command brands as well to make sure they also will run
        if not brands and not external_enrichment:
            active_internal_enrichment_brands = list(set(self.internal_enrichment_brands) & BrandManager.enabled_brands())
            if active_internal_enrichment_brands:
                brands = active_internal_enrichment_brands + BrandManager.get_brands_by_type(commands, CommandType.INTERNAL)
                demisto.debug("External enrichment false with no brands asked; using internal enrichment + commands")

        super().__init__(args, brands, verbose, commands)

    @cached_property
    def unsupported_enrichment_brands(self) -> list[str]:
        """Returns a list of brands that are not enabled but are required for external enrichment."""
        if not self.brands:
            return []
        return self.brand_manager.unsupported_external(self.commands)

    def run(self) -> CommandResults:
        """
        Main execution loop for the reputation aggregation.
        """
        demisto.debug("Aggregated reputation run: start")
        batch_results: list[list[list[tuple[ContextResult, str, str]]]] = []
        context_result: ContextResult = {}
        batch_verbose_outputs: list[str] = []

        demisto.debug("Step 1: Executing batch commands.")
        commands_to_execute = self.prepare_commands_batches(self.external_enrichment)
        if commands_to_execute:
            demisto.debug(
                f"Executing {sum(len(b) for b in commands_to_execute)} commands in " f"{len(commands_to_execute)} batch(es)"
            )
            batch_executor = BatchExecutor()
            batch_results = batch_executor.execute_list_of_batches(commands_to_execute, self.brand_manager.to_run, self.verbose)
            if batch_results:
                context_result, batch_verbose_outputs, entry_results = self.process_batch_results(
                    batch_results, commands_to_execute
                )
                self.verbose_outputs += batch_verbose_outputs
                self.entry_results += entry_results
            else:
                demisto.debug("No batch results.")

        demisto.debug("Step 2: Finding indicators.")
        self.get_indicators_from_tim()
        self.update_indicator_instances_status()

        demisto.debug("Step 3: Building final context.")
        context_builder = ContextBuilder(self.indicator_schema, self.final_context_path)
        context_builder.add_other_commands_results(context_result)
        context_builder.add_indicator_instances(self.indicator_instances)
        final_context = context_builder.build()

        demisto.debug("Step 4: Summarizing command results.")
        return self.summarize_command_results(self.entry_results, final_context)

    def update_indicator_instances_status(self):
        """
        Updates each IndicatorInstance based on the EntryResults of CreateNewIndicatorsOnly and enrichIndicator Commands.
        The following IndicatorInstance attributes will be updated:
        - created (bool): If CreateNewIndicatorsOnly succeeded/failed.
        - enriched (bool) If enrichIndicator succeeded/failed.
            if enrichIndicator does not exits (wasn't called) we will look at it as succeeded.
        - error_message (str): If one of the command failed will add the error message from the EntryResult Object.
        - final_status based on errors.
        """
        create_entry = next(
            (e for e in self.entry_results if e.command_name == "CreateNewIndicatorsOnly"),
            None,
        )
        demisto.debug(f"Create Entry: {create_entry}")
        enrich_entry = next(
            (e for e in self.entry_results if e.command_name == "enrichIndicators"),
            None,
        )
        demisto.debug(f"Enrich Entry: {enrich_entry}")
        errors: list[str] = []
        # Determine CreateNewIndicatorsOnly status and error message
        is_created = bool(create_entry and create_entry.status == Status.SUCCESS)
        if not is_created and create_entry:
            errors.append(create_entry.message or "Creating indicator failed.")

        # Determine enrichIndicator status and error message
        # enrich_entry is None → enrichment stage not used → treat as success
        if enrich_entry is None:
            is_enriched = True
        else:
            is_enriched = enrich_entry.status == Status.SUCCESS
            if not is_enriched:
                msg = enrich_entry.message or "Enrichment failed."
                errors.append(msg)

        for inst in self.indicator_instances:
            if inst.extracted_value:
                inst.created = is_created
                inst.enriched = is_enriched

                if errors:
                    inst.hr_message = " | ".join(errors) if errors else None

            # trigger the logic internally
            inst.compute_status()

    def prepare_commands_batches(self, external_enrichment: bool = False) -> list[list[Command]]:
        """
        The commands that will be added to execution are filtered as follow:
        1. external_enrichment=False, brands=[] → INTERNAL + BUILTIN.
        2. external_enrichment=True, brands=[] → INTERNAL + EXTERNAL + BUILTIN.
        3. external_enrichment=False, brands != []:
            - INTERNAL only if command.brand in self.brands.
            - EXTERNAL: all external commands are included (using-brand: {brands} injected to the command later).
            - BUILTIN included.
        Args:
            external_enrichment (bool): Flag to determine if external commands should run.
        Return:
            list[list[Command]]: The command batches after filtering.
        """
        demisto.debug(f"Preparing commands. External enrichment: {external_enrichment}")
        prepared_commands: list[list[Command]] = []
        for command_list in self.commands:
            current_command_list: list[Command] = []
            for command in command_list:
                if command.command_type == CommandType.INTERNAL and (command.brand in self.brands or not self.brands):
                    # If Command is internal and brand is in brands or brands is empty, add it to the list.
                    demisto.debug(f"Adding internal command {command}")
                    current_command_list.append(command)

                elif command.command_type == CommandType.EXTERNAL and (external_enrichment or self.brands):
                    # If Command is external and external_enrichment is True or brands is not empty, add it to the list.
                    demisto.debug(f"Adding external command {command}")
                    current_command_list.append(command)  # added using-brand argument on execution

                elif command.command_type == CommandType.BUILTIN:
                    # If Command is built-in, add it to the list.
                    demisto.debug(f"Adding Builtin command {command}")
                    current_command_list.append(command)

                else:
                    demisto.debug(f"Skipping command {command} | {command.command_type} | {self.brands}")
            prepared_commands.append(current_command_list)

        return prepared_commands

    def get_indicators_from_tim(self):
        """
        Searches TIM for indicators and processes the results.
        Updates the relevant Fields of each of the indicator instances.
        """
        iocs = self.search_indicators_in_tim()
        if not iocs:
            demisto.debug("No Search Results")
            return

        self.process_tim_results(iocs)

    def search_indicators_in_tim(self) -> list[ContextResult]:
        """
        Performs the actual search against TIM using the IndicatorsSearcher class.
        Returns:
            list[ContextResult]: The search results.
        """
        indicator_values = " or ".join(
            {
                f"value:{indicator_instance.extracted_value}"
                for indicator_instance in self.indicator_instances
                if indicator_instance.extracted_value
            }
        )
        query = f"type:{self.indicator_schema.type} and ({indicator_values})"
        try:
            demisto.debug(f"Executing TIM search with query: {query}")
            searcher = IndicatorsSearcher(query=query)
            iocs = flatten_list([res.get("iocs", []) for res in searcher])
            demisto.debug(f"TIM search returned {len(iocs)} raw IOCs.")

            if not iocs:
                return []
            return iocs
        except Exception as e:
            msg = f"Error searching TIM: {e}\n{traceback.format_exc()}"
            demisto.debug(msg)
            for indicator_instance in self.indicator_instances:
                if indicator_instance.extracted_value:
                    indicator_instance.hr_message = msg
            return []

    def process_tim_results(self, iocs: list[dict[str, Any]]):
        """Processes raw IOCs from a TIM search into structured context.
        Updates the indicator instances tim_context with the relevant extracted context.
        Args:
            iocs (list[dict[str, Any]]): The IOC objects from the TIM search.
        """
        demisto.debug(f"Processing {len(iocs)} IOCs from TIM.")

        for i, ioc in enumerate(iocs):
            demisto.debug(f"Processing #{i+1} TIM result")
            parsed_indicators, value, message = self._process_single_tim_ioc(ioc)
            indicator_instance = self.indicator_mapping[value]
            indicator_instance.tim_context = parsed_indicators
            indicator_instance.hr_message = message

    def _process_single_tim_ioc(self, ioc: dict[str, Any]) -> tuple[list[dict], str, str]:
        """
        Processes a single IOC object returned from a TIM search.
        Extract Score and brand and add them to parsed indicators.
        Args:
            ioc (dict[str, Any]): The IOC object to process.
        Returns:
            tuple[list[dict], str, str]: The parsed indicators, indicator value, and hr message for final table.
        """
        all_parsed_indicators: list[ContextResult] = []
        tim_indicator = self.create_tim_indicator(ioc)
        all_parsed_indicators.append(tim_indicator)

        value = tim_indicator.get("Value", "")

        found_brands = []
        demisto.debug(f"Extracting per brand information for {value}")
        for brand, brand_data in ioc.get("insightCache", {}).get("scores", {}).items():
            demisto.debug(f"Processing TIM indicators from brand: {brand}")
            score = brand_data.get("score", 0)
            context = brand_data.get("context", {})
            reliability = brand_data.get("reliability", "")
            parsed_indicators = self.parse_indicator(context, brand, reliability, score)
            if parsed_indicators:
                found_brands.append(brand)
            all_parsed_indicators.extend(parsed_indicators)

        message = f"Found indicator from brands: {', '.join(found_brands)}." if found_brands else "No matching indicators found."

        return all_parsed_indicators, value, message

    def create_tim_indicator(self, ioc: dict[str, Any]) -> dict[str, Any]:
        """
        Creates a TIM indicator from a TIM IOC CustomFields and Main Fields.
        Relevant for extracting the Score/Status/ModifiedTime from the TIM IOC to the main context.
        Args:
            ioc (dict[str, Any]): The TIM IOC to create a TIM indicator from.
        Returns:
            dict[str, Any]: The TIM indicator.
        """
        demisto.debug("Extracting Custom Fields")
        customFields = ioc.get("CustomFields", {})
        # all Keys under CustomFields are lowercase while the mapping are CamelCase, this insure we will find the right keys
        lower_mapping = {k.lower(): v for k, v in self.indicator_schema.context_output_mapping.items()}
        mapped_indicator = self.map_command_context(customFields.copy(), lower_mapping, is_indicator=True)

        if "Score" in self.indicator_schema.context_output_mapping:
            mapped_indicator.update({"Score": ioc.get("score", Common.DBotScore.NONE)})
        if "CVSS" in self.indicator_schema.context_output_mapping:
            mapped_indicator.update({"CVSS": customFields.get("cvssscore")})
        mapped_indicator.update(
            {
                "Brand": "TIM",
                "Status": self.get_indicator_status_from_ioc(ioc),
                "ModifiedTime": ioc.get("modifiedTime"),
            }
        )
        if self.indicator_schema.type == "file":
            value = map_back_to_input(
                values=self.valid_inputs, mapping=self.indicator_schema.get_all_values_from(mapped_indicator)
            ) or ioc.get("value")
        else:
            value = ioc.get("value", "")
        mapped_indicator.update({"Value": value})
        demisto.debug(f"Created TIM Indicator for {value}")
        return mapped_indicator

    def get_indicator_status_from_ioc(self, ioc: dict) -> str | None:
        """
        Determine the status of a dict based on manual edits and modification time.

        Rules:
        - If "Score" is in manuallyEditedFields → "manual"
        - Else if modifiedTime is less than STATUS_FRESHNESS_WINDOW ago → "fresh"
        - Else → "stale"
        """
        manually_edited_fields = ioc.get("manuallyEditedFields", {})
        if "Score" in manually_edited_fields or "score" in manually_edited_fields:
            return IndicatorStatus.MANUAL.value

        modified_time_str = ioc.get("modifiedTime")
        if modified_time_str:
            try:
                modified_time = datetime.fromisoformat(modified_time_str.replace("Z", "+00:00"))
            except ValueError:
                return None

            if modified_time >= datetime.now(modified_time.tzinfo) - STATUS_FRESHNESS_WINDOW:
                return IndicatorStatus.FRESH.value
            else:
                return IndicatorStatus.STALE.value

        return None

    def process_batch_results(
        self,
        all_results: list[list[list[tuple[ContextResult, str, str]]]],
        commands_to_execute: list[list[Command]],
    ) -> tuple[ContextResult, list[str], list[EntryResult]]:
        """
        Processes the results from the batch executor.
        runs through the execution results and processes each result according to the command parameters.
        Construct entry results and context results.

        Args:
            all_results (list[list[ContextResult]]): The results from the batch executor for all commands.
            commands_to_execute (list[Command]): The commands to execute.
        Returns:
            tuple[
                ContextResult, The non-reputation context output.
                list[str], The verbose command results.
                list[EntryResult], The entry results.
            ]
        """
        verbose_outputs: list[str] = []
        entry_results: list[EntryResult] = []
        context_result: ContextResult = defaultdict(lambda: defaultdict(list))

        demisto.debug(f"Processing {len(all_results)} batches.")
        for j, (command_batch, results_batch) in enumerate(zip(commands_to_execute, all_results)):
            demisto.debug(f"Processing batch {j}.")
            for command, processed_results_list in zip(command_batch, results_batch):
                demisto.debug(f"Processing result for command: {command} len: {len(processed_results_list)}")
                for i, result_tuple in enumerate(processed_results_list):
                    entry, mapped_ctx, verbose = self._process_single_command_result(result_tuple, command)
                    if not command.is_aggregated_output and command.is_multi_input and i < len(self.valid_inputs):
                        # Only if the command input is list and the command return many Command results.
                        entry.args = self.valid_inputs[i]

                    entry_results.append(entry)
                    deep_merge_in_place(context_result, mapped_ctx)
                    if verbose:
                        verbose_outputs.append(verbose)

                demisto.debug(f"Command {command} processed.")

        return context_result, verbose_outputs, entry_results

    def _process_single_command_result(
        self, result: tuple[ContextResult, str, str], command: Command
    ) -> tuple[EntryResult, ContextResult, str | None]:
        """
        Processes a single result from a batch command execution.
        Args:
            result (tuple[ContextResult, str, str]): The result from the batch command execution.
            command (Command): The command to execute.
        Returns:
            tuple[EntryResult, ContextResult, str | None]: The entry result, context result, and verbose output.
        """
        raw_result, hr_output, error = result

        entry = EntryResult(
            command_name=command.name,
            args=command.args,
            brand=command.brand,
            status=Status.SUCCESS if not error else Status.FAILURE,
            message=error or "No matching indicators found.",
        )

        mapped_context: ContextResult = {}
        if cmd_context := raw_result.get("EntryContext", {}):
            entry.message = error if error else ""
            demisto.debug(f"EntryContext found for command {command.name}")
            mapped_context = self.map_command_context(cmd_context.copy(), command.context_output_mapping)

        verbose_output = hr_output if self.verbose else None
        return entry, mapped_context, verbose_output

    def map_command_context(
        self, entry_context: dict[str, Any], context_output_mapping: dict[str, str] | None, is_indicator: bool = False
    ) -> dict[str, Any]:
        """
        Maps the entry context item to the final context using the mapping.
        Can add [] to transform the final path value to list.
        If mapping is empty, return entry_context.
        If mapping is None, return empty dict.
        Args:
            entry_context (dict[str, Any]): The entry context item.
            mapping (dict[str, str]): The mapping to use.
            Example1:
                mapping = {"result..value": "final_context..value"}
                {"results":{"value":value}} -> {"final_context":{"value":value}}
            Example2:
                mapping = {"result..value": "final_context..value[]"}
                {"results":{"value":value}} -> {"final_context":{"value":[value]}}
        Returns:
            dict[str, Any]: The mapped context.
        """
        if context_output_mapping is None:
            demisto.debug("Mapping is None, return Empty Dict.")
            return {}

        if not context_output_mapping:
            demisto.debug("Mapping is empty, return entry_context.")
            return entry_context

        if not entry_context:
            demisto.debug("No entry context provided, returning empty context.")
            return {}

        mapped_context: ContextResult = defaultdict()
        demisto.debug(f"Starting context mapping with {len(context_output_mapping)} rules. is_indicator: {is_indicator}")
        for src_path, dst_path in context_output_mapping.items():
            if (value := pop_dict_value(entry_context, src_path)) is not None:
                set_dict_value(mapped_context, dst_path, value)

        if self.additional_fields and is_indicator and entry_context:
            demisto.debug(f"Adding {len(entry_context)} remaining fields to AdditionalFields.")
            set_dict_value(mapped_context, "AdditionalFields", entry_context)

        return dict(mapped_context)

    def parse_indicator(
        self,
        entry_context: ContextResult,
        brand: str,
        reliability: str,
        score: int = Common.DBotScore.NONE,
    ) -> list[ContextResult]:
        """
        Parse the indicator context and complete missing fields such as brand, score, verdict if needed.
        self.indicator.context_output_mapping is used to map the indicator context to the final context.
        What is not mapped is added to the AdditionalFields if AdditionalFields is enabled.
        Final indicator is saved under the following structure:
        {indicator_value: {brand: [indicator]}}
        {"https://example.com":[
                {"indicator_value":"https://example.com",
                "brand":"brand",
                "score": 1,
                "verdict": "Good"},
                ]
        }
        Args:
            entry_context (ContextResult): The entry context item straight from the command result.entry_context.
            brand (str): The brand from the result.metadata.brand.
            score (int, optional): The score. Defaults to Common.DBotScore.NONE.
        Returns:
            list[ContextResult]: The parsed result.
        """
        demisto.debug(f"Starting parsing indicators from brand '{brand}'.")
        indicators_context: list[ContextResult] = []
        indicator_entries = flatten_list(
            [v for k, v in entry_context.items() if k.startswith(self.indicator_schema.context_path_prefix)]
        )
        demisto.debug(f"Extracted {len(indicator_entries)} indicators from {brand} entry context.")

        for indicator_data in indicator_entries:
            indicator_value = self.indicator_schema.get_all_values_from(indicator_data)
            demisto.debug(f"Parsing indicator: {indicator_value}")
            mapped_indicator = self.map_command_context(
                indicator_data, self.indicator_schema.context_output_mapping, is_indicator=True
            )
            if "Score" in self.indicator_schema.context_output_mapping:
                mapped_indicator["Score"] = score
                mapped_indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(score, "Unknown")
            mapped_indicator["Brand"] = brand
            mapped_indicator["Reliability"] = reliability
            indicators_context.append(mapped_indicator)
            demisto.debug(f"Parsed indicator '{indicator_value}' from brand '{brand}'")

        return indicators_context

    def summarize_command_results(self, entries: list[EntryResult], final_context: dict[str, Any]) -> CommandResults:
        """
        Construct the final Command Result with the appropriate readable output and context.
        Summarizes the human readable output.
        Adds verbose messages from all commands if verbose is True.
        If all commands failed, return an error message.
        If no indicator found and at least one command failed, return error message.
        If all commands succeeded with no indicators found, return a success message.
        If at least one command succeeded with indicators found, return a success message.

        Args:
            entries (list[EntryResult]): The entry results of the TIM.
            final_context (ContextResult): The final context.
        Returns:
            CommandResults: The command results.
        """
        demisto.debug(f"Summarizing final results from {len(entries)} command entries.")
        self.create_indicators_entry_results()
        if self.unsupported_enrichment_brands:
            # Add Entry with all requested unsupported brands.
            demisto.debug(f"Missing brands: {self.unsupported_enrichment_brands}")
            for unsupported_enrichment_brand in self.unsupported_enrichment_brands:
                entries.append(
                    EntryResult(
                        command_name=self.indicator_schema.type,
                        args="",
                        brand=unsupported_enrichment_brand,
                        status=Status.FAILURE,
                        message="Unsupported Command: Verify you have proper integrations enabled to support it",
                    )
                )
        human_readable = tableToMarkdown(
            "Final Results",
            # Remove Entries from non brands command such as CreateNewIndicator and EnrichIndicator
            t=[entry.to_entry() for entry in entries if entry.brand != ""],
            headers=["Brand", "Arguments", "Status", "Message"],
        )
        if self.verbose and self.verbose_outputs:
            demisto.debug("Adding verbose outputs to human readable.")
            human_readable += "\n\n".join(self.verbose_outputs)

        # Return an error only if there were no successes AND at least one of those was a hard failure.
        if all(entry.status == Status.FAILURE or entry.message == "No matching indicators found." for entry in entries) and any(
            entry.status == Status.FAILURE for entry in entries
        ):
            # Error when all failed, or some failed and the other had no indicators found.
            # If no indicators found, it is not an error.
            demisto.debug("All commands failed or no indicators found. Returning an error entry.")
            return CommandResults(
                readable_output="Error: All commands failed or no indicators found.\n" + human_readable,
                outputs=final_context,
                entry_type=EntryType.ERROR,
            )

        demisto.debug("All commands succeeded. Returning a success entry.")
        return CommandResults(readable_output=human_readable, outputs=final_context)

    def create_indicators_entry_results(self):
        """
        Create one EntryResult Object for each of the indicator instances, based on the commands and enrichment process.
        Relevant for the final HR table.
        """
        entry_results: list[EntryResult] = []
        for indicator_instance in self.indicator_instances:
            entry_results.append(
                EntryResult(
                    command_name="",
                    brand="TIM",
                    status=indicator_instance.final_status,
                    args=indicator_instance.extracted_value or indicator_instance.raw_input,
                    message=indicator_instance.hr_message or indicator_instance.context_message or "",
                )
            )
        self.entry_results[:0] = entry_results


"""HELPER FUNCTIONS"""


def build_hash_dict(value: str | None) -> dict[str, str]:
    """
    Constructs a dictionary mapping the hash type to the hash value.

    Args:
        value (str): The hash string to process.

    Returns:
        dict[str, str]: A dictionary where the key is the uppercase hash type
                        (e.g., "MD5") and the value is the original hash string.
    """
    if value:
        return {get_hash_type(value).upper(): value}
    return {}


def map_back_to_input(values: list[str], mapping: dict[str, str]) -> str:
    """
    Find the original input value that matches one of the mapped hash values.

    This compares `values` to `mapping.values()` case-insensitively and returns the first
    input value that appears in the mapping (e.g., to map back from TIM hash fields to the
    hash the user originally provided).

    Args:
        values: Original input values (e.g., hashes provided by the user).
        mapping: Hash field → value mapping (e.g., {"MD5": "...", "SHA256": "..."}).

    Returns:
        The matching original value, or an empty string if no match is found.
    """
    lower_mapping_values = [v.lower() for v in mapping.values()]
    for v in values:
        if v.lower() in lower_mapping_values:
            return v
    return ""


def create_and_extract_indicators(
    data: list[str],
    indicator_type: str,
    mark_mismatched_type_as_invalid: bool = False,
) -> tuple[list[IndicatorInstance], str]:
    """
    Extract indicators from the provided input list for a specific indicator type,
    using the `extractIndicators` command.

    Args:
        data (list[str]): Raw input values to validate/extract.
        indicator_type (str): Expected indicator type (e.g., "url", "file").
        mark_mismatched_type_as_invalid (bool): When True, inputs that are also
            extracted as additional types (e.g., URL + Domain) are treated as
            invalid for this call.

    Returns:
        tuple[list[IndicatorInstance], str]:
            - list[IndicatorInstance]: list of all created indicator instances.
            - str: Human-readable markdown summary of the extraction per input.

    Raises:
        ValueError: If no valid indicators of the requested type are found at all.
    """
    if not data:
        raise ValueError("No data provided to enrich")

    indicators_instances: list[IndicatorInstance] = []
    hr: str = ""
    valid_set: set[str] = set()
    invalid_set: set[str] = set()
    expected_type_lower = indicator_type.lower()

    for raw in data:
        demisto.debug(f"Validating input '{raw}' using extractIndicators")

        hr += f"\n\n### Result for name=extractIndicators args='text': {raw}\n\n"

        try:
            results = execute_command("extractIndicators", {"text": raw}, extract_contents=False)

            extracted_ctx = results[0].get("EntryContext", {}).get("ExtractedIndicators", {}) or {}
            demisto.debug(f"extractIndicators context for '{raw}': {extracted_ctx}")
            hr += tableToMarkdown(name="Extracted Indicators", t=extracted_ctx)

        except Exception as ex:
            msg = str(ex)
            demisto.debug(f"extractIndicators failed for '{raw}': {msg}")
            hr += f"Error Message: {msg}"
            if raw not in invalid_set:
                indicators_instances.append(IndicatorInstance(raw_input=raw, hr_message=msg, final_status=Status.FAILURE))
                invalid_set.add(raw)
            continue

        if not extracted_ctx:
            demisto.debug("Invalid Input (no indicators extracted)")
            if raw not in invalid_set:
                indicators_instances.append(IndicatorInstance(raw_input=raw, final_status=Status.FAILURE, hr_message="Invalid"))
                invalid_set.add(raw)

        else:
            expected_indicators = []
            has_other_types = False
            for key, indicators in extracted_ctx.items():
                if key.lower() == expected_type_lower:
                    expected_indicators = indicators
                else:
                    has_other_types = True
            demisto.debug(f"expected for '{raw}': {expected_indicators}, other types exits={has_other_types}")

            if not expected_indicators and raw not in invalid_set:
                # Extracted something, but not of the expected type -> invalid for this call
                demisto.debug("Invalid input (no indicators of expected type)")
                indicators_instances.append(IndicatorInstance(raw_input=raw, hr_message="Invalid", final_status=Status.FAILURE))
                invalid_set.add(raw)
            elif mark_mismatched_type_as_invalid and has_other_types and raw not in invalid_set:
                # We got expected type + other types and we choose to treat that as invalid
                demisto.debug("Invalid input (mismatched additional types present)")
                indicators_instances.append(IndicatorInstance(raw_input=raw, hr_message="Invalid", final_status=Status.FAILURE))
                invalid_set.add(raw)
            else:
                demisto.debug("Valid input")
                for expected_indicator in expected_indicators:
                    if expected_indicator not in valid_set:
                        indicators_instances.append(IndicatorInstance(raw_input=raw, extracted_value=expected_indicator))
                        valid_set.add(expected_indicator)

    if not valid_set:
        raise ValueError("No valid indicators found in the input data.")
    demisto.debug(f"Valid Inputs: {valid_set}")
    demisto.debug(f"Invalid Inputs: {invalid_set}")
    return indicators_instances, hr


def deep_merge_in_place(dst: dict, src: dict) -> None:
    """
    Recursively merges src into dst. If a key exists in both and the
    value is a list, it extends the list. For nested dicts, it recurses.
    This function modifies dst in place.

    Args:
        dst (dict): The first dictionary to merge to.
        src (dict): The second dictionary to merge from.
    """
    if not src:
        return
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            deep_merge_in_place(dst[k], v)
        elif k in dst and isinstance(dst[k], list) and isinstance(v, list):
            dst[k].extend(v)
        else:
            dst[k] = v


def flatten_list(nested_list: list[Any]) -> list[Any]:
    """
    Recursively flattens a nested list of lists.
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


def set_dict_value(d: dict[str, Any], path: str, value: Any) -> None:
    """
    Sets a value in a nested dictionary using a '..' separated path.
    Appends to a list if the path ends with '[]'.

    Args:
        d (dict[str, Any]): Dictionary to set nested key in.
        path (str): A double dot-separated key path (e.g "Signature.Copyright")
        value (Any): Value to set in the dictionary.
    """
    if path is None:
        return

    is_list = path.endswith("[]")
    if is_list:
        path = path[:-2]

    parts = path.split("..")
    current = d
    for part in parts[:-1]:
        current = current.setdefault(part, {})

    last_part = parts[-1]
    if is_list:
        current.setdefault(last_part, []).append(value)
    else:
        current[last_part] = value


def pop_dict_value(d: dict[str, Any], path: str) -> Any:
    """
    Retrieves a value from a nested dictionary given a ".." separated path.
    after getting remove the item from the dict.
    Returns `None` if any key along the path doesn’t exist.

    Args:
        d (Mapping[str, Any]): Dictionary to get nested key from.
        path (str): A ".." separated key path (e.g. "Signature..Copyright").
    """
    keys = path.split("..")
    current = d
    for key in keys[:-1]:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None  # Path not found

    last_key = keys[-1]
    if isinstance(current, dict) and last_key in current:
        return current.pop(last_key)

    return None


def is_debug_entry(execute_command_result) -> bool:
    """
    Check if the given execute_command_result is a debug entry.

    Args:
        execute_command_result: Demisto entry (required) or result of demisto.executeCommand()

    Returns:
        bool: True if the execute_command_result is a debug entry, false otherwise
    """
    if execute_command_result is None:
        return False

    if isinstance(execute_command_result, list) and len(execute_command_result) > 0:
        for entry in execute_command_result:
            if isinstance(entry, dict) and entry["Type"] == entryTypes["debug"]:
                return True

    return isinstance(execute_command_result, dict) and execute_command_result["Type"] == entryTypes["debug"]


def remove_empty_elements_with_exceptions(d, exceptions: set[str] | None = None) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary,
    unless their key is in the `exceptions` set.
    Args:
        d (dict): The dictionary to remove empty elements from.
        exceptions (set[str], optional): A set of keys to keep even if their values are empty. Defaults to set().
    Returns:
        dict: The dictionary with empty elements removed.
    """
    exceptions: set[str] = exceptions or set()

    def empty(k, v) -> bool:
        """Check if a value is considered empty, unless the key is in exceptions."""
        if isinstance(v, dict | list):
            return not v  # empty dict or list
        return v is None and (k not in exceptions if exceptions else True)

    if isinstance(d, list):
        return [v for v in (remove_empty_elements_with_exceptions(v, exceptions) for v in d) if v not in (None, {}, [])]

    elif isinstance(d, dict):
        result = {}
        for k, v in d.items():
            cleaned = remove_empty_elements_with_exceptions(v, exceptions)
            if not empty(k, cleaned) or k in exceptions:
                result[k] = cleaned
        return result

    else:
        return d
