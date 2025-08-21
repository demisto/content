from abc import ABC
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
import traceback
from typing import Any

from CommonServerPython import *
import demistomock as demisto

# Type alias for complex dictionary structures to improve readability
ContextResult = dict[str, Any]
DBotScoreList = list[ContextResult]


DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}

CVSS_TO_VERDICT = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}
SEVERITY_ORDER = ["None", "Low", "Medium", "High", "Critical"]


class Status(Enum):
    """Enum for command status."""

    SUCCESS = "Success"
    FAILURE = "Failure"


# --- Core Enumerations and Data Classes ---
class EntryResult:
    """
    Represents an entry result from a command.

    Attributes:
        command_name (str): The name of the command.
        brand (str): The brand of the command.
        args (str): The arguments associated with the entry as a string.
        status (Status): The status of the command.
        message (str): The message associated with the entry.
    """

    def __init__(self, command_name: str, args: str, brand: str, status: Status, message: str):
        self.command_name = command_name
        self.args = args
        self.brand = brand
        self.status = status
        self.message = message

    def to_entry(self) -> dict[str, Any]:
        return {
            "args": self.args,
            "brand": self.brand,
            "status": self.status.value,
            "message": self.message,
        }


@dataclass
class Indicator:
    """
    Represents an indicator type and its context mapping rules.

    Attributes:
        type (str): The indicator type (e.g., 'url', 'ip', 'cve').
        value_field (str): The field name holding the indicator's value (e.g., 'Data', 'Address').
        context_path_prefix (str): The context path prefix for the indicator (e.g., 'URL(', 'IP(').
        context_output_mapping (dict[str, str]): Mapping rules for the command's output.
            - {"Name": "Value"} will change the key "Name" to "Value".
            - {"Name..Value": "Value"} will map the context {"Name": {"Value": "example"}} to {"Value": "example"}.
            - When empty mapping is given, the context result will be mapped to the same name.
            - Append '[]' in the end to transform the final value to a list.
            - If "Score" is one of the keys, the final indicator will be enriched with MaxScore, MaxVerdict.
            - If "CVSS" is one of the keys, the final indicator will be enriched with MaxCVSS, MaxCVSSRating.
    """
    type: str
    value_field: str
    context_path_prefix: str
    context_output_mapping: dict[str, str]


class CommandType(Enum):
    """
    Categorizes commands for execution logic.
    - internal: Always executed unless specific brands are requested that don't include it.
    - external: Executed only if `external_enrichment` is True or brand is not empty.
    - regular: For future use or custom command types.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
    REGULAR = "regular"


class Command:
    """
    Represents a single command to be executed.

    Attributes:
        name (str): The command name (e.g., 'ip', 'url').
        args (dict[str, Any]): Arguments for the command.
        brand (str): The specific integration brand to use.
        command_type (CommandType): The type of the command.
        context_output_mapping (dict[str, str]): Mapping rules for the command's output.
            - {"Name": "Value"} will change the key "Name" to "Value".
            - {"Name..Value": "Value"} will map the context {"Name": {"Value": "example"}} to {"Value": "example"}.
            - When empty mapping is given, the context result will be mapped to the same name.
            - Append '[]' in the end to transform the final value to a list.
            - If "Score" is one of the keys, the final indicator will be enriched with MaxScore, MaxVerdict.
            - If "CVSS" is one of the keys, the final indicator will be enriched with MaxCVSS, MaxCVSSRating.
    """

    def __init__(
        self,
        name: str,
        args: dict = {},
        brand: str = "",
        command_type: CommandType = CommandType.REGULAR,
        context_output_mapping: dict[str, str] = {},
    ):
        self.name = name
        self.args = args
        self.brand = brand
        self.command_type = command_type
        self.context_output_mapping = context_output_mapping

    def __str__(self) -> str:
        """
        Returns a string representation of the Command object.
        """
        return f"Command(name='{self.name}', args={self.args}, type={self.command_type.value})"

    def to_batch_item(self, brands_to_run: list[str] = []) -> dict[str, dict[str, Any]]:
        """Converts the command to the format required by `executeCommandBatch`."""
        final_args = self.args.copy()
        if brands_to_run:
            final_args["using-brand"] = ",".join(brands_to_run)
        return {self.name: final_args}

    def execute(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Executes the command and returns the results."""
        demisto.debug(f"[Command.execute] Executing command {self.name} with args: {self.args}")
        results, errors = execute_command(self.name, self.args)
        demisto.debug(f"[Command.execute] Command {self.name} execution completed with {len(results)} results")
        return results, errors


class ReputationCommand(Command):
    """
    Initializes a ReputationCommand object.
    Args:
        indicator (Indicator): The indicator object.
        data (str): The data to enrich only one per command.
    """

    def __init__(self, indicator: Indicator, data: str):
        demisto.debug(f"Creating ReputationCommand for indicator type '{indicator.type}' with data: {data}")
        super().__init__(
            name=indicator.type,
            args={indicator.type: data},
            command_type=CommandType.EXTERNAL,
            context_output_mapping=indicator.context_output_mapping,
        )
        self.indicator = indicator


class BatchExecutor:
    """
    Initializes a BatchExecutor object.
    Args:
        commands (list[Command]): A list of Command objects to execute.
        brands_to_run (list[str]): A list of brands to run on.
    """

    def __init__(self, commands: list[Command], brands_to_run: list[str] = []):
        self.commands = commands
        self.brands_to_run = brands_to_run
        if not self.commands:
            demisto.info("BatchExecutor initialized with no commands. Returning empty list.")
            raise ValueError("BatchExecutor initialized with no commands.")

    def execute(self) -> list[list[dict]]:
        """
        Executes commands in a batch.

        Returns:
            A list where each item is a list of results for the corresponding command.
        """
        commands_to_execute = [command.to_batch_item(self.brands_to_run) for command in self.commands]
        demisto.debug(f"Executing batch of {len(commands_to_execute)} commands. Brands: {self.brands_to_run or 'all'}")
        results = demisto.executeCommandBatch(commands_to_execute)
        demisto.debug(f"Batch execution completed with {len(results)} result sets.")
        return results


# --- Context Builder ---
class ContextBuilder:
    """
    A builder class to handle the aggregation and merging of context data.
    Support merging reputation sources and DBot scores with priority ranks where higher ranks win.
    merge other commands results straightforward.
    Args:
        indicator (Indicator): The indicator object.
        final_context_path (str): The final context path.
    """

    def __init__(self, indicator: Indicator, final_context_path: str):
        self.indicator = indicator
        self.final_context_path = final_context_path
        self.reputation_context: list[tuple[int, ContextResult]] = []
        self.dbot_context: list[tuple[int, DBotScoreList]] = []
        self.other_context: ContextResult = {}

    def add_reputation_context(self, reputation_ctx: ContextResult, dbot_scores: DBotScoreList, priority: int):
        """Adds a data source with a given priority. Higher numbers win.
        Reputation Context expected format:
        {"https://example.com": {"brandA": [{"data": "value"}]}}
        Args:
            reputation_ctx (ContextResult): The reputation context.
            dbot_scores (DBotScoreList): The DBot scores.
            priority (int): The priority of the data source.
        """
        if reputation_ctx:
            self.reputation_context.append((priority, reputation_ctx))
        if dbot_scores:
            self.dbot_context.append((priority, dbot_scores))

    def add_other_commands_results(self, commands_ctx: ContextResult):
        """Adds context from non-prioritized commands.
        Args:
            commands_ctx (ContextResult): The commands context.
        """
        self.other_context.update(commands_ctx or {})

    def build(self) -> ContextResult:
        """
        Builds the final context by merging sources according to their priority.
        Returns:
            ContextResult: The final context.
        """
        # 1. Merge Reputation Context
        merged_reputation_map: dict[str, dict[str, Any]] = self.merge_indicators()

        # 2. Merge DBot Scores
        merged_dbot_map: dict[tuple[str, str], dict[str, Any]] = self.merge_dbot_scores()

        # 3. Assemble the Final Context
        final_context = self.other_context
        indicator_list = self.create_indicator_list(merged_reputation_map)
        self.enrich_final_indicator(indicator_list)

        final_context[f"{self.final_context_path}(val.Value && val.Value == obj.Value)"] = indicator_list
        final_context[Common.DBotScore.CONTEXT_PATH] = list(merged_dbot_map.values())
        final_context.update(self.other_context)

        return remove_empty_elements_with_exceptions(final_context, exceptions={"MaxCVSS", "MaxSeverity"})

    def merge_indicators(self) -> dict[str, dict[str, Any]]:
        """
        Merges reputation sources with priority ranks where higher ranks win.
        Example:
        {"https://example.com": {"brandA": [{"data": "value"}]}} priority 1
        {"https://example.com": {"brandA": [{"data": "value2"}]}} priority 2
        {"https://example.com": {"brandB": [{"data": "value"}]}} priority 2
        {"https://example2.com": {"brandC": [{"data": "value"}]}} priority 1
        Result:
        {"https://example.com": {"brandA": [{"data": "value2"}], "brandB": [{"data": "value"}]}}
        {"https://example2.com": {"brandC": [{"data": "value"}]}}
        Args:
            merged_map (dict): The merged reputation map.
        Returns:
            list[dict]: The final list structure.
        """
        sorted_rep_sources = sorted(self.reputation_context, key=lambda x: x[0], reverse=True)
        merged_reputation_map: dict[str, dict[str, Any]] = {}

        for _, context in sorted_rep_sources:
            for indicator_value, brands_from_source in context.items():
                if indicator_value not in merged_reputation_map:
                    merged_reputation_map[indicator_value] = {}

                for brand, results in brands_from_source.items():
                    if brand not in merged_reputation_map[indicator_value]:
                        merged_reputation_map[indicator_value][brand] = results

        return merged_reputation_map

    def merge_dbot_scores(self) -> dict[tuple[str, str], dict[str, Any]]:
        """
        Merges DBot scores with priority ranks where higher ranks win.
        Args:
            merged_map (dict): The merged reputation map.
        Returns:
            list[dict]: The final list structure.
        """
        merged_dbot_map: dict[tuple[str, str], Any] = {}
        sorted_dbot_sources = sorted(self.dbot_context, key=lambda x: x[0], reverse=True)
        for _, dbot_list in sorted_dbot_sources:
            for item in dbot_list:
                key = (item.get("Indicator", ""), item.get("Vendor", ""))
                if key not in merged_dbot_map:
                    merged_dbot_map[key] = item
        return merged_dbot_map

    def create_indicator_list(self, merged_map: dict[str, dict[str, Any]]) -> list[dict]:
        """
        Converts the merged reputation map into the final list structure.
        Example:
        {"https://example.com": {"brandA": [{"data": "value2"}],
                                 "brandB": [{"data": "value"}]}}
        Result:
        [{"Value": "https://example.com",
           "Results": [{"data": "value2"},
                       {"data": "value"}]}}]
        Args:
            merged_map (dict): The merged reputation map.
        Returns:
            list[dict]: The final list structure.
        """
        return [
            {"Value": indicator_value, "Results": flatten_list(list(brands.values()))}
            for indicator_value, brands in merged_map.items()
        ]

    def enrich_final_indicator(self, indicator_list: list[dict]):
        """
        Adds enrichment fields to the final indicator objects depending on the context output mapping.
        Args:
            indicator_list (list[dict]): The list of indicators to enrich.
        """
        for indicator in indicator_list:
            all_scores = [res.get("Score", 0) for res in indicator.get("Results", [])]
            max_score = max(all_scores or [0])
            if "Score" in self.indicator.context_output_mapping:
                indicator["MaxScore"] = max_score
                indicator["MaxVerdict"] = DBOT_SCORE_TO_VERDICT.get(max_score, "Unknown")
                if max_tim_score := [r.get("Score", 0) for r in indicator.get("Results", []) if r.get("Brand") == "TIM"]:
                    indicator["TIMScore"] = max(max_tim_score)
            if "CVSS" in self.indicator.context_output_mapping:
                self.compute_cvss_fields(indicator)

    def compute_cvss_fields(self, indicator: ContextResult) -> None:
        """
        Update indicator with MaxCVSS (float | None) and MaxSeverity (str | None).
        MaxCVSS is the maximum numerical Score found in CVSS.
        MaxSeverity computed from all numerical and string CVSS values found in the indicator.
        If no numerical score is found, MaxCVSS will remain None.
        If no CVSS values found at all, MaxSeverity will remain None.
        """
        values = [res.get("CVSS") for res in indicator.get("Results", [])]

        # compute max numerical score
        scores = [extract_cvss_score(v) for v in values]
        scores = [s for s in scores if s is not None]
        indicator["MaxCVSS"] = max(scores) if scores else None

        # compute max severity
        ratings = [extract_cvss_rating(v) for v in values]
        ratings = [r for r in ratings if r is not None]

        if indicator["MaxCVSS"] is not None:
            ratings.append(convert_cvss_score_to_rating(indicator["MaxCVSS"]))

        if ratings:
            # pick the one with highest order
            indicator["MaxSeverity"] = max(ratings, key=lambda r: SEVERITY_ORDER.index(r))
        else:
            indicator["MaxSeverity"] = None


# --- Main Framework Abstraction and Implementation ---


class AggregatedCommand(ABC):
    def __init__(
        self,
        args: dict,
        brands: list[str],
        verbose: bool,
        commands: list[Command] = [],
        validate_input_function: Callable[[dict], None] = lambda args: None,
    ):
        """
        Initializes the module.

        Args:
            args (dict[str, Any]): The arguments from `demisto.args()`.
            brands (list[str]): A list of specific integration brands to run.
            verbose (bool): If True, include detailed command outputs.
            commands (list[Command]): List of commands to run.
            validate_input_function (Callable): A function to validate input arguments. Should raise an error on failure.
        """
        self.args = args
        self.brands = brands
        self.verbose = verbose
        self.commands = commands
        validate_input_function(args)

    @cached_property
    def enabled_brands(self) -> set[str]:
        """
        Returns a set of enabled brands.
        Caches the result to avoid redundant calculations.
        """
        all_modules = demisto.getModules()
        enabled_brands = {module.get("brand") for module in all_modules.values() if module.get("state") == "active"}
        demisto.debug(f"Found {len(enabled_brands)} enabled integration brands.")
        return enabled_brands

    @cached_property
    def brands_to_run(self) -> list[str]:
        """
        Returns a list of active brands to run on from the given brands.
        If no brands are given, returns empty list.
        Caches the result to avoid redundant calculations.
        """
        if not self.brands:
            demisto.debug("No specific brands provided; will run on all available brands.")
            return []

        demisto.debug(f"Filtering for user-provided brands: {self.brands}")
        brands_to_execute = list(set(self.brands) & set(self.enabled_brands))
        if not brands_to_execute:
            raise DemistoException(
                "None of the provided brands correspond to an enabled integration instance. "
                "Please ensure brand names are correct and instances are enabled."
            )
        demisto.debug(f"Final brands to run on: {brands_to_execute}")
        return brands_to_execute

    @cached_property
    def missing_brands(self) -> list[str]:
        """
        Returns a list of missing brands from the given brands.
        If no brands are given, returns empty list.
        Caches the result to avoid redundant calculations.
        """
        if not self.brands:
            return []

        demisto.debug(f"Filtering for user-provided brands: {self.brands}")
        missing_brands = list(set(self.brands) - self.enabled_brands)
        demisto.debug(f"Missing brands: {missing_brands}")
        return missing_brands


class ReputationAggregatedCommand(AggregatedCommand):
    def __init__(
        self,
        args: dict[str, Any],
        brands: list[str],
        indicator: Indicator,
        data: list[str],
        final_context_path: str,
        external_enrichment: bool = False,
        additional_fields: bool = False,
        verbose: bool = False,
        commands: list[Command] = [],
        validate_input_function: Callable[[dict[str, Any]], None] = lambda args: None,
    ):
        """
        Initializes the reputation aggregated command.

        Args:
            args (dict[str, Any]): The arguments from `demisto.args()`.
            brands (list[str]): List of brands to run on.
            indicator (Indicator): Indicator object to use for reputation.
            data (list[str]): Data to enrich Example: ["https://example.com"].
            final_context_path (str): Path to the context to extract to for the indicators, with this added to the path
                                      (val.Value && val.Value == obj.Value).
            external_enrichment (bool): Whether to run external enrichment.
            additional_fields (bool): Whether to include additional fields in the output.
            verbose (bool): Whether to add verbose outputs.
            commands (list[Command]): List of commands to run.
            validate_input_function (Callable[[dict[str, Any]], None]): Function to validate the input, the function
            should receive args, validate the inputs, and raise an error if the input is invalid. Defaults to lambda args: None.
        """
        super().__init__(args, brands, verbose, commands, validate_input_function)
        self.external_enrichment = external_enrichment
        self.final_context_path = final_context_path
        self.additional_fields = additional_fields
        self.data = data
        self.indicator = indicator

    @cached_property
    def external_missing_brands(self) -> list[str]:
        """
        Returns a list of external brands to run on from the given brands.
        If no brands are given, returns empty list.
        Caches the result to avoid redundant calculations.
        """
        if not self.brands:
            demisto.debug("No specific brands provided; will run on all available brands.")
            return []
        requested = set(self.brands)
        non_external_brands = {command.brand for command in self.commands if command.command_type != CommandType.EXTERNAL}
        external_brands = requested - non_external_brands
        demisto.debug(f"External brands to run on: {external_brands}")
        return list(external_brands - set(self.enabled_brands))

    def run(self) -> CommandResults:
        """
        Main execution loop for the reputation aggregation.
        """
        demisto.debug("Starting aggregated command main loop.")
        context_builder = ContextBuilder(self.indicator, self.final_context_path)
        
        # 1. Execute batch commands
        demisto.debug("Step 1: Executing batch commands.")
        commands_to_execute = self.prepare_commands(self.external_enrichment)
        if commands_to_execute:
            batch_executor = BatchExecutor(commands_to_execute, self.brands_to_run)
            batch_results = batch_executor.execute()
            demisto.debug(f"Batch execution resulted in {len(batch_results)} results.")
        else:
            demisto.debug("No commands to execute.")
            batch_results = []
        
        # 2. Process batch results
        demisto.debug("Step 2: Processing batch results.")
        commands_context, reputation_context, batch_dbot, verbose_outputs, batch_entries = self.process_batch_results(
            batch_results, commands_to_execute
        )
        context_builder.add_reputation_context(reputation_context, batch_dbot, priority=2)
        context_builder.add_other_commands_results(commands_context)
        
        # 3. Prepare commands and get TIM results
        demisto.debug("Step 3: querying TIM.")
        tim_context, tim_dbot, tim_entries = self.get_indicators_from_tim()
        context_builder.add_reputation_context(tim_context, tim_dbot, priority=1)
        demisto.debug(
            f"TIM query resulted in {len(tim_dbot)} DBot scores, "
            f"and {sum(len(lst) for brands_map in tim_context.values() for lst in brands_map.values())} indicators."
        )

        # 4. Merge context
        demisto.debug("Step 4: Merging all contexts.")
        final_context = context_builder.build()

        # 5. Summarize command results
        demisto.debug("Step 5: Summarizing command results.")
        return self.summarize_command_results(tim_entries + batch_entries, verbose_outputs, final_context)

    def prepare_commands(self, external_enrichment: bool = False) -> list[Command]:
        """
        Filters the initial command list based on execution policies.
        If external_enrichment is True, all commands will be executed.
        If external_enrichment is False, only internal commands will be executed.
        If brands is not empty, external_enrichment will be overridden and only commands 
        that are in the brands list will be executed.
        Args:
            external_enrichment (bool): Flag to determine if external commands should run.
        """
        demisto.debug(f"Preparing commands. External enrichment: {external_enrichment}")
        prepared_commands: list[Command] = []
        for command in self.commands:
            if command.command_type == CommandType.INTERNAL and (command.brand in self.brands or not self.brands):
                demisto.debug(f"Adding internal command {command}")
                prepared_commands.append(command)
            elif command.command_type == CommandType.EXTERNAL and (external_enrichment or self.brands):
                demisto.debug(f"Adding external command {command}")
                prepared_commands.append(command)
            else:
                demisto.debug(f"Command {command} is not a valid command type. Skipping.")
        return prepared_commands

    def get_indicators_from_tim(self) -> tuple[ContextResult, DBotScoreList, list[EntryResult]]:
        """
        Searches TIM for indicators and processes the results.

        Returns:
            tuple[ContextResult: TIM Context Output,
            DBotScoreList: DBot Scores List,
            list[EntryResult]: Result Entries].
        """

        demisto.debug(f"Searching TIM for {self.indicator.type} indicators: {self.data}")
        iocs, result_entry = self.search_indicators_in_tim()

        if not iocs:
            demisto.debug("No indicators found in TIM.")
            return {}, [], [result_entry]

        demisto.debug(f"Found {len(iocs)} IOCs in TIM. Processing results.")
        tim_context, tim_dbot = self.process_tim_results(iocs)

        return tim_context, tim_dbot, [result_entry]

    def search_indicators_in_tim(self) -> tuple[list[ContextResult], EntryResult]:
        """
        Performs the actual search against TIM.
        Returns:
            tuple[list[ContextResult], EntryResult]: The search results object and entry result.
        """
        indicators = " or ".join({f"value: {indicator}" for indicator in self.data})
        query = f"type:{self.indicator.type} and ({indicators})"
        result_entry = EntryResult(
            command_name="search-indicators-in-tim",
            args=query,
            brand="TIM",
            status=Status.SUCCESS,
            message="",
        )
        try:
            demisto.debug(f"Executing TIM search with query: {query}")
            searcher = IndicatorsSearcher(query=query, size=len(self.data))
            iocs = flatten_list([res.get("iocs", []) for res in searcher])
            demisto.debug(f"TIM search returned {len(iocs)} raw IOCs.")

            if not iocs:
                result_entry.message = "No matching indicators found."
            return iocs, result_entry
        except Exception as e:
            demisto.debug(f"Error searching TIM: {e}\n{traceback.format_exc()}")
            result_entry.status = Status.FAILURE
            result_entry.message = str(e)

            return [], result_entry

    def process_tim_results(self, iocs: list[dict[str, Any]]) -> tuple[ContextResult, DBotScoreList]:
        """
        Processes the iocs results from the TIM command and return the results.
        indicators are extracted from the iocs and added to the tim context under the indicator type and brand.
        DBot scores are extracted from the search results and added to the DBot scores context.
        Args:
            iocs (list[dict[str, Any]]): The IOC objects from the TIM search in the following format:
            iocs = [
                {"score": 1,
                "insightCache":
                        {"scores":{
                                    "Brand1": {
                                        "score": 1,
                                        "context": {
                                            "indicator": "https://example.com",
                                            "brand": "Brand1"},
                                        },
                                    },
                                    "Brand2": {
                                        "score": 1,
                                        "context": {
                                            "indicator": "https://example.com",
                                            "brand": "Brand2"},
                                    },
                                },
                            },
                        },
                    }
                ]
        Returns:
            tuple[ContextResult, DBotScoreList]: The TIM context output and DBot scores list.
            Example:
            tim_context_output = {
                "https://example.com": {
                    "Brand1": ["Data": "https://example.com", "brand": "Brand1", "additionalFields": {..},]
                    "Brand2": ["Data": "https://example.com", "brand": "Brand2", "additionalFields": {..},]
                }
                "https://example2.com": {
                    "Brand1": ["Data": "https://example2.com", "brand": "Brand1", "additionalFields": {..},]
                "Brand2": ["Data": "https://example2.com", "brand": "Brand2", "additionalFields": {..},]
            }
        }
        """
        demisto.debug(f"Processing {len(iocs)} IOCs from TIM.")
        tim_context: ContextResult = {}
        dbot_scores: DBotScoreList = []

        for ioc in iocs:
            demisto.debug(f"Processing TIM results for indicator: {ioc.get('value')}")
            tim_indicator = self.create_tim_indicator(ioc)
            if tim_indicator:
                demisto.debug(f"Processing TIM results for indicator: {tim_indicator}")
                merge_nested_dicts_in_place(tim_context, tim_indicator)
            for brand, indicators in ioc.get("insightCache", {}).get("scores", {}).items():
                demisto.debug(f"Processing TIM results from brand: {brand}")
                score = indicators.get("score", 0)
                context = indicators.get("context", {})
                parsed_indicators, parsed_dbot = self.parse_indicator(context, brand, score)
                merge_nested_dicts_in_place(tim_context, parsed_indicators)
                dbot_scores.extend(parsed_dbot)

        return tim_context, dbot_scores
    
    def create_tim_indicator(self, ioc: ContextResult) -> dict[str, Any]:
        """
        Creates a TIM indicator from the given IOC.
        Takes the finalize score from tim result and creates a final indicator object.
        Args:
            ioc (ContextResult): The IOC object from the TIM search.
        Returns:
            dict[str, Any]: The TIM indicator.
        """
        indicators_context: ContextResult = defaultdict(lambda: defaultdict(list))
        value = ioc.get("value")
        score = ioc.get("score", Common.DBotScore.NONE)
        if not value:
            demisto.debug("No value found in TIM result")
            return {}
        indicators_context[value]["TIM"].append({
            self.indicator.value_field: value,
            "Brand": "TIM",
            "Score": score,
            "Verdict": DBOT_SCORE_TO_VERDICT.get(score),
        })
        return indicators_context
        

    def process_batch_results(
        self,
        all_results: list[list[ContextResult]],
        commands_to_execute: list[Command],
    ) -> tuple[ContextResult, ContextResult, DBotScoreList, list[str], list[EntryResult]]:
        """
        Processes the results from the batch executor.
        runs through the execution results and processes each result according to the command.

        Args:
            all_results (list[list[ContextResult]]): The results from the batch executor for all commands.
            commands_to_execute (list[Command]): The commands to execute.

        Returns:
            tuple[
                ContextResult, The non-reputation context output.
                ContextResult, The reputation context output.
                DBotScoreList, The dbot scores context.
                list[str], The verbose command results.
                list[EntryResult], The entry results.
            ]
        """
        verbose_outputs: list[str] = []
        entry_results: list[EntryResult] = []
        context_result: ContextResult = defaultdict(lambda: defaultdict(list))
        reputation_context_result: ContextResult = defaultdict(lambda: defaultdict(list))
        dbot_scores: DBotScoreList = []

        demisto.debug(f"Processing {len(all_results)} sets of batch results.")
        for command, results_for_command in zip(commands_to_execute, all_results):
            demisto.debug(f"Processing result for command: {command} len: {len(results_for_command)}")
            for result in results_for_command:
                if is_debug_entry(result):
                    demisto.debug("Skipping debug result")
                    continue

                brand = command.brand or result.get("Metadata", {}).get("brand", command.brand or "Unknown")
                if brand == "Unknown":
                    # When only internal brands given and reputation command run with using-brand and no relevant brand
                    # Empty result with empty brand will be skipped
                    demisto.debug("Skipping result with unknown brand")
                    continue
                cmd_context, cmd_dbot, hr_output, entry = self.parse_result(result, command, brand)

                if cmd_context:
                    # Reputation commands are grouped under a single key for easier merging.
                    if isinstance(command, ReputationCommand):
                        merge_nested_dicts_in_place(reputation_context_result, cmd_context)
                    else:
                        merge_nested_dicts_in_place(context_result, cmd_context)
                dbot_scores.extend(cmd_dbot)
                if entry:
                    entry_results.append(entry)
                if hr_output and self.verbose:
                    verbose_outputs.append(hr_output)

        demisto.debug(
            f"Finished processing batch results.\n"
            f"Found {len(dbot_scores)} DBot scores.\n"
            f"Found {len(entry_results)} command entries.\n"
        )

        return context_result, reputation_context_result, dbot_scores, verbose_outputs, entry_results

    def parse_result(
        self, result: ContextResult, command: Command, brand: str
    ) -> tuple[ContextResult, DBotScoreList, str, EntryResult]:
        """
        Parses a single command's result into structured context, DBot scores, and readable output,
        Depends on the command type.
        All reputation commands are parsed as indicators under the prefix structure.
        For other commands each result will be parsed by the mapping into the final context.
        DBot scores are extracted to one list of DBotScores.
        Args:
            result (ContextResult): The result of a command.
            command (Command): The command associated with the result.
            brand (str): The brand associated with the result.
        Returns:
            tuple[ContextResult, The context of the result.
                  DBotScoreList, The DBot scores of the result.
                  str, The human readable of the result.
                  EntryResult]: The entry result of the result.
        """
        indicator_args = ",".join(
            str(v) for v in flatten_list(command.args.values())
            ) if isinstance(command.args, dict) else command.args
        
        result_entry = EntryResult(
            command_name = command.name,
            args = indicator_args,
            brand = brand,
            status = Status.SUCCESS,
            message = "",
        )
        hr_output = ""
        command_context: ContextResult = {}
        dbot_scores: DBotScoreList = []

        if is_error(result):
            demisto.debug(f"Result for command: {command} is error")
            error = get_error(result)
            result_entry.status = Status.FAILURE
            result_entry.message = error
            if self.verbose:
                hr_output = f"#### Error for name={command.name} args={command.args} current brand={brand}\n{error}"
                if human_readable := result.get("HumanReadable"):
                    hr_output += f"\n\n{human_readable}"

        elif self.verbose:
            if human_readable := result.get("HumanReadable"):
                hr_output = f"#### Result for name={command.name} args={command.args} current brand={brand}\n{human_readable}"

        if entry_context := result.get("EntryContext"):
            # parse_command_result
            if isinstance(command, ReputationCommand):
                demisto.debug(f"Parsing indicator for reputation command: {command}")
                command_context, dbot_scores = self.parse_indicator(entry_context, brand)
            else:
                demisto.debug(f"Mapping indicator for command: {command}")
                command_context = self.map_command_context(entry_context, command.context_output_mapping)

        if not command_context and result_entry.status == Status.SUCCESS:
            demisto.debug(f"No context or DBot scores for command: {command}")
            result_entry.message = "No matching indicators found."

        return command_context, dbot_scores, hr_output, result_entry

    def map_command_context(
        self, entry_context: dict[str, Any], context_output_mapping: dict[str, str], is_indicator: bool = False
    ) -> dict[str, Any]:
        """
        Maps the entry context item to the final context using the mapping.
        Can add [] to transform the final path value to list.
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
        if not context_output_mapping:
            demisto.debug("No mapping provided, returning entry context item as is.")
            return entry_context

        if not entry_context:
            demisto.debug("No entry context provided, returning empty context.")
            return {}

        mapped_context: ContextResult = defaultdict()
        demisto.debug(f"Starting context mapping with {len(context_output_mapping)} rules. is_indicator: {is_indicator}")
        for src_path, dst_path in context_output_mapping.items():
            value = pop_dict_value(entry_context, src_path)
            if value:
                set_dict_value(mapped_context, dst_path, value)

        if self.additional_fields and is_indicator:
            demisto.debug(f"Adding {len(entry_context)} remaining fields to AdditionalFields.")
            set_dict_value(mapped_context, "AdditionalFields", entry_context)

        return mapped_context

    def parse_indicator(
        self,
        entry_context: ContextResult,
        brand: str,
        score: int = Common.DBotScore.NONE,
    ) -> tuple[ContextResult, DBotScoreList]:
        """
        Parse the indicator context and complete missing fields such as brand, score, verdict if needed.
        indicator_object is used to map the indicator context to the final context.
        What is not mapped is added to the AdditionalFields if AdditionalFields is enabled.
        Final indicator is saved under the following structure:
        {indicator_value: {brand: [indicator]}}
        {"https://example.com":
            {"brand":[
                {"indicator_value":"https://example.com",
                "brand":"brand",
                "score": 1,
                "verdict": "Good"},
                ]
            }
        }
        Args:
            entry_context (ContextResult): The entry context item straight from the command result.entry_context.
            brand (str): The brand from the result.metadata.brand.
            score (int, optional): The score. Defaults to Common.DBotScore.NONE.
        Returns:
            tuple[ContextResult, DBotScoreList]: The parsed result and DBot scores.
        """
        demisto.debug(f"Starting parsing indicators from brand '{brand}'.")
        indicators_context: ContextResult = defaultdict(lambda: defaultdict(list))

        dbot_list = flatten_list([v for k, v in entry_context.items() if k.startswith("DBotScore")])

        # Prefer provided score, else find the max score from the DBot list.
        effective_score = score or max([dbot.get("Score") for dbot in dbot_list], default=Common.DBotScore.NONE)

        indicator_entries = flatten_list(
            [v for k, v in entry_context.items() if k.startswith(self.indicator.context_path_prefix)]
        )
        demisto.debug(
            f"Extracted {len(indicator_entries)} indicators and {len(dbot_list)} DBot scores from {brand} entry context."
        )

        for indicator_data in indicator_entries:
            indicator_value = indicator_data.get(self.indicator.value_field)
            demisto.debug(f"Parsing indicator: {indicator_value}")
            mapped_indicator = self.map_command_context(indicator_data, self.indicator.context_output_mapping, is_indicator=True)
            
            if "Score" in self.indicator.context_output_mapping:
                mapped_indicator["Score"] = effective_score
                mapped_indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(effective_score, "Unknown")
            mapped_indicator["Brand"] = brand

            indicators_context[indicator_value][brand].append(mapped_indicator)
            demisto.debug(f"Parsed indicator '{indicator_value}' from brand '{brand}'")

        return indicators_context, dbot_list

    def summarize_command_results(
        self, entries: list[EntryResult], verbose_outputs: list[str], final_context: dict[str, Any]
    ) -> CommandResults:
        """
        Construct the final Command Result with the appropriate readable output and context.
        Summarizes the human readable output.
        Adds verbose messages from all commands if verbose is True.
        If all commands failed, return an error message.
        If all commands failed and no indicators were found, return an error message.
        If all commands succeeded with no indicators found, return a success message.
        If at least one command succeeded with indicators found, return a success message.

        Args:
            entries (list[EntryResult]): The entry results of the TIM.
            verbose_outputs (list[str]): The verbose results of the batch executor.
            final_context (ContextResult): The final context.
        Returns:
            CommandResults: The command results.
        """
        demisto.debug(f"Summarizing final results from {len(entries)} command entries.")
        if self.external_missing_brands:
            demisto.debug(f"Missing brands: {self.external_missing_brands}")
            entries.append(
                EntryResult(
                    command_name=self.indicator.type,
                    args="",
                    brand=",".join(self.external_missing_brands),
                    status=Status.FAILURE,
                    message="Unsupported Command : Verify you have proper integrations enabled to support it",
                )
            )
        self.raise_non_enabled_brands_error(entries)
        human_readable = tableToMarkdown(
            "Final Results",
            t=[entry.to_entry() for entry in entries],
            headers=["brand", "args", "status", "message"],
        )
        if self.verbose:
            demisto.debug("Adding verbose outputs to human readable.")
            human_readable += "\n\n".join(verbose_outputs)

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

    def raise_non_enabled_brands_error(self, entries: list[EntryResult]) -> None:
        """
        Raises an exception if all commands failed due to unsupported brand.
        If no other commands supplied, raise an exception.
        Args:
            entries (list[EntryResult]): The list of entry results.
        """
        non_tim_entries = [entry for entry in entries if entry.brand != "TIM"]
        if non_tim_entries and all(entry.message.startswith("Unsupported Command") for entry in non_tim_entries):
            raise DemistoException(
                "None of the commands correspond to an enabled integration instance. "
                "Please ensure relevant brands are enabled."
            )


"""HELPER FUNCTIONS"""


def merge_nested_dicts_in_place(dict1: dict, dict2: dict) -> None:
    """
    Recursively merges dict2 into dict1. If a key exists in both and the
    value is a list, it extends the list. For nested dicts, it recurses.
    This function modifies dict1 in place.

    Args:
        dict1 (dict): The first dictionary to merge to.
        dict2 (dict): The second dictionary to merge from.
    """
    for data, brand_dict in dict2.items():
        if data not in dict1:
            dict1[data] = brand_dict
        else:
            if isinstance(brand_dict, dict):
                for brand, results in brand_dict.items():
                    if brand not in dict1[data]:
                        dict1[data][brand] = []
                    dict1[data][brand].extend(results)
            else:
                dict1[data].extend(brand_dict)


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
        path (str): A dot-separated key path (e.g "Signature.Copyright")
        value (Any): Value to set in the dictionary.
    """
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


def extract_cvss_score(value) -> float:
    """
    Extract the numerical Score from a CVSS object.
    If no numerical score is found, return None.

    Returns:
        float: CVSS score (0.0 - 10.0)
    """

    # Handle dict case: {"Score": ...}
    if isinstance(value, dict) and "Score" in value:
        return extract_cvss_score(value["Score"])

    # Handle "N/A"
    if isinstance(value, str) and value.strip().upper() == "N/A":
        return None

    # Handle numbers (int, float, str)
    try:
        score = float(value)
        if 0.0 <= score <= 10.0:
            return score
    except (TypeError, ValueError):
        pass
    
    return None

def extract_cvss_rating(value) -> str | None:
    """
    Get the severity rating from a CVSS Object.
    Turn numerical to string rating.
    """
    # Dict with nested score
    if isinstance(value, dict) and "Score" in value:
        return extract_cvss_rating(value["Score"])

    # Numeric → map to rating
    score = extract_cvss_score(value)
    if score is not None:
        return convert_cvss_score_to_rating(score)

    # String severity
    if isinstance(value, str):
        val = value.strip().capitalize()
        if val in SEVERITY_ORDER:
            return val

    return None

def convert_cvss_score_to_rating(score: float) -> str:
    """
    Given a CVSS numeric score (0.0 - 10.0),
    return the corresponding severity rating.
    Args:
        score (float): The CVSS numeric score.
    Returns:
        str: The severity rating. "Unknown" if the score is not in the range (0.0 - 10.0).
    """
    for rating, (low, high) in CVSS_TO_VERDICT.items():
        if low <= score <= high:
            return rating

    return "Unknown"

def remove_empty_elements_with_exceptions(d, exceptions: set[str] = None):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary,
    unless their key is in the `exceptions` set.

    :param d: Input dictionary or list.
    :type d: dict | list
    :param exceptions: Keys that should be kept even if their values are None/empty.
    :type exceptions: set[str] | None
    :return: Cleaned dictionary or list.
    :rtype: dict | list
    """
    if exceptions is None:
        exceptions = set()

    def empty(k, v):
        """Check if a value is considered empty, unless the key is in exceptions."""
        if isinstance(v, (dict, list)):
            return not v  # empty dict or list
        return v is None and k not in exceptions

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
