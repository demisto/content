from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
import json
from typing import Any

from CommonServerPython import *
import demistomock as demisto

# Type alias for complex dictionary structures to improve readability
ContextResult = dict[str, Any]
DBotScoreList = list[ContextResult]
CommandList    = list["Command"]


DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}

# --- Core Enumerations and Data Classes ---
@dataclass
class Indicator:
    """
    Represents an indicator type and its context mapping rules.

    Attributes:
        type (str): The indicator type (e.g., 'url', 'ip', 'cve').
        value_field (str): The field name holding the indicator's value (e.g., 'Data', 'Address').
        context_path (str): The context path prefix for the indicator (e.g., 'URL(', 'IP(').
        mapping (Dict[str, str]): Rules to map raw command output to the final context.
            - Key: Source path in double dot notation (e.g., 'VirusTotal..POSITIVES').
            - Value: Destination path in double dot notation.
              Append '[]' in the end to transform the final value to a list.
    """
    type: str
    value_field: str
    context_path: str
    mapping: dict[str, str]

class EntryResult:
    """
    Represents an entry result from a command.

    Attributes:
        name (str): The name of the entry.
        args (dict[str, Any]): The arguments associated with the entry.
    """
    def __init__(self,
                 command_name: str,
                 args: dict[str, Any],
                 brand: str,
                 status: str,
                 message: str):
        self.command_name = command_name
        self.args = args
        self.brand = brand
        self.status = status
        self.message = message
    
    def to_entry(self) -> dict[str, Any]:
        return {"command name": self.command_name,
                "args": self.args,
                "brand": self.brand,
                "status": self.status,
                "message": self.message}
    

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
        mapping (dict[str, str]): Mapping rules for the command's output.
            Example:
                {"Name": "Value"} will change the key "Name" to "Value".
                For nested mapping use double dot notation. Example:
                {"Name..Value": "Value"} will map the context {"Name": {"Value": "example"}} to {"Value": "example"}.
                When empty mapping is given, the context result will be mapped to the same name.
    """
    def __init__(self,
                 name: str,
                 args: dict={},
                 brand: str="",
                 command_type: CommandType=CommandType.REGULAR,
                 mapping: dict[str, str]={}):
        
        self.name = name
        self.args = args
        self.brand = brand
        self.command_type = command_type
        self.mapping = mapping
        
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
        super().__init__(name=indicator.type,
                         args={indicator.type: data},
                         command_type=CommandType.EXTERNAL,
                         mapping=indicator.mapping)
        self.indicator = indicator


class BatchExecutor:
    """
    Initializes a BatchExecutor object.
    Args:
        commands (list[Command]): A list of Command objects to execute.
        brands_to_run (list[str]): A list of brands to run on.
    """
    def __init__(self, commands: list[Command], brands_to_run: list[str] = None):
        self.commands = commands
        self.brands_to_run = brands_to_run
    
    def execute(self) -> list[list[dict]]:
        """
        Executes commands in a batch.

        Returns:
            A list where each item is a list of results for the corresponding command.
        """
        if not self.commands:
            demisto.debug("BatchExecutor.execute called with no commands. Returning empty list.")
            return []
        commands_to_execute = [command.to_batch_item(self.brands_to_run) for command in self.commands]
        demisto.debug(f"Executing batch of {len(commands_to_execute)} commands. Brands: {self.brands_to_run or 'all'}")
        results = demisto.executeCommandBatch(commands_to_execute)
        demisto.debug(f"Batch execution completed with {len(results)} result sets.")
        return results

# --- Main Framework Abstraction and Implementation ---

class AggregatedCommandAPIModule(ABC):
    def __init__(self,
                 args: dict,
                 brands: list[str],
                 verbose: bool,
                 commands: list[Command] = [],
                 validate_input_function: Callable[[dict], None] = lambda args: None):
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
    def enabled_brands(self) -> list[str]:
        """
        Returns a list of enabled brands.
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
            internal_brands = [command.brand for command in self.commands if command.command_type == CommandType.INTERNAL]
            # If only internal commands and all disabled raise error
            if not set(internal_brands) & self.enabled_brands and not self.external_enrichment:
                raise DemistoException(
                    "None of the commands correspond to an enabled integration instance. "
                    "Please ensure relevant brand are enabled."
                )
            return []
        
        demisto.debug(f"Filtering for user-provided brands: {self.brands}")
        brands_to_execute = list(set(self.brands) & self.enabled_brands)
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
        
        demisto.debug(f"Filtering for user-provided brands: {self.brands}")
        external_missing_brands = set(set(self.brands) - set([command.brand for command in self.commands if command.command_type == CommandType.INTERNAL]))
        demisto.debug(f"External missing brands to run on: {external_missing_brands}")
        return list(external_missing_brands - self.enabled_brands)
    
    @abstractmethod
    def process_batch_results(self, execution_results: list[dict[str, Any]]):
        """Abstract method that must be implemented by subclasses.
        Process the batch results after batch execution.
        """
        raise NotImplementedError
    
    @abstractmethod
    def aggregated_command_main_loop(self):
        """Abstract method that must be implemented by subclasses.
        This method handles the main execution loop for aggregated commands.
        """
        raise NotImplementedError

class ReputationAggregatedCommand(AggregatedCommandAPIModule):
    def __init__(self,
                 args: dict[str, Any],
                 brands: list[str],
                 indicator: Indicator,
                 data: list[str],
                 final_context_path: str,
                 external_enrichment: bool = False,
                 additional_fields: bool = False,
                 verbose: bool = False,
                 commands: CommandList = [],
                 validate_input_function: Callable[[dict[str, Any]], None] = lambda args: None):
        """
        Initializes the reputation aggregated command.
        
        Args:
            args (dict[str, Any]): The arguments from `demisto.args()`.
            brands (list[str]): List of brands to run on.
            indicator (Indicator): Indicator object to use for reputation.
            data (list[str]): Data to enrich Example: ["https://example.com"].
            final_context_path (str): Path to the context to extract to for the indicators.
            external_enrichment (bool): Whether to run external enrichment.
            additional_fields (bool): Whether to include additional fields in the output (what is not in the indicator mapping).
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
    
    def aggregated_command_main_loop(self) -> CommandResults:
        """
        Main execution loop for the reputation aggregation.
        """
        demisto.debug("Starting aggregated command main loop.")
        
        # 1. Prepare commands and get TIM results
        demisto.debug("Step 1: querying TIM.")
        tim_context, tim_dbot, tim_entries = self.get_indicators_from_tim()
        demisto.debug(f"TIM query resulted in {len(tim_dbot)} DBot scores. \n"
                      f"    and {sum(len(lst) for lst in tim_context.values())} indicators.")
        
        # 2. Execute batch commands
        demisto.debug("Step 2: Executing batch commands.")
        commands_to_execute = self.prepare_commands(self.external_enrichment)
        batch_executor = BatchExecutor(commands_to_execute, self.brands_to_run)
        batch_results = batch_executor.execute()
        demisto.debug(f"Batch execution resulted in {len(batch_results)} results.")
        
        # 3. Process batch results
        demisto.debug("Step 3: Processing batch results.")
        batch_context, batch_dbot, verbose_outputs, batch_entries = self.process_batch_results(batch_results, commands_to_execute)
        
        demisto.debug(f"Batch processing resulted in {len(batch_dbot)} DBot scores.\n"
                      f"    {len(batch_context.get('reputation', {}).values())} indicators.")
        
        # 4. Merge context
        demisto.debug("Step 4: Merging all contexts.")
        final_context = self.merge_context(tim_context, batch_context,tim_dbot, batch_dbot)
        
        # 5. Summarize command results
        demisto.debug("Step 5: Summarizing command results.")
        return  self.summarize_command_results(tim_entries + batch_entries, verbose_outputs, final_context)


    def prepare_commands(self, external_enrichment: bool = False) -> list[Command]:
        """
        Filters the initial command list based on execution policies.

        Args:
            external_enrichment (bool): Flag to determine if external commands should run.
        """
        demisto.debug(f"Preparing commands. External enrichment: {external_enrichment}")
        prepared_commands: CommandList = []
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
            tuple[ContextResult, DBotScoreList, list[EntryResult]]: The TIM context output and DBot scores list and result entries.
        """

        demisto.debug(f"Searching TIM for {self.indicator.type} indicators: {self.data}")
        iocs, result_entry = self.search_indicators_in_tim()
        
        if not iocs:
            demisto.debug("No indicators found in TIM.")
            return {}, [], [result_entry]
        
        demisto.debug(f"Found {len(iocs)} IOCs in TIM. Processing results.")
        tim_context, tim_dbot = self.process_tim_results(iocs)
                        
        return tim_context, tim_dbot, [result_entry]
        
    def search_indicators_in_tim(self)-> tuple[list[ContextResult], EntryResult]:
        """
        Performs the actual search against TIM.
        Returns:
            tuple[list[ContextResult], EntryResult]: The search results object and entry result.
        """
        indicators = " or ".join({f"value: {indicator}" for indicator in self.data})
        query = f"type:{self.indicator.type} and ({indicators})"
        result_entry = EntryResult(command_name="search-indicators-in-tim",
                                   args={"query": query},
                                   brand="TIM",
                                   status="Success",
                                   message="")
        try:
            demisto.debug(f"Executing TIM search with query: {query}")
            searcher = IndicatorsSearcher(query=query, size=len(self.data))
            iocs = flatten_list([res.get("iocs", []) for res in searcher])
            demisto.debug(f"TIM search returned {len(iocs)} raw IOCs.")

            if not iocs:
                result_entry.message = "No matching indicators found in TIM."
            return iocs, result_entry
        except Exception as e:
            demisto.debug(f"Error searching TIM: {e}\n{traceback.format_exc()}")
            result_entry.status = "Failure"
            result_entry.message = str(e)
            
            return [], result_entry
    
    def process_tim_results(self, iocs: list[dict[str, Any]])-> tuple[ContextResult, DBotScoreList]:
        """
        Processes the iocs results from the TIM command adn return the results.
        indicators are extracted from the iocs and added to the tim context under the indicator type and brand.
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
        DBot scores are extracted from the search results and added to the DBot scores context.
        Args:
            iocs (list[dict[str, Any]]): The IOC objects from the TIM search.
            iocs = [
                {"insightCache":
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
        """
        demisto.debug(f"Processing TIM results. {json.dumps(iocs, indent=4)}")
        demisto.debug(f"Processing {len(iocs)} IOCs from TIM.")
        tim_context: ContextResult = {}
        dbot_scores: DBotScoreList = []

        for ioc in iocs:
            for brand, indicators in ioc.get("insightCache", {}).get("scores", {}).items():
                demisto.debug(f"Processing TIM results from brand: {brand}")
                score = indicators.get("score", 0)
                context = indicators.get("context", {})
                parsed_indicators, parsed_dbot = self.parse_indicator(context, brand, score)
                merge_nested_dicts_in_place(tim_context, parsed_indicators)
                dbot_scores.extend(parsed_dbot)
                
        return tim_context, dbot_scores
    
    def process_batch_results(self,
                              all_results: list[list[ContextResult]],
                              commands_to_execute: CommandList,
                              ) -> tuple[ContextResult, DBotScoreList, list[str], list[EntryResult]]:
        """
        Processes the results from the batch executor.
        runs through the execution results and processes each result according to the command.
        
        Args:
            all_results (list[list[ContextResult]]): The results from the batch executor for all commands.
            commands_to_execute (CommandList): The commands to execute.
        
        Returns:
            tuple[
                ContextResult, The batch context output.
                DBotScoreList, The dbot scores context.
                list[str], The verbose command results.
                list[EntryResult], The entry results.
            ]
        """
        verbose_outputs: list[str] = []
        entry_results: list[EntryResult] = []
        batch_context = defaultdict(lambda: defaultdict(list))
        dbot_scores: DBotScoreList = []
        
        demisto.debug(f"Processing {len(all_results)} sets of batch results.")
        for command, results_for_command in zip(commands_to_execute, all_results):
            demisto.debug(f"Processing result for command: {command} len: {len(results_for_command)}")
            for result in results_for_command:
                if is_debug(result):
                    demisto.debug("Skipping debug result")
                    continue
                
                brand = result.get("Metadata", {}).get("brand", command.brand or "Unknown")
                if brand == "Unknown":
                    demisto.debug("Skipping result with unknown brand")
                    continue
                cmd_context, cmd_dbot, hr_output, entry = self.parse_result(result, command, brand)
                if cmd_context:
                    # Reputation commands are grouped under a single key for easier merging.
                    if isinstance(command, ReputationCommand):
                        merge_nested_dicts_in_place(batch_context["reputation"], cmd_context)
                    else:
                        merge_nested_dicts_in_place(batch_context, cmd_context)
                dbot_scores.extend(cmd_dbot)
                if entry:
                    entry_results.append(entry)
                if hr_output and self.verbose:
                    verbose_outputs.append(hr_output)
        demisto.debug(
            f"Finished processing batch results.\n"
            f"Found {len(dbot_scores)} DBot scores.\n"
            f"Found {len(entry_results)} command entries.\n"
            f"Found {sum(len(lst) for lst in batch_context['reputation'].values())} indicators."
        )

        return batch_context, dbot_scores, verbose_outputs, entry_results

    def parse_result(self, result: ContextResult, command: Command, brand: str)-> tuple[ContextResult, DBotScoreList, str, EntryResult]:
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
        result_entry = EntryResult(command_name=command.name,
                                   args=json.dumps(command.args),
                                   brand=brand,
                                   status="Success",
                                   message="")
        hr_output = ""
        command_context: ContextResult = {}
        dbot_scores: DBotScoreList = []
        
        if is_error(result):
            demisto.debug(f"Result for command: {command} is error")
            error = get_error(result)
            result_entry.status = "Failure"
            result_entry.message = error
            if self.verbose:
                hr_output = f"#### Error for name={command.name} args={command.args} current brand={brand}\n{error}"
                if human_readable := result.get("HumanReadable"):
                    hr_output += f"\n\n{human_readable}"
        
        elif self.verbose:
            if (human_readable := result.get("HumanReadable")):
                hr_output = f"#### Result for name={command.name} args={command.args} current brand={brand}\n{human_readable}"
            
        if entry_context := result.get("EntryContext"):
            # parse_command_result
            if isinstance(command, ReputationCommand):
                demisto.debug(f"Parsing indicator for reputation command: {command}")
                command_context, dbot_scores = self.parse_indicator(entry_context, brand)
            else:
                demisto.debug(f"Mapping indicator for command: {command}")
                command_context = self.map_command_context(entry_context, command.mapping)
                
        return command_context, dbot_scores, hr_output, result_entry
    
    def map_command_context(self, entry_context: dict[str, Any], mapping: dict[str, str], is_indicator: bool=False)-> dict[str, Any]:
        """
        Maps the entry context item to the final context using the mapping.
        Can add [] to transform the final path value to list.
        Args:
            entry_context (dict[str, Any]): The entry context item.
            mapping (dict[str, str]): The mapping to use.
            Example1:
                mapping = {"reslut..value": "final_context..value"}
                {"results":{"value":value}} -> {"final_context":{"value":value}}
            Example2:
                mapping = {"reslut..value": "final_context..value[]"}
                {"results":{"value":value}} -> {"final_context":{"value":[value]}}
        Returns:
            dict[str, Any]: The mapped context.
        """
        if not mapping:
            demisto.debug("No mapping provided, returning entry context item as is.")
            return entry_context
        
        if not entry_context:
            return None
        
        mapped_context = defaultdict()
        demisto.debug(f"Starting context mapping with {len(mapping)} rules. for indicator: {is_indicator}")
        for src_path, dst_path in mapping.items():
            value = get_and_remove_dict_value(entry_context, src_path)
            if value:
                set_dict_value(mapped_context, dst_path, value)
            
        if self.additional_fields and is_indicator:
            demisto.debug(f"Adding {len(entry_context)} remaining fields to AdditionalFields.")
            set_dict_value(mapped_context, "AdditionalFields", entry_context)
        
        return mapped_context
    
    def parse_indicator(self,
                        entry_context: ContextResult,
                        brand: str,
                        score: int = Common.DBotScore.NONE,
                        )-> tuple[ContextResult, DBotScoreList]:
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
        indicators_context = defaultdict(lambda: defaultdict(list))
        
        dbot_list = flatten_list([v for k, v in entry_context.items() if k.startswith("DBotScore")])

        
        # Prefer provided score, else find the max score from the DBot list.
        effective_score = score or max([dbot.get("Score") for dbot in dbot_list], default=Common.DBotScore.NONE)
        
        indicator_entries = flatten_list([v for k, v in entry_context.items() if k.startswith(self.indicator.context_path)])
        demisto.debug(f"Extracted {len(indicator_entries)} indicators and {len(dbot_list)} DBot scores from {brand} entry context.")
        
        for indicator_data in indicator_entries:
            indicator_value = indicator_data.get(self.indicator.value_field)
            if not indicator_value:
                demisto.debug("Skipping indicator entry, missing value field.")
                continue
            
            demisto.debug(f"Parsing indicator: {indicator_value}")
            mapped_indicator = self.map_command_context(indicator_data, self.indicator.mapping, is_indicator=True)
            
            # Enrich with standard fields if they were mapped
            if "Score" in self.indicator.mapping:
                mapped_indicator["Score"] = effective_score
            if "Verdict" in self.indicator.mapping:
                mapped_indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(effective_score, "Unknown")
            if "Brand" in self.indicator.mapping:
                mapped_indicator["Brand"] = brand
            
            indicators_context[indicator_value][brand].append(mapped_indicator)
            demisto.debug(f"Parsed indicator '{indicator_value}' from brand '{brand}' with score {effective_score}")
        
        return indicators_context, dbot_list
    
    def merge_context(self, tim_ctx: ContextResult,batch_ctx: ContextResult,tim_dbot: DBotScoreList, batch_dbot: DBotScoreList,
                      )-> ContextResult:
        """
        Merges all context pieces into the final, structured output.
        structure as follow:
        {final_context_path: [{"data":"example",
                               "other_context": other_context,
                               "results":[indicators_dicts]},
                               ...]
        DBotScore: []
        Other Command Contexts: []
                               }
        Indicator from reputation are prioritize over indicators from TIM.
        DBotScore are listed in one list.
        Args:
            tim_ctx (ContextResult): The context output of the TIM.
            batch_ctx (ContextResult): The context output of the batch executor.
            tim_dbot (DBotScoreList): The DBotScore context of the TIM.
            batch_dbot (DBotScoreList): The DBotScore context of the batch executor.
        Returns:
            ContextResult: The final context.
        """
        demisto.debug("Merging contexts.")
        merged_indicators = self.merge_indicators(batch_ctx.get("reputation", {}), tim_ctx)
        self.enrich_final_indicator(merged_indicators)
                
        final_context = {k: v for k, v in batch_ctx.items() if k != "reputation"}
        final_context[self.final_context_path] = merged_indicators
        final_context[Common.DBotScore.CONTEXT_PATH] = batch_dbot + tim_dbot
        
        return remove_empty_elements(final_context)
    
    def enrich_final_indicator(self, indicator_list: list[dict[str, Any]])-> None:
        """
        Adds aggregated fields like max score and verdict to the final indicator list.
        Args:
            indicator_list (list[dict[str, Any]]): The list of indicators to enrich.
        """
        demisto.debug(f"Enriching {len(indicator_list)} final indicators with max scores.")
        for indicator in indicator_list:
            if "Score" in self.indicator.mapping:
                all_scores = [res.get("Score", Common.DBotScore.NONE) for res in indicator.get("results", [])]
                max_score = max(all_scores) if all_scores else Common.DBotScore.NONE
                demisto.debug(f"Enriching indicator {indicator[self.indicator.value_field]} with max scores {max_score}.")
                indicator["max_score"] = max_score
                indicator["max_verdict"] = DBOT_SCORE_TO_VERDICT.get(max_score, "Unknown")
    
    def merge_indicators(
        self,
        batch_map: dict[str, dict[str, list[dict]]],
        tim_map: dict[str, dict[str, list[dict]]]
    ) -> list[dict[str, Any]]:
        """
        Merges indicator results from batch commands and TIM, prioritizing batch results.
        
        Args:
            batch_map (Dict): Indicators from reputation commands, structured as {indicator_value: {brand: [results]}}.
            tim_map (Dict): Indicators from TIM, with the same structure.

        Returns:
            A list of final, merged indicator objects.
        """
        demisto.debug(f"Merging indicators from batch ({len(batch_map)} values) and TIM ({len(tim_map)} values).")
        merged_list: list[dict[str, Any]] = []
        all_indicator_values = set(batch_map.keys()) | set(tim_map.keys())
        demisto.debug(f"Found {len(all_indicator_values)} unique indicator values to merge.")
        
        for indicator_value in all_indicator_values:
            batch_brands = batch_map.get(indicator_value, {})
            tim_brands   = tim_map.get(indicator_value,   {})
            final_results: list[dict] = []
            
            # 1) add all batch entries (in whatever order they came)
            for brand_results in batch_brands.values():
                final_results.extend(brand_results)
                demisto.debug(f"For '{indicator_value}', added {len(brand_results)} results from batch.")
                
            # 2) add only those tim entries whose brand wasn’t in batch
            for brand, brand_results in tim_brands.items():
                if brand not in batch_brands:
                    final_results.extend(brand_results)
                    demisto.debug(f"For '{indicator_value}', added {len(brand_results)} results from tim brand '{brand}'.")

            merged_list.append({
                self.indicator.value_field:indicator_value,
                "results": final_results
            })
        demisto.debug(f"Finished merging. Created {len(merged_list)} final indicator objects.")
        return merged_list
            
    def summarize_command_results(self,
                                   entries: list[EntryResult],
                                   verbose_outputs: list[str],
                                   final_context: dict[str, Any]) -> CommandResults:
        """
        Construct the final Command Result with the appropriate readable output and context.
        Summarizes the human readable output.
        Adds verbose messages from all commands if verbose is True.
        If all commands failed, return an error message.
        
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
            entries.append(EntryResult(command_name="url",
                                       args="",
                                       brand=",".join(self.external_missing_brands),
                                       status="Failure",
                                       message="Unsupported Command : Verify you have proper integration enabled to support it"))
        self.raise_non_enabled_brands_error(entries)
        human_readable = tableToMarkdown("Final Results", t=[entry.to_entry() for entry in entries],
                                         headers=["command name", "brand", "args", "status", "message"])
        if self.verbose:
            demisto.debug("Adding verbose outputs to human readable.")
            human_readable += "\n\n".join(verbose_outputs)
            
        if all(entry.status == "Failure" for entry in entries):
            demisto.debug("All commands failed. Returning an error entry.")
            return CommandResults(readable_output= "Error: All commands failed.\n" + human_readable,
                                  outputs=final_context,
                                  entry_type=EntryType.ERROR)
            
        demisto.debug("All commands succeeded. Returning a success entry.")
        return CommandResults(readable_output=human_readable, outputs=final_context)

                
    def raise_non_enabled_brands_error(self,entries: list[EntryResult])-> None:
        """
        Raises an exception if all commands failed due to unsupported brand.
        Args:
            entries (list[EntryResult]): The list of entry results.
        """
        if all(entry.message.startswith("Unsupported Command") for entry in entries if entry.brand != "TIM"):
            raise DemistoException(
                "None of the commands correspond to an enabled integration instance. "
                "Please ensure relevant brand are enabled."
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
    

def set_dict_value(d: dict[str, Any], path: str, value: Any)-> None:
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


def get_and_remove_dict_value(d: dict[str, Any], path: str) -> Any:
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

def is_debug(execute_command_result) -> bool:
    """
        Check if the given execute_command_result is a debug entry.

        :type execute_command_result: ``dict`` or ``list``
        :param execute_command_result: Demisto entry (required) or result of demisto.executeCommand()

        :return: True if the execute_command_result is a debug entry, false otherwise
        :rtype: ``bool``
    """
    if execute_command_result is None:
        return False

    if isinstance(execute_command_result, list) and len(execute_command_result) > 0:
        for entry in execute_command_result:
            if isinstance(entry, dict) and entry['Type'] == entryTypes['debug']:
                return True

    return isinstance(execute_command_result, dict) and execute_command_result['Type'] == entryTypes['debug']
