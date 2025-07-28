from enum import Enum
import json
from collections.abc import Callable
from nturl2path import url2pathname
from tabnanny import verbose

import demistomock as demisto
from CommonServerPython import *
from collections import defaultdict
from abc import ABC

DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}

class CommandType(Enum):
    internal = "internal"
    external = "external"
class Command:
    def __init__(self, name: str, args: dict, type: CommandType = CommandType.internal, context_path: str = None) -> None:
        """
        Initializes a Command object.
        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            brand (str): Brand associated with the command.
        """
        self.name: str = name
        self.args: dict = args
        self.type: CommandType = type
        self.context_path: str = context_path

    # @property
    def to_batch_item(self, brands = "") -> dict:
        """
        Convert to the dict format expected by executeCommandBatch.
        """
        args = self.args
        args["using-brand"] = brands
        return {self.name: args}

class BatchExecutor:
    def __init__(self, commands: list[dict]):
        self.commands = commands
    
    def execute(self) -> list[list[dict]]:
        execution_results = demisto.executeCommandBatch(self.commands)
        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self}")
            return []
        return execution_results
        
# Disable insecure warnings
class AggregatedCommandAPIModule(ABC):
    def __init__(self, args: dict, main_keys: list[str], brands: list[str], verbose: bool, additional_fields: bool, commands: list[Command] = [], validate_input_function: Callable[[dict], bool] = lambda: True):
        self.main_keys = main_keys
        self.brands = brands
        self.verbose = verbose
        self.additional_fields = additional_fields
        self.commands = commands
        self.args = args
        self.brands_to_run = self.get_brands_to_run()
        self.validate_input_function = validate_input_function

    
    def get_brands_to_run(self) -> list[str]:
        """
        Returns a list of active brands to run on from the given brands.
        if no brands are given, returns all active brands.
        """
        brands_to_execute = []
        if self.brands:
            demisto.debug(f"Got list of brands to run on {self.brands}, Getting integration brands on tenant.")
            enabled_brands = list(
                {module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"}
            )
            demisto.debug(f"Found {len(enabled_brands)} enabled integration brands.")
            demisto.debug("Validating overlap between enrichment brands and enabled integration brands.")
            if not (brands_to_execute := list(set(self.brands).intersection(enabled_brands))):
                raise DemistoException(
                    "None of the given brands has an enabled integration instance. "
                    f"Ensure valid integration IDs are specified. For example: '{Brands.CORE_IR},{Brands.WILDFIRE_V2.value}'"
            )
        else:
            demisto.debug("No specific brands were given, will run on all available brands.")
        demisto.debug(f"Brands to run on: {brands_to_execute}")
        return brands_to_execute
    
    @abstractmethod
    def process_batch_results(self, execution_results: list[dict[str, Any]]):
        """Abstract method that must be implemented by subclasses.
        This method handles the main execution loop for aggregated commands.
        """
        raise NotImplementedError
    
    @abstractmethod
    def aggregated_command_main_loop(self):
        """Abstract method that must be implemented by subclasses.
        This method handles the main execution loop for aggregated commands.
        """
        raise NotImplementedError
    
    def prepare_commands(self):
        """
        Prepares the commands to execute.
        """
        commands = []
        brands_to_run_input = ",".join(self.brands_to_run)
        for command in self.commands:
            if command.type == CommandType.INTERNAL or (self.external_enrichment and command.type == CommandType.EXTERNAL_ENRICHMENT):
                commands.append(command.to_batch_item(brands_to_run_input))
        return commands
    
class ReputationAggregatedCommand(AggregatedCommandAPIModule):
    def __init__(self,
                 main_keys: list[str] = [],
                 brands: list[str] = [],
                 verbose: bool = False,
                 additional_fields: bool = False,
                 external_enrichment: bool = False,
                 context_path: str = "",
                 indicator_path: str = "",
                 indicator_value_field: str = "",
                 validate_input_function: Callable[[dict], bool] = lambda: True,
                 args: dict = {},
                 commands: list[Command] = []):
        """
        Initializes the reputation aggregated command.
        
        Args:
            main_keys (list[str]): List of main keys to extract from the indicator context.
            brands (list[str]): List of brands to run on.
            verbose (bool): Whether to run in verbose mode.
            additional_fields (bool): Whether to include additional fields in the output.
            external_enrichment (bool): Whether to run external enrichment.
            context_path (str): Path to the context to extract to.
            indicator_path (str): Path to the indicator to extract from.
            indicator_value_field (str): Field to extract the indicator value from.
            validate_input_function (Callable[[dict], bool]): Function to validate the input.
            commands (list[Command]): List of commands to run.
        """
        super().__init__(args, main_keys, brands, verbose, additional_fields, commands, validate_input_function)
        self.external_enrichment = external_enrichment
        self.context_path = context_path
        self.indicator_path = indicator_path
        self.indicator_value_field = indicator_value_field

    def aggregated_command_main_loop(self):
        """
        Main loop for the aggregated command.
        """
        self.validate_input_function()
        demisto.debug("Starting aggregated command main loop.")
        tim_context_output, dbot_scores_context_tim, verbose_command_tim = self.get_indicators_from_tim()
        
        demisto.debug("Preparing commands to execute.")
        commands_to_execute = self.prepare_commands()
        demisto.debug(f"Commands to execute: {json.dumps(commands_to_execute, indent=2)}")
        batch_executor = BatchExecutor(commands_to_execute)
        demisto.debug("Executing BatchExecutor.")
        batch_results = batch_executor.execute()
        demisto.debug(f"Batch results: {json.dumps(batch_results, indent=2)}")
        
        indicators_context, dbot_scores_context_commands, verbose_command_results = self.process_batch_results(batch_results, commands_to_execute)
        
        command_results = self.summarize_command_results(context, verbose_command_results)
    
        return command_results
    
    def search_indicators_in_tim(self, indicator_type: str, data_list: list[str]):
        verbose_command_results: dict[str, dict[str, list[CommandResults]]] = defaultdict(lambda: defaultdict(list))
        try:
            indicators = " or ".join({f"value: {indicator}" for indicator in data_list})
            query = f"type:{indicator_type} and ({indicators})"
            demisto.debug(f"Search query: {query}")
            search_results = IndicatorsSearcher(query=query, size=len(data_list))
        except Exception as e:
            demisto.debug(
                f"Error searching for {indicator_type} indicator with value: {data_list}. Error: {str(e)}.\n{traceback.format_exc()}"
            )
            return {}, CommandResults(
                readable_output=f"#### Error for Search Indicators\n{str(e)}", entry_type=EntryType.ERROR
            )
        if not search_results:
            demisto.debug(f"Could not find indicator with value: {indicator_list}.")
            return {}, CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
        return search_results, {}
    
    def get_indicators_from_tim(self) -> tuple[dict[str, list], dict[str, dict[str, list[CommandResults]]]]:
        """
        Parses the results from the Thread Intelligence Module (TIM) and transforms
        the Indicator of Compromise (IOC) into a standard context output by extracting the `indicator` dictionary. It also adds source
        brand fields to additional context items.
        """
        verbose_command_results: list[CommandResults] = []
        tim_context_output: dict[str,dict[str, list]] = {}
        dbot_scores_context: list[dict[str, Any]] = []
        
        for indicator_type, data_list in zip([self.indicator_type], [self.data_list]): #TODO remove zip use args
            demisto.debug(f"Starting to search for {indicator_type} indicator with values: {data_list}.")
            search_results,verbose_results = self.search_indicators_in_tim(indicator_type,data_list)
            if not search_results:
                verbose_command_results.extend(verbose_results)
                demisto.debug(f"Could not find indicator with value: {data_list}.")
                continue
            
            iocs = flatten_list([result.get("iocs") or [] for result in search_results])
            
            for ioc in iocs:
                # Extract indicators context
                demisto.debug(f"Current ioc: {json.dumps(ioc, indent=2)}")
                indicator_context_list = ioc.get("insightCache").get("scores")
                for brand, indicators in indicator_context_list.items():
                    score = indicators.get("score", 0)
                    context = indicators.get("context", {})
                    parsed_indicators_context, parsed_dbot_scores_context = self.parse_indicator(context, brand, score)
                    demisto.debug(f"Parsed indicators context before merging: {json.dumps(parsed_indicators_context, indent=2)}")
                    
                    merge_nested_dicts_in_place(tim_context_output, parsed_indicators_context)
                    demisto.debug(f"Parsed indicators context after merging: {json.dumps(tim_context_output, indent=2)}")
                    dbot_scores_context.extend(parsed_dbot_scores_context)
                   
                table = tableToMarkdown(name="Found Indicators", t=tim_context_output)
                readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")
                verbose_command_results.append(readable_command_results)
            
        return tim_context_output, dbot_scores_context, verbose_command_results
        
    

                
                
                
    def merge_context(self, context_output: dict[str, list]) -> dict[str, list]:
        """
        Merges the context output from all the executed commands.
        Args:
            context_output (dict[str, list]): The context output from all the executed commands.
        Returns:
            dict[str, list]: The merged context output.
        """
        final_context_output = {}
        data_enrichment_list = []
        for data in self.data_list:
            data_context = {self.indicator_value_field: data}
            results_dict = {}
            tim_context = context_output.get("TIM", {}).get("indicator", {}).get(data, [])
            external_context = context_output.get(CommandType.external, {}).get("indicator", {}).get(data, [])
            internal_context = context_output.get(CommandType.internal, {}).get("indicator", {}).get(data, [])
            for entry in external_context:
                demisto.debug(f"External indicator entry: {json.dumps(entry, indent=2)}")
                key = (entry[self.indicator_value_field], entry["Brand"])
                results_dict[key] = entry
                
            for entry in tim_context:
                demisto.debug(f"TIM indicator entry: {json.dumps(entry, indent=2)}")
                key = (entry[self.indicator_value_field], entry["Brand"])
                if key not in results_dict:
                    results_dict[key] = entry

        
            if external_context or tim_context:
                results = list(results_dict.values())
                demisto.debug(f"For the following url: {url}, results dict: {json.dumps(results, indent=2)}")
                max_score = max((indicator.get("Score") for indicator in results), default=Common.DBotScore.NONE)
                data_context["Max_score"] = max_score
                data_context["Verdict"] = DBOT_SCORE_TO_VERDICT.get(max_score, "Unknown")
                data_context["Results"] = results
                data_enrichment_list.append(data_context)
        
        # Merge DBotScore entries
        score_map = {}
        for entry in context_output.get("TIM", {}).get("DBotScore", []):
            key = (entry["Indicator"], entry["Vendor"])
            score_map[key] = entry
        for entry in context_output.get(CommandType.external, {}).get("DBotScore", []):
            key = (entry["Indicator"], entry["Vendor"])
            score_map[key] = entry
        for entry in context_output.get(CommandType.internal, {}).get("DBotScore", []):
            key = (entry["Indicator"], entry["Vendor"])
            score_map[key] = entry
        
        final_enrichment_output = {}
        for data in self.data_list:
            for command in self.commands:
                final_enrichment_output[command.context_path].extend(context_output[CommandType.internal][data])
        
        final_enrichment_output.update(self.context_path: url_enrichment_list,
                                       ContextPaths.DBOT_SCORE.value: list(score_map.values()))
        return final_enrichment_output
                

    def summarize_command_human_readable(self, verbose_command_results):
        return ""
    
    def summarize_command_results(
        self,
        context_output: dict[str, list],
        verbose_command_results: list[CommandResults],
        ) -> CommandResults:
        """
        Summarizes the results from all the executed commands.
        Args:
            verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
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

        summaries: list[dict] = []
        
        for data in self.data_list:
            result = {"Data": data, "Brand":"TIM"}
            tim_response = verbose_command_results.get(data, {}).get("TIM", {}):
            if not time_response or tim_response.entry_type == EntryType.ERROR:
                result["Result"] = "Failed"
                result["Message"] = verbose_command_results.get(data,{}).get("TIM",{}).human_readable or "Failed to execute command."
            else:
                result["Result"] = "Success"

                
        
        for data in self.data_list:
            for brand in self.external_brands:
                result = {"Data": data, "Brand": brand}
                command_response = []
                if verbose_command_results[data][brand].entry_type == EntryType.ERROR:
                    result["Result"] = "Failed"
                    result["Message"] = verbose_command_results[data][brand].human_readable or "Integration not configured."
                else:
                    result["Result"] = "Success"
                summaries.append(result)
            
            for brand in self.internal_brands:
                result = {"Data": data, "Brand": brand}
                if verbose_command_results[data][brand].entry_type == EntryType.ERROR:
                    result["Result"] = "Failed"
                    result["Message"] = verbose_command_results[data][brand].human_readable or "Integration not configured."
                else:
                    result["Result"] = "Success"
                summaries.append(result)

        demisto.debug(f"Summarized results from all executed commands: {summaries}.")

        return CommandResults(
            outputs=self.merge_context(context_output),
            readable_output=tableToMarkdown(name=f"URL Enrichment result for {', '.join(url_list)}", t=summaries),
        )
    
    def process_batch_results(self, execution_results: list[list[dict[str, Any]]], commands_to_execute: list[dict[str, Any]]) -> tuple[defaultdict[str, defaultdict[str, list]], list[dict[str, Any]], defaultdict[str, defaultdict[str, CommandResults]]]:
        verbose_command_results: defaultdict[str, defaultdict[str, CommandResults]] = defaultdict(defaultdict(CommandResults))
        batch_context: defaultdict[str, defaultdict[str, list]] = defaultdict(defaultdict(list))
        dbot_scores_context: list[dict[str, Any]] = []
        
        for command,execution_result in zip(commands_to_execute,execution_results):
            for result in execution_result:
                brand = result.get("Metadata", {}).get("brand")
                data = command.get(command.name, {}).get(self.indicator_type)
                indicator, dbot_scores, human_readable = self.parse_result(result, data, self.main_keys, self.additional_fields)
                verbose_command_results[data][brand] = human_readable
                if indicator:
                    batch_context[data][brand].append(indicator)
                if dbot_scores:
                    dbot_scores_context.extend(dbot_scores)
        return batch_context, dbot_scores_context, verbose_command_results

    def parse_result(result: dict[str, Any], data: str)-> dict[str, Any]:
        """
        Parses the result of a reputation command.
        Args:
            result (dict[str, Any]): The result of a reputation command.
            data (str): The data associated with the result.
        Returns:
            dict[str, Any]: The parsed result.
        """
        human_readable: CommandResults | None = None
        indicators_context: dict[str, list] = defaultdict(list)
        dbot_scores_context: list[dict[str, Any]] = []
        brand = result.get("Metadata", {}).get("brand")
        if is_error(result):
            human_readable = CommandResults(
                readable_output=f"#### Error for data={data} brand={brand}\n{get_error(result)}", entry_type=EntryType.ERROR
            )
            return
        if human_readable := result.get("HumanReadable"):
            human_readable = CommandResults(
                readable_output=f"#### Result for data={data} brand={brand}\n{human_readable}"
            )
        if entry_context_item := result.get("EntryContext"):
            if is_external(brand):
                indicators_context, dbot_scores_context = self.parse_indicator(entry_context_item, brand)
            else:
                indicators_context = entry_context_item
                
        return indicators_context, dbot_scores_context, human_readable

    def construct_context_by_keys(self, context: dict[str, Any]):
            """
            Constructs a context dictionary by extracting values from the given context item based on the specified keys.
            Args:
                context_item (dict): The context item to extract values from.
                keys (list[str]): List of keys to extract values from the context item.
                additional_fields (bool): Whether to include additional fields in the context. Defaults to False.
            Returns:
                dict: Constructed context dictionary.
            """
            output: dict[str, Any] = {}
            for key, values in context.items():
                if key in self.main_keys:
                    output[key] = values
                elif self.additional_fields:
                    output["AdditionalFields"] = values
            return output
        
    def parse_indicator(self, entry_context_item: dict[str, Any], brand: str, score: int = Common.DBotScore.NONE)-> tuple[dict[str, Any], list[dict[str, Any]]]:
        demisto.debug(f"Parsing the following indicators: {json.dumps(entry_context_item, indent=2)}")
        dbot_scores = []
        indicators_context = defaultdict(lambda: defaultdict(list))
        dbot_list = flatten_list([value for key, value in entry_context_item.items() if key.startswith("DBotScore")])
        demisto.debug(f"DBot scores: {dbot_list}")
        if dbot_list:
            score = max([score.get("Score") for score in dbot_list],default=Common.DBotScore.NONE)
            dbot_scores.extend(dbot_list)
            demisto.debug(f"DBot scores: {score}")
        entry_context_item = flatten_list([value for key, value in entry_context_item.items() if key.startswith(self.indicator_path)])
        for indicator in entry_context_item:
            indicator = self.construct_context_by_keys(indicator)
            indicator["Brand"] = brand
            indicator["Score"] = indicator.get("Score") or score
            indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(indicator["Score"], "Unknown")
            demisto.debug(f"Parsed indicator: {json.dumps(indicator, indent=2)}")
            indicators_context[indicator.get(self.indicator_value_field)][brand].append(indicator)
        demisto.debug(f"Indicators context after parsing: {json.dumps(indicators_context, indent=2)}")
          
        return indicators_context, dbot_scores
    
def merge_nested_dicts_in_place(dict1: dict, dict2: dict) -> None:
    """
    Merges dict2 into dict1 in-place for nested dictionaries of the form:
    """
    for url, brand_data in dict2.items():
        if url not in dict1:
            dict1[url] = brand_data
        else:
            dict1[url].update(brand_data)

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
    

