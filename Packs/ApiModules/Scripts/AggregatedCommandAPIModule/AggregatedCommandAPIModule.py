from enum import Enum
from functools import cached_property
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
    regular = "regular"
class Command:
    def __init__(self, name: str, args: dict, type: CommandType = CommandType.regular, mapping: dict[str, str] = {}) -> None:
        """
        Initializes a Command object.
        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            type (CommandType): The type of the command.
        """
        self.name: str = name
        self.args: dict = args
        self.type: CommandType = type
        self.mapping: dict[str, str] = mapping

    # @property
    def to_batch_item(self, brands_to_run: list[str] = []) -> dict:
        """
        Convert to the dict format expected by executeCommandBatch.
        """
        if brands_to_run:
            self.args["using-brand"] = ",".join(brands_to_run)
        return {self.name: self.args}
    
    def execute(self) -> dict:
        return execute_command(self.name, self.args)
    
class ReputationCommand(Command):
    def __init__(self, name: str, args: dict,mapping: dict[str, str] = {}) -> None:
        super().__init__(name, args ,CommandType.external, mapping)

class BatchExecutor:
    def __init__(self, commands: list[Command], brands_to_run: list[str] = []):
        self.commands = commands
        self.brands_to_run = brands_to_run
    
    def execute(self) -> list[list[dict]]:
        commands_to_execute = [command.to_batch_item(self.brands_to_run) for command in self.commands]
        return demisto.executeCommandBatch(commands_to_execute)
        
# Disable insecure warnings
class AggregatedCommandAPIModule(ABC):
    def __init__(self, args: dict, main_keys: list[str], brands: list[str], verbose: bool, commands: list[Command] = [], validate_input_function: Callable[[dict], bool] = lambda: True):
        """_summary_

        Args:
            args (dict): _description_
            main_keys (list[str]): _description_
            brands (list[str]): _description_
            verbose (bool): _description_
            commands (list[Command], optional): _description_. Defaults to [].
            validate_input_function (Callable[[dict], bool]): Function to validate the input, the function should receive args, validate the inputs, and raise an error if the input is invalid. Defaults to lambda:True.
        """
        self.main_keys = main_keys
        self.brands = brands
        self.verbose = verbose
        self.commands = commands
        self.args = args
        self.validate_input_function = validate_input_function
        self.validate_input_function(args)

    
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
        commands:list[Command] = []
        for command in self.commands:
            if self.brands_to_run or not command.type == CommandType.external or (self.external_enrichment and command.type == CommandType.external):
                commands.append(command)
        return commands
    
    @cached_property
    def brands_to_run(self):
        return self.get_brands_to_run()
    
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
                 commands: list[Command] = [],
                 data: dict = {}):
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
            validate_input_function (Callable[[dict], bool]): Function to validate the input, the function should receive args, validate the inputs, and raise an error if the input is invalid. Defaults to lambda:True.
            commands (list[Command]): List of commands to run.
        """
        super().__init__(args, main_keys, brands, verbose, commands, validate_input_function)
        self.external_enrichment = external_enrichment
        self.context_path = context_path
        self.indicator_path = indicator_path
        self.indicator_value_field = indicator_value_field
        self.additional_fields = additional_fields
        self.data = data

    def aggregated_command_main_loop(self):
        """
        Main loop for the aggregated command.
        """
        demisto.debug("Starting Reputation aggregated command main loop.")
        tim_context_output, dbot_scores_context_tim, result_entries_tim = self.get_indicators_from_tim()
        
        demisto.debug("Preparing commands to execute.")
        commands_to_execute = self.prepare_commands()
        demisto.debug(f"Commands to execute: {json.dumps(commands_to_execute, indent=2)}")
        batch_executor = BatchExecutor(commands_to_execute, self.brands_to_run)
        demisto.debug("Executing BatchExecutor.")
        batch_results = batch_executor.execute()
        
        indicators_context, dbot_scores_context_commands, verbose_command_results = self.process_batch_results(batch_results, commands_to_execute)
        
        command_results = self.summarize_command_results(context, verbose_command_results)
    
        return command_results
    
    def search_indicators_in_tim(self, indicator_type: str, data_list: list[str]):
        """
        Searches for indicators in TIM.
        Args:
            indicator_type (str): The type of indicator to search for.
            data_list (list[str]): The list of indicators to search for.
        Returns:
            tuple[dict[str, list], dict[str, dict[str, list[CommandResults]]]]: The search results and verbose command results.
        """
        indicators = " or ".join({f"value: {indicator}" for indicator in data_list})
        query = f"type:{indicator_type} and ({indicators})"
        result_entry = {"command name": "search-indicators-in-tim",
                        "args": query,
                        "brand": "TIM",
                        "status": "Success",
                        "message": ""}
        search_results = None
        try:
            demisto.debug(f"Search query: {query}")
            search_results = IndicatorsSearcher(query=query, size=len(data_list))
        except Exception as e:
            demisto.debug(
                f"Error searching for {indicator_type} indicator with value: {data_list}. Error: {str(e)}.\n{traceback.format_exc()}"
            )
            result_entry.update({"status": "Failure", "message": str(e)})
        if not search_results:
            demisto.debug(f"Could not find indicator with value: {indicator_list}.")
            result_entry.update({"status": "Failure", "message": "No Indicators found."})
            
        return search_results, result_entry
    
    def get_indicators_from_tim(self) -> tuple[dict[str, list], dict[str, dict[str, list[CommandResults]]]]:
        """
        Parses the results from the Thread Intelligence Module (TIM) and transforms
        the Indicator of Compromise (IOC) into a standard context output by extracting the `indicator` dictionary. It also adds source
        brand fields to additional context items.
        """
        result_entries: list[dict[str, Any]] = []
        tim_context_output: dict[str,dict[str, list]] = {}
        dbot_scores_context: list[dict[str, Any]] = []

        for indicator_type, data_list in self.data.items():
            demisto.debug(f"Starting to search for {indicator_type} indicator with values: {data_list}.")
            search_results, result_entry = self.search_indicators_in_tim(indicator_type,data_list)
            if not search_results:
                result_entries.append(result_entry)
                continue
            
            demisto.debug(f"going to process tim results for indicator type: {indicator_type}.")
            
            self.process_tim_results(search_results, dbot_scores_context, tim_context_output)
                        
        return tim_context_output, dbot_scores_context, result_entries
    
    def process_tim_results(self, search_results, dbot_scores_context, tim_context_output):
        iocs = flatten_list([result.get("iocs") or [] for result in search_results])
        
        for ioc in iocs:
            # Extract indicators context
            indicator_context_list = ioc.get("insightCache").get("scores")
            for brand, indicators in indicator_context_list.items():
                score = indicators.get("score", 0)
                context = indicators.get("context", {})
                parsed_indicators_context, parsed_dbot_scores_context = self.parse_indicator(context, brand, score)
                merge_nested_dicts_in_place(tim_context_output, parsed_indicators_context)
                dbot_scores_context.extend(parsed_dbot_scores_context)
        
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
    
    def process_batch_results(self,
                              execution_results: list[list[dict[str, Any]]],
                              commands_to_execute: list[Command],
                              ) -> tuple[defaultdict[str, defaultdict[str, list]],
                                         list[dict[str, Any]],
                                         defaultdict[str, defaultdict[str, CommandResults]]]:
                                  
        verbose_command_results: defaultdict[str, defaultdict[str, CommandResults]] = defaultdict(defaultdict(CommandResults))
        entry_results: list[dict[str, Any]] = []
        batch_context: defaultdict[str, defaultdict[str, list]] = defaultdict(defaultdict(list))
        dbot_scores_context: list[dict[str, Any]] = []
        
        for command, execution_result in zip(commands_to_execute, execution_results):
            for result in execution_result:
                brand = result.get("Metadata", {}).get("brand")
                indicator, dbot_scores, human_readable, result_entry = self.parse_result(result, command, brand)
                if indicator:
                    batch_context[data][brand].append(indicator)
                if dbot_scores:
                    dbot_scores_context.extend(dbot_scores)
        return batch_context, dbot_scores_context, verbose_command_results

    def parse_result(self, result: dict[str, Any], command: Command, brand: str)-> dict[str, Any]:
        """
        Parses the result of a reputation command.
        Args:
            result (dict[str, Any]): The result of a reputation command.
            command (Command): The command associated with the result.
        Returns:
            dict[str, Any]: The parsed result.
        """
        result_entry = {"command name": command.name,
                        "args": command.args,
                        "brand": brand,
                        "status": "Success",
                        "message": ""}
        human_readable = ""
        indicators_context: dict[str, list] = defaultdict(list)
        dbot_scores_context: list[dict[str, Any]] = []
        if is_error(result):
            result_entry.update({"status": "Failure", "message": get_error(result)})
            
        if self.verbose and (human_readable := result.get("HumanReadable")):
            human_readable = f"#### Result for name={command.name} args={command.args} brand={brand}\n{human_readable}"
            
        if entry_context_item := result.get("EntryContext"):
            # parse_command_result
            if isinstance(command, ReputationCommand):
                indicators_context, dbot_scores_context = self.parse_indicator(entry_context_item, brand, command=command)
            else:
                indicators_context = self.parse_command_result(entry_context_item, command)
                
        return indicators_context, dbot_scores_context, human_readable, result_entry
    
    def parse_command_result(self, entry_context_item: dict[str, Any], command: Command):
        if not command.mapping:
            return entry_context_item
        final_command_context: list[defaultdict(lambda: defaultdict(list))] = []
        entry_context_item = flatten_list([value for key, value in entry_context_item.items() if key.startswith(self.indicator_path)])
        for command_context_item in entry_context_item:
            current_command_context = defaultdict(lambda: defaultdict(list))
            for src, dst in command.mapping.items():
                set_dict_value(current_command_context, dst, get_dict_value(command_context_item, src))
            if self.additional_fields:
                set_dict_value(current_command_context, "AdditionalFields", command_context_item)
            final_command_context.append(current_command_context)
        
        return final_command_context
    
    def parse_indicator(self, entry_context_item: dict[str, Any], brand: str, score: int = Common.DBotScore.NONE, command: Command = None)-> tuple[dict[str, Any], list[dict[str, Any]]]:
        indicators_context = defaultdict(lambda: defaultdict(list))
        dbot_list = flatten_list([value for key, value in entry_context_item.items() if key.startswith("DBotScore")])
        score = score or max([dbot.get("Score") for dbot in dbot_list], default=Common.DBotScore.NONE)
        entry_context_item = flatten_list([value for key, value in entry_context_item.items() if key.startswith(self.indicator_path)])
        for indicator in entry_context_item:
            indicator = self.construct_context_by_keys(indicator, command.mapping.keys())
            indicator["Brand"] = brand
            indicator["Score"] = score
            indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(indicator["Score"], "Unknown")
            indicators_context[indicator.get(self.indicator_value_field)][brand].append(indicator)
        
        return indicators_context, dbot_list
    
    def construct_context_by_keys(self, context: dict[str, Any], main_keys: list[str]):
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
            if key in main_keys:
                output[key] = values
            elif self.additional_fields:
                output["AdditionalFields"] = values
        return output
        
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

def get_dict_value(d: Mapping[str, Any], path: str, default: Any = None) -> Any:
    """
    Retrieves a value from a nested dictionary given a dot-separated path.
    Returns `default` if any key along the path doesn’t exist.
    after getting remove the item from the dict

    Args:
        d (Mapping[str, Any]): Dictionary to get nested key from.
        path (str): A dot-separated key path (e.g. "Signature.Copyright").
        default (Any): Value to return if the full path is not found.
    """
    if not path:
        return default

    # Simple key
    if "." not in path:
        return d.get(path, default)

    # Nested keys
    current: Any = d
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
            del d[part]
        else:
            return default
    return current


