import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any
from collections import defaultdict
import json
from collections.abc import Callable

from abc import ABC
from enum import Enum
from functools import cached_property
import json
from collections.abc import Callable

import demistomock as demisto
from CommonServerPython import *
from collections import defaultdict
from abc import ABC


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
        demisto.debug(f"Tim context output: {json.dumps(tim_context_output, indent=2)}")
        demisto.debug(f"Tim dbot scores context: {json.dumps(dbot_scores_context_tim, indent=2)}")
        demisto.debug(f"Tim result entries: {json.dumps(result_entries_tim, indent=2)}")
        demisto.debug("Preparing commands to execute.")
        commands_to_execute = self.prepare_commands()
        demisto.debug(f"Commands to execute: {json.dumps([command.to_batch_item() for command in commands_to_execute], indent=2)}")
        batch_executor = BatchExecutor(commands_to_execute, self.brands_to_run)
        demisto.debug("Executing BatchExecutor.")
        batch_results = batch_executor.execute()
        
        indicators_context, dbot_scores_context_commands, verbose_command_results = self.process_batch_results(batch_results, commands_to_execute)
        
        command_results = self.summarize_command_results(context, verbose_command_results)
    
        return command_results
    
    def search_indicators_in_tim(self, indicator_type: str, data_list: list[str])-> tuple[IndicatorsSearcher, dict[str, Any]]:
        """
        Searches for indicators in TIM.
        Args:
            indicator_type (str): The type of indicator to search for.
            data_list (list[str]): The list of indicators to search for.
        Returns:
            tuple[IndicatorsSearcher, dict[str, Any]]: The search results object and entry context.
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
    
    def get_indicators_from_tim(self) -> tuple[dict[str, list], dict[str, dict[str, list[dict[str, Any]]]]]:
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
                parsed_indicators_context, parsed_dbot_scores_context = self.parse_indicator(context, brand, score,)
                merge_nested_dicts_in_place(tim_context_output, parsed_indicators_context)
                dbot_scores_context.extend(parsed_dbot_scores_context)
        
    
    def process_batch_results(self,
                              execution_results: list[list[dict[str, Any]]],
                              commands_to_execute: list[Command],
                              ) -> tuple[defaultdict[str, defaultdict[str, list]],
                                         list[dict[str, Any]],
                                         defaultdict[str, defaultdict[str, CommandResults]]]:
                                  
        verbose_command_results: list[str] = []
        entry_results: list[dict[str, Any]] = []
        batch_context: defaultdict[str, defaultdict[str, list]] = defaultdict(defaultdict(list))
        dbot_scores_context: list[dict[str, Any]] = []
        
        for command, execution_result in zip(commands_to_execute, execution_results):
            for result in execution_result:
                brand = result.get("Metadata", {}).get("brand")
                indicator, dbot_scores, human_readable, result_entry = self.parse_result(result, command, brand)
                if indicator:
                    merge_nested_dicts_in_place(batch_context, indicator)
                dbot_scores_context.extend(dbot_scores)
                entry_results.append(result_entry)
                verbose_command_results.append(human_readable)
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
                indicators_context, dbot_scores_context = self.parse_indicator(entry_context_item, brand, mapping=command.mapping)
            else:
                indicators_context = self.map_command_context(entry_context_item, command.mapping)
                
        return indicators_context, dbot_scores_context, human_readable, result_entry
    
    def map_command_context(self, entry_context_item: dict[str, Any], mapping: dict[str, str]):
        if not mapping:
            return entry_context_item
        mapped_context = defaultdict(lambda: defaultdict(list))
        for src, dst in mapping.items():
            set_dict_value(mapped_context, dst, get_dict_value(entry_context_item, src))
        if self.additional_fields:
            set_dict_value(mapped_context, "AdditionalFields", entry_context_item)
        
        return mapped_context
    
    def parse_indicator(self, entry_context_item: dict[str, Any], brand: str, score: int = Common.DBotScore.NONE, mapping: dict[str, str] = {})-> tuple[dict[str, Any], list[dict[str, Any]]]:
        indicators_context = defaultdict(lambda: defaultdict(list))
        dbot_list = flatten_list([value for key, value in entry_context_item.items() if key.startswith("DBotScore")])
        score = score or max([dbot.get("Score") for dbot in dbot_list], default=Common.DBotScore.NONE)
        entry_context_item = flatten_list([value for key, value in entry_context_item.items() if key.startswith(self.indicator_path)])
        for indicator in entry_context_item:
            indicator = self.map_command_context(indicator, mapping)
            indicator["Brand"] = brand
            indicator["Score"] = score
            indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(indicator["Score"], "Unknown")
            indicators_context[indicator.get(self.indicator_value_field)][brand].append(indicator)
        
        return indicators_context, dbot_list
    
    def construct_context_by_mapping(self, context: dict[str, Any], main_keys: list[str]):
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

def get_dict_value(d: dict[str, Any], path: str, default: Any = None) -> Any:
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


"""Constants"""


class ContextPaths(Enum):
    URL_ENRICHMENT = "URLEnrichment(" "val.Brand && val.Brand == obj.Brand && (" "val.Data && val.Data == obj.Data))"

    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    URL = Common.URL.CONTEXT_PATH


CONTEXT_PATH = {"url": Common.URL.CONTEXT_PATH, "domain": Common.Domain.CONTEXT_PATH}
INDICATOR_PATH = {"url": "URL", "domain": "Domain", "ip": "IP"}
INDICATOR_VALUE_FIELDS = {"url": "Data", "domain": "Name", "ip": "Address"}

DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}

MAIN_KEYS = ["Address", "Name", "Brand", "Data", "DetectionEngines", "PositiveDetections", "Score"]
""" COMMAND CLASS """

""" COMMAND FUNCTION """


def url_enrichment_script(
    data_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False, indicator_type="url"
):
    """
    Enriches URL data with information from various integrations
    """
    mapping = {"Data":"Data",
               "DetectionEngines":"DetectionEngines",
               "PositiveDetections":"PositiveDetections",
               "Score":"Score",
               "Brand":"Brand"}
    
    commands = [ReputationCommand(name="url", args={"url": data_list}, mapping=mapping)]
    urlreputation = ReputationAggregatedCommand(
        main_keys={"Data":"Data",
                   "DetectionEngines":"DetectionEngines",
                   "PositiveDetections":"PositiveDetections",
                   "Score":"Score",
                   "Brand":"Brand"},
        brands =[],
        verbose=True,
        commands = commands,
        validate_input_function=lambda args: True,
        additional_fields=True,
        external_enrichment=True,
        indicator_path="URL(",
        indicator_value_field="Data",
        context_path="URL",
        args=demisto.args(),
        data={"url":data_list}
        
    )
    return urlreputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
    args = demisto.args()
    data_list = argToList(args.get("data"))
    indicator_type = args.get("indicator_type")
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(url_enrichment_script(data_list, external_enrichment, verbose, brands, additional_fields, indicator_type))
    except Exception as ex:
        return_error(f"Failed to execute URLEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()