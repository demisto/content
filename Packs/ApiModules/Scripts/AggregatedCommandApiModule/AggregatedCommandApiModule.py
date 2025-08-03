from enum import Enum
from functools import cached_property
import json
from collections.abc import Callable

from CommonServerPython import *
import demistomock as demisto
from collections import defaultdict
from abc import ABC

DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}

class CommandType(Enum):
    """
    Enum for command types.
    Used to categorize the commands to execute.
    When external_enrichment is True, both internal and external commands are executed.
    When external_enrichment is False, only internal commands are executed.
    Regular are for future implementation.
    """
    internal = "internal"
    external = "external"
    regular = "regular"
    tim = "tim"
    
class Command:
    def __init__(self, name: str, args: dict, brand: str = None, command_type: CommandType = CommandType.regular, mapping: dict[str, str] = {}) -> None:
        """
        Initializes a Command object.
        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            command_type (CommandType): The type of the command.
            mapping (dict[str, str]): A dictionary containing the mapping of the command context outputs.
                Example: {"Name": "Value"} will map the command argument "Name" to "Value".
                For nested mapping use double dot notation. Example:
                {"Name..Value": "Value"} will map the context {"Name": {"Value": "example"}} to {"Value": "example"}.
                When empty mapping is given, the context result will be mapped to the same name.
        """
        self.name: str = name
        self.args: dict = args
        self.brand: str = brand
        self.command_type: CommandType = command_type
        self.mapping: dict[str, str] = mapping
    
    def __str__(self) -> str:
        """
        Returns a string representation of the Command object.
        """
        return f"Command(name='{self.name}', args={self.args}, type={self.command_type.value})"
    
    def __repr__(self) -> str:
        """
        Returns a string representation of the Command object.
        """
        return f"Command(name='{self.name}', args={self.args}, type={self.command_type.value})"
    
    def to_batch_item(self, brands_to_run: list[str] = []) -> dict:
        """
        Convert to the dict format expected by executeCommandBatch.
        """
        if brands_to_run:
            self.args["using-brand"] = ",".join(brands_to_run)
        return {self.name: self.args}
    
    def execute(self) -> dict:
        """
        Executes the command.
        """
        demisto.debug(f"[Command.execute] Executing command {self.name} with args: {self.args}")
        result = demisto.executeCommand(self.name, self.args)
        demisto.debug(f"[Command.execute] Command {self.name} execution completed with {len(result)} results")
        return result
    
class ReputationCommand(Command):
    """
    Initializes a ReputationCommand object.
    Args:
        name (str): The name of the command.
        args (dict): A dictionary containing the command arguments.
        mapping (dict[str, str]): A dictionary containing the mapping of the command context outputs.
            Example: {"Name": "Value"} will map the command argument "Name" to "Value".
            For nested mapping use double dot notation. Example: {"Name..Value": "Value"} will map the context {"Name": {"Value": "example"}} to {"Value": "example"}.
            When empty mapping is given, the context result will be mapped to the same name.
    """
    def __init__(self, name: str, args: dict, mapping: dict[str, str] = {}, indicator_context_path: str = "") -> None:
        super().__init__(name, args ,command_type=CommandType.external, mapping=mapping)
        self.indicator_context_path = indicator_context_path
        
class TIMCommand(Command):
    """
    Initializes a TIMCommand object.
    Args:
        name (str): The name of the command.
        args (dict): A dictionary containing the command arguments.
        mapping (dict[str, str]): A dictionary containing the mapping of the command context outputs.
            Example: {"Name": "Value"} will map the command argument "Name" to "Value".
            For nested mapping use double dot notation. Example: {"Name..Value": "Value"} will map the context {"Name": {"Value": "example"}} to {"Value": "example"}.
            When empty mapping is given, the context result will be mapped to the same name.
    """
    def __init__(self, mapping: dict[str, str] = {}, indicator_context_path: str = "") -> None:
        super().__init__("search-indicators-in-tim", {}, CommandType.tim, mapping)
        self.indicator_context_path = indicator_context_path

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
        Executes the commands in a batch.
        Returns:
            list[list[dict]]: A list of lists of dictionaries containing the results of the commands.
            The format is [{"command_name": {"arg1": "value1", "arg2": "value2"}}].
            Example: [{"wildfire-get-verdict": {"url": "https://example.com"}}]
        """
        commands_to_execute = [command.to_batch_item(self.brands_to_run) for command in self.commands]
        demisto.debug(f"BatchExecutor.execute Executing batch with the following commands: {self.commands}")
        results = demisto.executeCommandBatch(commands_to_execute)
        demisto.debug(f"BatchExecutor.execute Batch execution completed with {len(results)} result sets")
        return results
        
class AggregatedCommandAPIModule(ABC):
    def __init__(self, args: dict, brands: list[str], verbose: bool, commands: list[Command] = [], validate_input_function: Callable[[dict], bool] = lambda: True):
        """
        Initializes an AggregatedCommandAPIModule object.
        
        Args:
            args (dict): straight forward args from demisto.args()
            brands (list[str]): list of brands to run on
            verbose (bool): whether to run in verbose mode
            commands (list[Command], optional): list of commands to run. Defaults to [].
            validate_input_function (Callable[[dict], bool]): Function to validate the input, the function should receive args, validate the inputs, and raise an error if the input is invalid. Defaults to lambda:True.
        """
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
                    "Ensure valid integration IDs are specified. For example: Cortex Core - IR,WildFire-v2"
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
    
    def prepare_commands(self) -> list[Command]:
        """
        Prepares the commands to execute.
        """
        commands:list[Command] = []
        for command in self.commands:
            demisto.debug(f"Processing command {command.name}.")
            if command.command_type == CommandType.tim:
                continue
            if command.command_type == CommandType.internal and (command.brand in self.brands or not self.brands):
                demisto.debug(f"Adding internal command {command.name} to commands list.")
                commands.append(command)
            if command.command_type == CommandType.external and (self.external_enrichment or self.brands):
                demisto.debug(f"Adding external command {command.name} to commands list.")
                commands.append(command)
            else:
                demisto.debug(f"Command {command.name} is not a valid command type. Skipping.")
        return commands
    
    @cached_property
    def brands_to_run(self):
        return self.get_brands_to_run()
    
class ReputationAggregatedCommand(AggregatedCommandAPIModule):
    def __init__(self,
                 brands: list[str] = [],
                 verbose: bool = False,
                 additional_fields: bool = False,
                 external_enrichment: bool = False,
                 indicator_value_field: str = "",
                 final_context_path: str = "",
                 validate_input_function: Callable[[dict], bool] = lambda: True,
                 args: dict = None,
                 commands: list[Command] = None,
                 data: list[str] = None,
                 indicator_mapping: dict[str, str] = None,
                 indicator_context_path: str = "",
                 indicator_type: str = ""):
        """
        Initializes the reputation aggregated command.
        
        Args:
            brands (list[str]): List of brands to run on.
            verbose (bool): Whether to run in verbose mode.
            additional_fields (bool): Whether to include additional fields in the output.
            external_enrichment (bool): Whether to run external enrichment.
            final_context_path (str): Path to the context to extract to.
            data (dict): Data to enrich Example: {"url": ["https://example.com"]}.
            indicator_value_field (str): Field to extract the indicator value from.
            validate_input_function (Callable[[dict], bool]): Function to validate the input, the function should receive args, validate the inputs, and raise an error if the input is invalid. Defaults to lambda:True.
            commands (list[Command]): List of commands to run.
        """
        super().__init__(args, brands, verbose, commands, validate_input_function)
        self.external_enrichment = external_enrichment
        self.final_context_path = final_context_path
        self.additional_fields = additional_fields
        self.data = data
        self.indicator_value_field = indicator_value_field
        self.indicator_type = indicator_type
        self.command_tim = TIMCommand(indicator_context_path=indicator_context_path, mapping=indicator_mapping)
    
    def aggregated_command_main_loop(self):
        """
        Main loop for the aggregated command.
        """
        demisto.debug("Starting Reputation aggregated command main loop.")
        commands_to_execute = self.prepare_commands()
        demisto.debug(f"Commands to execute: {[command.to_batch_item() for command in commands_to_execute]}")
        tim_context_output, dbot_scores_context_tim, entry_tim_results = self.get_indicators_from_tim(self.command_tim)
        demisto.debug(f"Tim context output: {json.dumps(tim_context_output, indent=4)}")
        demisto.debug(f"Tim dbot scores context: {json.dumps(dbot_scores_context_tim, indent=4)}")
        demisto.debug(f"Tim entry results: {json.dumps(entry_tim_results, indent=4)}")
        batch_executor = BatchExecutor(commands_to_execute, self.brands_to_run)
        demisto.debug("Executing BatchExecutor.")
        batch_results = batch_executor.execute()
        demisto.debug(f"Batch per command results: {[len(result) for result in batch_results]}")
        
        batch_executor_context, dbot_scores_context_batch, verbose_batch_results, entry_batch_results = self.process_batch_results(batch_results, commands_to_execute)
        final_context = self.merge_context(tim_context_output, batch_executor_context,
                                            dbot_scores_context_tim, dbot_scores_context_batch,
                                            )
        return  self.summarize_command_results(entry_tim_results,entry_batch_results, verbose_batch_results,final_context)

        
        
        
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
            demisto.debug(f"Could not find indicator with value: {data_list}.")
            result_entry.update({"status": "Failure", "message": "No Indicators found."})
            
        return search_results, result_entry
    
    def get_indicators_from_tim(self, tim_command: Command) -> tuple[dict[str, list], list[dict], dict[str, Any]]:
        """
        Parses the results from the Thread Intelligence Module (TIM) and transforms
        the Indicator of Compromise (IOC) into a standard context output by extracting the `indicator` dictionary. It also adds source
        brand fields to additional context items.
        
        Args:
            tim_command (Command): The TIM command to execute.
        
        Returns:
            tuple[dict[str, list], list[dict], dict[str, Any]]: The TIM context output and DBot scores list.
        """
        result_entries: list[dict[str, Any]] = []
        tim_context_output: dict[str,dict[str, list]] = {}
        dbot_scores_context: list[dict[str, Any]] = []


        demisto.debug(f"Starting to search for {self.indicator_type} indicator with values: {self.data}.")
        search_results, result_entry = self.search_indicators_in_tim(self.indicator_type,self.data)
        result_entries.append(result_entry)
        if not search_results:
            return {}, [], result_entries
        
        demisto.debug(f"going to process tim results for indicator type: {self.indicator_type}.")
        
        self.process_tim_results(search_results, dbot_scores_context, tim_context_output, tim_command)
                        
        return tim_context_output, dbot_scores_context, result_entries
    
    def process_tim_results(self, search_results, dbot_scores_context, tim_context_output, tim_command: Command):
        """
        Processes the results from the TIM command and update the tim context in place.
        indicators are extracted from the search results and added to the tim context under the indicator type and brand.
        Example:
        tim_context_output = {
            "url": {
                "TIM": [
                    {
                        "score": 1,
                        "context": {
                            "url": "https://example.com",
                            "brand": "TIM",
                            "positiveDetections": 1,
                            "detectionEngines": 1,
                        },
                    }
                ]
            }
        }
        DBot scores are extracted from the search results and added to the DBot scores context.
        Args:
            search_results (list[dict[str, Any]]): The search results from the TIM command.
            dbot_scores_context (list[dict[str, Any]]): The DBot scores context.
            tim_context_output (dict[str, dict[str, list]]): The TIM context output.
            tim_command (Command): The TIM command to execute.
        
        """
        iocs = flatten_list([result.get("iocs") or [] for result in search_results])
        demisto.debug(f"Total iocs: {len(iocs)}")
        for ioc in iocs:
            # Extract indicators context
            indicator_context_list = ioc.get("insightCache", {}).get("scores", {})
            for brand, indicators in indicator_context_list.items():
                score = indicators.get("score", 0)
                context = indicators.get("context", {})
                parsed_indicators_context, parsed_dbot_scores_context = self.parse_indicator(context, brand, score, tim_command)
                demisto.debug(f"Parsed indicators context: {json.dumps(parsed_indicators_context, indent=4)}")
                demisto.debug(f"Parsed dbot scores context: {json.dumps(parsed_dbot_scores_context, indent=4)}")
                merge_nested_dicts_in_place(tim_context_output, parsed_indicators_context)
                demisto.debug(f"Tim context output after merging: {json.dumps(tim_context_output, indent=4)}")
                dbot_scores_context.extend(parsed_dbot_scores_context)
        
    
    def process_batch_results(self,
                              execution_results: list[list[dict[str, Any]]],
                              commands_to_execute: list[Command],
                              ) -> tuple[defaultdict[str, defaultdict[str, list]],
                                         list[dict[str, Any]],
                                         list[dict[str,str]],
                                         list[str]]:
        """
        Processes the results from the batch executor.
        runs through the execution results and processes each result.
        
        Args:
            execution_results (list[list[dict[str, Any]]]): The search results from the TIM command.
            commands_to_execute (list[Command]): The commands to execute.
        
        Returns:
            tuple[defaultdict[str, defaultdict[str, list]],
                 list[dict[str, Any]],
                 list[dict[str,str]],
                 list[str]]: The batch context output, dbot scores context, verbose command results, and entry results.
        
        """
        verbose_command_results: list[str] = []
        entry_results: list[dict[str, Any]] = []
        batch_context: defaultdict[str, defaultdict[str, list]] = defaultdict(lambda: defaultdict(list))
        dbot_scores_context: list[dict[str, Any]] = []
        
        for command, execution_result in zip(commands_to_execute, execution_results):
            demisto.debug(f"Processing result for command: {command} len: {len(execution_result)}")
            for i,result in enumerate(execution_result):
                demisto.debug(f"Processing result {i}, with type: {get_type(result)}")
                demisto.debug(f"Result for the command: {json.dumps(result, indent=4)}")
                if is_debug(result):
                    demisto.debug(f"Skipping debug result {i}")
                    continue
                command_context, dbot_scores, human_readable, result_entry = self.parse_result(result, command)
                demisto.debug(f"Parsed command context: {json.dumps(command_context, indent=4)}")
                demisto.debug(f"Parsed dbot scores: {json.dumps(dbot_scores, indent=4)}")
                demisto.debug(f"Parsed human readable: {json.dumps(human_readable, indent=4)}")
                demisto.debug(f"Parsed result entry: {json.dumps(result_entry, indent=4)}")
                demisto.debug(f"batch_context before merge: {json.dumps(batch_context, indent=4)}")
                if command_context:
                    merge_nested_dicts_in_place(batch_context, command_context)
                demisto.debug(f"batch_context after merge: {json.dumps(batch_context, indent=4)}")
                if dbot_scores:
                    dbot_scores_context.extend(dbot_scores)
                if result_entry:
                    entry_results.append(result_entry)
                if human_readable:
                    verbose_command_results.append(human_readable)
        return batch_context, dbot_scores_context, verbose_command_results, entry_results

    def parse_result(self, result: dict[str, Any], command: Command)-> tuple[dict[str, Any], list[dict[str, Any]], str, dict[str, Any]]:
        """
        Parses the result of a command.
        Depends on the command type. All reputation commands are parsed as indicators under the following structure:
        indicators_context = {
            "data": {
                "brand": [{}]
            }
        }
        for not reputation commands each result will be parsed by the mapping into the final context
        DBot scores are extracted to one list of DBotScores.
        Args:
            result (dict[str, Any]): The result of a command.
            command (Command): The command associated with the result.
            brand (str): The brand associated with the result.
        Returns:
            tuple[dict[str, Any], list[dict[str, Any]], str, dict[str, Any]]:
            The context, dbot scores, human readable and result entry.
        """
        indicator, brand = extract_data(result)
        result_entry = {"command name": command.name,
                        "brand": brand,
                        "args": json.dumps(command.args),
                        "status": "Success",
                        "message": ""}
        human_readable = ""
        indicators_context: dict[str, list] = defaultdict(list)
        dbot_scores_context: list[dict[str, Any]] = []

        if is_error(result):
            result_entry.update({"status": "Failure", "message": get_error(result).split("\n")[:2]})
        if self.verbose and (human_readable := result.get("HumanReadable")):
            human_readable = f"#### Result for name={command.name} args={command.args} current brand={brand}\n{human_readable}"
            
        if entry_context_item := result.get("EntryContext"):
            # parse_command_result
            if isinstance(command, ReputationCommand):
                demisto.debug(f"Parsing indicator for reputation command: {command}")
                indicators_context, dbot_scores_context = self.parse_indicator(entry_context_item, brand, command=command)
            else:
                demisto.debug(f"Mapping indicator for command: {command}")
                indicators_context = self.map_command_context(entry_context_item, command.mapping)
                
        return indicators_context, dbot_scores_context, human_readable, result_entry
    
    def map_command_context(self, entry_context_item: dict[str, Any], mapping: dict[str, str])-> dict[str, Any]:
        """
        Maps the entry context item to the final context using the mapping.
        Args:
            entry_context_item (dict[str, Any]): The entry context item.
            mapping (dict[str, str]): The mapping to use.
            Example:
                mapping = {"reslut..value": "final_context..value"} will map the value of {"results":{"value":value}} to {"final_context":{"value":value}}
                can use [] to transform the final path value to list Example:
                mapping = {"reslut..value": "final_context..value[]"} will map the value of {"results":{"value":value}} to {"final_context":{"value":[value]}}
                
        Returns:
            dict[str, Any]: The mapped context.
        """
        if not mapping:
            return entry_context_item
        mapped_context = defaultdict()
        
        for src, dst in mapping.items():
            demisto.debug(f"Mapping {src} to {dst}")
            set_dict_value(mapped_context, dst, get_dict_value(entry_context_item, src))
        if self.additional_fields:
            set_dict_value(mapped_context, "AdditionalFields", entry_context_item)
        
        return mapped_context
    
    def parse_indicator(self,
                        entry_context_item: dict[str, Any],
                        brand: str,
                        score: int = Common.DBotScore.NONE,
                        command: Command = None,
                        )-> tuple[dict[str, Any], list[dict[str, Any]]]:
        """
        Parse the indicator context and complete missing fields such as brand, score, verdict.
        Mapping is used to map the indicator context to the final context.
        What is not mapped is added to the AdditionalFields.
        Args:
            entry_context_item (dict[str, Any]): The entry context item.
            brand (str): The brand.
            score (int, optional): The score. Defaults to Common.DBotScore.NONE.
            command (Command, optional): The command. Defaults to None.
        Returns:
            tuple[dict[str, Any], list[dict[str, Any]]]: The parsed result.
        """
        indicators_context = defaultdict(lambda: defaultdict(list))
        dbot_list = flatten_list([value for key, value in entry_context_item.items() if key.startswith("DBotScore")])
        score = score or max([dbot.get("Score") for dbot in dbot_list], default=Common.DBotScore.NONE)
        entry_context_item = flatten_list([value for key, value in entry_context_item.items() if key.startswith(command.indicator_context_path)])
        for indicator in entry_context_item:
            indicator = self.map_command_context(indicator, command.mapping)
            indicator["Brand"] = brand
            indicator["Score"] = score
            indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(indicator["Score"], "Unknown")
            indicators_context[indicator.get(self.indicator_value_field)][brand].append(indicator)
            demisto.debug(f"Parsed indicator: {indicator.get(self.indicator_value_field)} from brand: {brand} with score: {score} and verdict: {indicator['Verdict']}")
        
        return indicators_context, dbot_list
    
    def merge_context(self,
                                  tim_context_output,
                                  batch_executor_context,
                                  dbot_scores_context_tim,
                                  dbot_scores_context_batch,
                                  ):
        """
        Summarizes the results of a reputation command.
        Foreach data in self.data construct one summary of the data, max score, max verdict and results list,
        All indicators are added to the results list.
        Indicator from reputation are prioritize over indicators from TIM.
        Dbot Score are listed in one list.
        Args:
            tim_context_output (dict[str, Any]): The context output of the TIM.
            batch_executor_context (dict[str, Any]): The context output of the batch executor.
            dbot_scores_context_tim (list[dict[str, Any]]): The DBotScore context of the TIM.
            dbot_scores_context_batch (list[dict[str, Any]]): The DBotScore context of the batch executor.
        Returns:
            dict[str, Any]: The final context.
        """
        results_context = []
        for data in self.data:
            if data not in tim_context_output:
                continue
            results_list = flatten_list(list(batch_executor_context[data].values()))
            for brand, result in tim_context_output[data].items():
                if brand not in batch_executor_context[data]:
                    results_list.extend(flatten_list(result))
            max_score = max([result.get("Score", Common.DBotScore.NONE) for result in results_list])
            max_verdict = DBOT_SCORE_TO_VERDICT.get(max_score, "Unknown")
            data_context = {self.indicator_value_field: data,
                            "max_score": max_score,
                            "max_verdict": max_verdict,
                            "results": results_list}
            results_context.append(data_context)
        demisto.debug(f"DBot scores context TIM: {json.dumps(dbot_scores_context_tim, indent=4)}")
        demisto.debug(f"DBot scores context Batch: {json.dumps(dbot_scores_context_batch, indent=4)}")
        dbot_scores_context = dbot_scores_context_tim + dbot_scores_context_batch
        demisto.debug(f"final DBot scores context: {json.dumps(dbot_scores_context, indent=4)}")
        final_context = defaultdict(lambda: defaultdict(list))
        for key in batch_executor_context:
            if key not in self.data:
                final_context[key] = batch_executor_context[key]
        final_context.update({self.final_context_path:results_context,
                             "DBotScore":dbot_scores_context})
        return final_context
        
    def summarize_command_results(self, entry_tim_results: list[dict[str, Any]], entry_batch_results: list[dict[str, Any]], verbose_batch_results: list[dict[str, Any]], final_context: dict[str, Any]):
        """
        Summarizes the human readable output.
        Construct the final table from the results of the TIM and the batch executor.
        adds verbose messages from all commands if verbose is True.
        If all commands failed, return an error message.
        
        Args:
            entry_tim_results (list[dict[str, Any]]): The entry results of the TIM.
            entry_batch_results (list[dict[str, Any]]): The entry results of the batch executor.
            verbose_batch_results (list[dict[str, Any]]): The verbose results of the batch executor.
            final_context (dict[str, Any]): The final context.
        Returns:
            CommandResults: The command results.
        """
        human_readable = tableToMarkdown("Final Results", t=entry_tim_results + entry_batch_results,
                                         headers=["command name", "brand", "args", "status", "message"])
        if self.verbose:
            human_readable += "\n\n".join(verbose_batch_results)
        if all(entry.get("status") == "Failure" for entry in entry_tim_results + entry_batch_results):
            return CommandResults(readable_output= "Error: All commands failed." + human_readable, outputs=final_context, type=CommandResultsType.ERROR)
        return CommandResults(readable_output=human_readable, outputs=final_context)
        

"""HELPER FUNCTIONS"""


def merge_nested_dicts_in_place(dict1: dict, dict2: dict) -> None:
    """
    Merges dict2 into dict1 in-place for nested dictionaries of the form.
    Assuming both dict1 and dict2 are of the form:
    {data: {brand: [results]}}
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
    list_mode = False
    if path.endswith("[]"):
        list_mode = True
        path = path[:-2]
    demisto.debug(f"list_mode: {list_mode}, path: {path}, value: {value}")
    # Field in root
    if ".." not in path:
        if list_mode:
            d.setdefault(path, []).append(value)
        else:
            d[path] = value
        return
    
    # Field nested
    parts = path.split("..")
    current = d
    
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    
    last = parts[-1]
    demisto.debug(f"last: {last}, list_mode: {list_mode}")
    if list_mode:
        demisto.debug(f"current: {current}")
        # create or append to list
        current.setdefault(last, []).append(value)
        demisto.debug(f"current after: {current}")
    else:
        current[last] = value


def get_dict_value(d: dict[str, Any], path: str) -> Any:
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
        return None

    if ".." not in path:
        value = d.get(path)
        d.pop(path, None)
        return value

    keys = path.split("..")
    current = d
    for key in keys[:-1]:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None

    last_key = keys[-1]
    if isinstance(current, dict) and last_key in current:
        value = current[last_key]
        del current[last_key]
        return value

    return None

def is_debug(execute_command_result):
    """
        Check if the given execute_command_result has an error entry

        :type execute_command_result: ``dict`` or ``list``
        :param execute_command_result: Demisto entry (required) or result of demisto.executeCommand()

        :return: True if the execute_command_result has an error entry, false otherwise
        :rtype: ``bool``
    """
    if execute_command_result is None:
        return False

    if isinstance(execute_command_result, list) and len(execute_command_result) > 0:
        for entry in execute_command_result:
            if type(entry) == dict and entry['Type'] == entryTypes['debug']:
                return True

    return type(execute_command_result) == dict and execute_command_result['Type'] == entryTypes['debug']

def get_type(execute_command_result):
    if execute_command_result is None:
        return None
    if isinstance(execute_command_result, list) and len(execute_command_result) > 0:
        return execute_command_result[0]['Type']
    return execute_command_result['Type']
    
def extract_data(result: dict[str, Any]):
    brand = result.get("Metadata", {}).get("brand")
    demisto.debug(f"result-------------: {result}")
    demisto.debug(f"brand-------------: {brand}")
    entry_context = result.get("EntryContext", {})
    demisto.debug(f"entry_context-------------: {entry_context}")
    if not entry_context:
        return None, brand
    dbot_score = flatten_list([value for key, value in entry_context.items() if key.startswith("DBotScore")])
    demisto.debug(f"dbot_score-------------: {dbot_score}")
    if dbot_score:
        return dbot_score[0].get("Indicator"), brand
    return None, brand
        
    
