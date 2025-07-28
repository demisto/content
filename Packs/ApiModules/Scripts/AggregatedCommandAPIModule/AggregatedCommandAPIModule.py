from enum import Enum
import json
from collections.abc import Callable

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
    def __init__(self, name: str, args: dict, type: CommandType, context_path: str = None) -> None:
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

    def prepare_human_readable(
        self, human_readable: str, is_error: bool = False, brand_name: str = None, data: str = None
    ) -> CommandResults:
        """
        Prepare human-readable output for a command execution.
        Args:
            human_readable (str): The human-readable output of the command.
            is_error (bool): Whether the command resulted in an error. Defaults to False.
            brand_name (str): Brand name associated with the command.
            data (str): Data associated with the command.
        Returns:
            CommandResults: CommandResult object with the formatted output.
        """
        if not is_error:
            return CommandResults(readable_output=f"#### Result for !{self.name}={data} brand={brand_name}\n{human_readable}")
        return CommandResults(
            readable_output=f"#### Error for !{self.name}={data} brand={brand_name}\n{human_readable}", entry_type=EntryType.ERROR
        )

    def execute(self) -> tuple[list[dict], list[CommandResults]]:
        """
        Executes the specified command with given arguments, handles any errors, and parses the execution results.
        Returns:
            tuple[list[dict], list[CommandResults]]: A tuple of entry context dictionaries and human-readable CommandResults.
        """
        demisto.debug(f"Starting to execute command: {self}.")
        execution_results = demisto.executeCommand(self.name, self.args)
        if not execution_results:
            demisto.debug(f"Got no execution response from command: {self}")
            return [], {}
        indicator_context: dict = {}
        dbot_scores_context: list[dict] = []
        readable_command_results: dict[str, CommandResults] = {}

        for result in execution_results:
            brand = result.get("Metadata", {}).get("brand")
            if is_error(result):
                readable_command_results[brand] = self.prepare_human_readable(
                        get_error(result), is_error=True, brand_name=brand, data=self.args[self.indicator_type]
                    )
                continue
            
            if human_readable := result.get("HumanReadable"):
                readable_command_results[brand] = self.prepare_human_readable(
                    human_readable, brand_name=brand, data=self.args[self.indicator_type]
                )

            if entry_context_item := result.get("EntryContext"):
                entry_context_item["Brand"] = brand
                entry_context.append(entry_context_item)
                
            
        return indicator_context, dbot_scores_context, readable_command_results

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
    
# Disable insecure warnings
class AggregatedCommandAPIModule(ABC):
    def __init__(self, main_keys: list[str], brands: list[str], verbose: bool, additional_fields: bool, commands: list[Command] = []):
        self.main_keys = main_keys
        self.brands = brands
        self.verbose = verbose
        self.additional_fields = additional_fields
        self.commands = commands
        self.brands_to_run = self.get_brands_to_run()
    
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
        return brands_to_execute
    
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
                args = command.args
                args["using-brand"] = brands_to_run_input
                command = {command.name: args}
                commands.append(command)
        return commands
    
class ReputationAggregatedCommand(AggregatedCommandAPIModule):
    def __init__(self,
                 main_keys: list[str] = [],
                 internal_brands: list[str] = [],
                 external_brands: list[str] = [],
                 verbose: bool = False,
                 additional_fields: bool = False,
                 external_enrichment: bool = False,
                 data_list: list[str] = [],
                 indicator_type: str = None,
                 context_path: str = "",
                 indicator_path: str = "",
                 indicator_value_field: str = "",
                 validate_input_function: Callable[[dict], bool] = lambda: True,
                 commands: list[Command] = []):
        """
        Initializes the reputation aggregated command.
        
        Args:
            main_keys (list[str]): List of main keys to extract from the indicator context.
            internal_brands (list[str]): List of internal brands to run on.
            external_brands (list[str]): List of external brands to run on.
            verbose (bool): Whether to run in verbose mode.
            additional_fields (bool): Whether to include additional fields in the output.
            external_enrichment (bool): Whether to run external enrichment.
            data_list (list[str]): Data to search for.
            indicator_type (str): Type of indicator to search for.
            context_path (str): Path to the context to extract to.
            c (str): Path to the indicator to extract from.
            indicator_value_field (str): Field to extract the indicator value from.
            validate_input_function (Callable[[dict], bool]): Function to validate the input.
            commands (list[Command]): List of commands to run.
        """
        super().__init__(main_keys, internal_brands, verbose, additional_fields, commands)
        self.external_enrichment = external_enrichment
        self.data_list = data_list
        self.indicator_type = indicator_type
        self.context_path = context_path
        self.indicator_path = indicator_path
        self.indicator_value_field = indicator_value_field
        self.external_brands = external_brands
        self.external_enrichment = external_enrichment
        self.validate_input_function = validate_input_function
        
    
    def search_indicators_in_tim(self) -> tuple[dict[str, list], dict[str, dict[str, list[CommandResults]]]]:
        """
        Searches for the URL indicator using the URL value in the Thread Intelligence Module (TIM). If found, it transforms
        the Indicator of Compromise (IOC) into a standard context output by extracting the `URL` dictionary. It also adds source
        brand fields to additional context items.

        Args:
            url (str): URL to search for.
            context_output (dict[str, list]): Dictionary of the entry context (value) of each command name (key).
            verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
        """
        verbose_command_results: dict[str, dict[str, list[CommandResults]]] = {}
        context_output: dict[str, list] = {}
        for data in self.data_list:
            demisto.debug(f"Starting to search for {indicator_type} indicator with values: {data_list}.")
            try:
                indicators = " or ".join({f"value: {indicator}" for indicator in data_list})
                search_results = IndicatorsSearcher(query=f"type:{indicator_type} and ({indicators})", size=len(data_list))
            except Exception as e:
                demisto.debug(
                    f"Error searching for {indicator_type} indicator with value: {data_list}. Error: {str(e)}.\n{traceback.format_exc()}"
                )
                readable_command_results = CommandResults(
                    readable_output=f"#### Error for Search Indicators\n{str(e)}", entry_type=EntryType.ERROR
                )
                verbose_command_results[data]["TIM"] = readable_command_results
                return verbose_command_results, context_output

            if not search_results:
                demisto.debug(f"Could not find indicator with value: {indicator_list}.")
                readable_command_results = CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
                verbose_command_results[data]["TIM"] = readable_command_results
                return verbose_command_results, context_output
            
            tim_output: dict[str, list] = defaultdict(list)
            dbot_score_output: list[dict[str, Any]] = []
            demisto.debug(f"IOCS Found: {search_results.total}")
            
            for ioc in search_results:
                # Extract indicators context
                indicator_context_list = ioc.get("insightCache").get("scores")
                for brand, indicators in indicator_context_list.items():
                    score = indicators.get("score", 0)
                    context = indicators.get("context", {})
                    url_indicators = [value for key, value in context.items() if key.startswith(self.indicator_path)]
                    demisto.debug(f"Brand {brand}, Score: {score}, Number of indicators {len(url_indicators)}")
                    for indicator in url_indicators:
                        if indicator.get(self.indicator_value_field):
                            indicator_context = {"Brand": brand, "Score": score , "Verdict": DBOT_SCORE_TO_VERDICT.get(score, "Unknown")}
                            indicator_context.update(construct_context_by_keys(indicator, self.main_keys, self.additional_fields))
                            demisto.debug(f"Indicator context: {indicator_context}")
                            tim_output[indicator[self.indicator_value_field]].append(indicator_context)
                    
                    dbot_list = [value for key, value in context.items() if key.startswith("DBotScore")]
                    for dbot in dbot_list:
                        dbot_score_output.extend(dbot)
                    
                    
                    table = tableToMarkdown(name="Found Indicators", t=tim_output)
                    readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")
                    
                    verbose_command_results[data]["TIM"] = readable_command_results
                demisto.debug("------------End-IOC------------")
                
            for tim_score in tim_output:
                demisto.debug(f"TIM output: {tim_score}")
                demisto.debug("------------End-TIM------------")
            context_output["TIM"] = {"indicator": tim_output, "DBotScore": dbot_score_output}
            demisto.debug(json.dumps(context_output, indent=4))
            
        return context_output, verbose_command_results
    
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
    
    def execute_command(self, commands: list[])-> tuple[list[dict], list[CommandResults]]:
        """
        Executes the reputation aggregated command.
        """
        entry_context, readable_command_results = demisto.executeCommandBatch(commands)
        context_output: dict[str, list] = {}
        
        indicators_context: dict[str, list] = defaultdict(list)
        dbot_scores_context: list[dict[str, Any]] = []
        
        for context_item in entry_context:
            score = Common.DBotScore.NONE
            if dbot_scores := context_item.get("DBotScore"):
                dbot_scores_context.extend(dbot_scores)
                score = max([score.get("Score") for score in dbot_scores])
                
            if indicators := get_from_context(context_item, command.context_path):
                for indicator in indicators:
                    if command.type == CommandType.external:
                        indicator = construct_context_by_keys(indicator, self.main_keys, self.additional_fields)
                        indicator["Brand"] = context_item["Brand"]
                        indicator["Score"] = indicator.get("Score") or score
                        indicator["Verdict"] = DBOT_SCORE_TO_VERDICT.get(indicator["Score"], "Unknown")
                        indicators_context[indicator[self.indicator_value_field]].append(indicator)
                    elif command.type == CommandType.internal:
                        indicators_context[indicator[self.indicator_value_field]].append(indicator)

        context_output[command.type] = {"indicator": indicators_context, "DBotScore": dbot_scores_context}
        return context_output, readable_command_results
        
    def aggregated_command_main_loop(self):
        """
        Main loop for the aggregated command.
        """
        if not self.validate_input_function():
            raise DemistoException("Invalid input parameters.")
        
        context = defaultdict(dict)
        verbose_command_results = {}
        
        context_output_tim, verbose_command_tim = self.search_indicators_in_tim()
        context.update(context_output_tim)
        verbose_command_results.update(verbose_command_tim)
        
        
        commands_to_execute = self.prepare_commands()
        
        results = self.execute_command(commands_to_execute)
        
        command_results = self.summarize_command_results(context, verbose_command_results)
        if verbose:
            command_results = [command_results, *verbose_command_results]
                
        return command_results

                
                
                
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
                command_response = 
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