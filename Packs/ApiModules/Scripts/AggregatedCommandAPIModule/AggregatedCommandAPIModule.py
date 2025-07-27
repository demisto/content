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

# Disable insecure warnings
class AggregatedCommandAPIModule(ABC):
    def __init__(self, main_keys: list[str], brands: list[str], verbose: bool, additional_fields: bool):
        self.main_keys = main_keys
        self.brands = brands
        self.verbose = verbose
        self.additional_fields = additional_fields
    
    def get_active_brands(self) -> list[str]:
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
    
class ReputationAggregatedCommand(AggregatedCommandAPIModule):
    def __init__(self, main_keys: list[str] = [],
                 internal_brands: list[str] = [],
                 external_brands: list[str] = [],
                 verbose: bool = False,
                 additional_fields: bool = False,
                 external_enrichment: bool = False,
                 data: dict = {},
                 indicator_type: str = None,
                 context_path: str = "",
                 indicator_path: str = "",
                 indicator_value_field: str = "",
                 validate_input_function: Callable[[dict], bool] = lambda: True):
        super().__init__(main_keys, internal_brands, verbose, additional_fields)
        self.external_enrichment = external_enrichment
        self.data = data
        self.indicator_type = indicator_type
        self.context_path = context_path
        self.indicator_path = indicator_path
        self.indicator_value_field = indicator_value_field
        self.external_brands = external_brands
        self.external_enrichment = external_enrichment
        self.validate_input_function = validate_input_function
        
    def execute(self):
        """
        Executes the reputation aggregated command.
        """
    
    def search_indicators_in_tim(self) -> tuple[list[CommandResults], dict[str, list]]:
        """
        Searches for the URL indicator using the URL value in the Thread Intelligence Module (TIM). If found, it transforms
        the Indicator of Compromise (IOC) into a standard context output by extracting the `URL` dictionary. It also adds source
        brand fields to additional context items.

        Args:
            url (str): URL to search for.
            context_output (dict[str, list]): Dictionary of the entry context (value) of each command name (key).
            verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
        """
        verbose_command_results: list[CommandResults] = []
        context_output: dict[str, list] = {}
        for indicator_type, data_list in self.data.items():
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
                verbose_command_results.append(readable_command_results)
                return verbose_command_results, context_output

            if not search_results:
                demisto.debug(f"Could not find indicator with value: {indicator_list}.")
                readable_command_results = CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
                verbose_command_results.append(readable_command_results)
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
                    demisto.debug(f"Brand {brand} Score: {score}")
                    url_indicators = [value for key, value in context.items() if key.startswith(self.indicator_path)]
                    for indicator in url_indicators:
                        if indicator.get(self.indicator_value_field):
                            indicator_context = {"Brand": brand, "Score": score , "Verdict": DBOT_SCORE_TO_VERDICT.get(score, "Unknown")}
                            indicator_context.update(construct_context_by_keys(indicator, self.main_keys, self.additional_fields))
                            demisto.debug(f"Indicator context: {indicator_context}")
                            tim_output[indicator[self.indicator_value_field]].append(indicator_context)
                    
                    dbot_list = [value for key, value in context.items() if key.startswith("DBotScore")]
                    for dbot in dbot_list:
                        demisto.debug(f"DBotScore for brand {brand}: {dbot}")
                        dbot_score_output.extend(dbot)
                    
                    
                    table = tableToMarkdown(name="Found Indicators", t=tim_output)
                    readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")
                    
                    verbose_command_results.append(readable_command_results)
                demisto.debug("------------End-IOC------------")
                
            for tim_score in tim_output:
                demisto.debug(f"TIM output: {tim_score}")
                demisto.debug("------------End-TIM------------")
            context_output["TIM"] = {"indicator": tim_output, "DBotScore": dbot_score_output}
            demisto.debug(json.dumps(context_output, indent=4))
            
        return verbose_command_results, context_output
    
    def execute_command(self, brands: list[str]) -> tuple[list[CommandResults], dict[str, list]]:
        """
        Executes the reputation aggregated command.
        """
        demisto.debug(f"Starting to execute command: !{self.indicator_type} brand={self}.")
        execution_results = demisto.executeCommand(self.name, self.args)
        
        
    def aggregated_command_main_loop(self):
        """
        Main loop for the aggregated command.
        """
        if not self.validate_input_function():
            raise DemistoException("Invalid input parameters.")
        
        context_output_tim, verbose_command_tim = self.search_indicators_in_tim()
        
        context_output_internal, verbose_command_internal = self.execute_command(brands=self.internal_brands)
        if self.external_enrichment:
            context_output_external, verbose_command_external = self.execute_command(brands=self.external_brands)
        
        
            
        
        