import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from enum import Enum
from typing import Any
from collections import defaultdict

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


class Command:
    def __init__(self, name: str, args: dict, brand: str, indicator_type: str = None) -> None:
        """
        Initializes a Command object.

        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            brand (str): Brand associated with the command.
        """
        self.brand: str = brand
        self.name: str = name
        self.args: dict = args
        self.indicator_type: str = indicator_type

    def prepare_human_readable(
        self, human_readable: str, is_error: bool = False, brand_name: str = None, url: str = None
    ) -> CommandResults:
        """
        Prepare human-readable output for a command execution.

        Args:
            human_readable (str): The human-readable output of the command.
            is_error (bool): Whether the command resulted in an error. Defaults to False.
            brand_name (str): Brand name associated with the command.
            url (str): URL associated with the command.

        Returns:
            CommandResults: CommandResult object with the formatted output.
        """
        if not is_error:
            return CommandResults(readable_output=f"#### Result for !url={url} brand={brand_name}\n{human_readable}")
        demisto.debug(f"Error for !url={url} brand={brand_name}\n{human_readable}")
        return CommandResults(
            readable_output=f"#### Error for !url={url} brand={brand_name}\n{human_readable}", entry_type=EntryType.ERROR
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
            error_message = f"No execution response from command: {self}"
            error_result = self.prepare_human_readable(error_message, is_error=True)
            return [], [error_result]
        demisto.debug("------------execute-----------")
        entry_context: list[dict] = []
        readable_command_results: list[CommandResults] = []

        for result in execution_results:
            brand = result.get("Metadata", {}).get("brand")
            demisto.debug(f"Brand: {brand}")
            if is_error(result):
                readable_command_results.append(
                    self.prepare_human_readable(
                        get_error(result), is_error=True, brand_name=brand, url=self.args[self.indicator_type]
                    )
                )
                continue

            if human_readable := result.get("HumanReadable"):
                demisto.debug(f"Human readable output: {human_readable}")
                readable_command_results.append(
                    self.prepare_human_readable(human_readable, brand_name=brand, url=self.args[self.indicator_type])
                )

            if entry_context_item := result.get("EntryContext"):
                entry_context_item["Brand"] = brand
                entry_context.append(entry_context_item)
                demisto.debug("---------Entry---------context---------")
                demisto.debug(f"Entry context: {json.dumps(entry_context_item, indent=2)}")

        demisto.debug(f"Finished parsing execution response of command: {self}.")
        demisto.debug("------------execute entry context-----------")
        demisto.debug(f"Entry context: {json.dumps(entry_context, indent=2)}")
        return entry_context, readable_command_results

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


""" HELPER FUNCTION """


def get_from_context(entry_context_item: dict, context_path: str) -> list:
    """
    Gets an item from the entry context by key. If the value is not a list, it is converted into a list of one item.

    Args:
        entry_context_item (dict): The entry context item in the command response.
        context_path (str): Key of the item in the context dictionary.

    Returns:
        dict: Value from the context.
    """
    value = entry_context_item.get(context_path) or {}

    return value if value and isinstance(value, list) else [value]


def is_valid_url(url_list: list[str]) -> bool:
    """
    Checks if all URLs in the provided list are valid.

    Args:
        url_list (list[str]): List of URLs to validate.

    Returns:
        bool: True if all URLs in the list are valid, False otherwise.
    """
    return


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


def construct_context_by_keys(context_items: dict, keys: list[str], additional_fields: bool = False):
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
    for key, values in context_items.items():
        if key in keys:
            output[key] = values
        elif additional_fields:
            set_dict_value(output, f"AdditionalFields.{key}", values)
    return output


def merge_context(output_context: dict, url_list: list[str], indicator_type: str) -> dict:
    """
    Merge TIM and command results into the final structure:
      {
        "URLEnrichment(val.Data && val.Data == obj.Data && val.Brand == obj.Brand) ": [ ... ],
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [ ... ]
      }
    - For URLEnrichment: unique by (Data, Brand), with command['indicators'] overriding tim['indicator'].
    - For DBotScore: unique by (Indicator, Vendor), with command['DBotScore'] overriding tim['DBotScore'].
    """
    # Merge URLEnrichment entries
    url_enrichment_list = []
    for url in url_list:
        url_context = {"Value": url}
        results_dict = {}
        tim_context = output_context.get("TIM", {}).get("indicator", {}).get(url, [])
        for entry in tim_context:
            demisto.debug(f"TIM indicator entry: {json.dumps(entry, indent=2)}")
            key = (entry[INDICATOR_VALUE_FIELDS[indicator_type]], entry["Brand"])
            results_dict[key] = entry

        command_context = output_context.get("Command", {}).get("indicator", {}).get(url, [])
        for entry in command_context:
            demisto.debug(f"Command indicator entry: {json.dumps(entry, indent=2)}")
            key = (entry[INDICATOR_VALUE_FIELDS[indicator_type]], entry["Brand"])
            results_dict[key] = entry

        if command_context or tim_context:
            results = list(results_dict.values())
            demisto.debug(f"For the following url: {url}, results dict: {json.dumps(results, indent=2)}")
            url_context["Max_score"] = max((indicator.get("Score") for indicator in results), default=Common.DBotScore.NONE)
            url_context["Verdict"] = DBOT_SCORE_TO_VERDICT.get(url_context["Max_score"], "Unknown")
            url_context["Results"] = results
            url_enrichment_list.append(url_context)

    # Merge DBotScore entries
    score_map = {}
    for entry in output_context.get("Command", {}).get("DBotScore", []):
        key = (entry["Indicator"], entry["Vendor"])
        score_map[key] = entry
    for entry in output_context.get("Command", {}).get("DBotScore", []):
        key = (entry["Indicator"], entry["Vendor"])
        score_map[key] = entry  # overrides TIM if duplicate

    return {
        ContextPaths.URL_ENRICHMENT.value: url_enrichment_list,
        ContextPaths.DBOT_SCORE.value: list(score_map.values()),
    }


""" COMMAND EXECUTION FUNCTIONS """


def execute_url_enrichment(
    command: Command, context_output, verbose_command_results, additional_fields=False, indicator_type: str = "url"
):
    entry_context, readable_command_results = command.execute()
    verbose_command_results.extend(readable_command_results)
    # Add each CommandResult to verbose_command_results
    demisto.debug(f"Executing command: {command}.")
    demisto.debug("------------Entry Context------------")
    demisto.debug(f"Entry context: {json.dumps(entry_context, indent=2)}.")
    demisto.debug("------------End Entry Context------------")
    indicators_context: dict[str, list] = defaultdict(list)
    dbot_scores_context: list[dict[str, Any]] = []
    for context_item in entry_context:
        demisto.debug(f"Processing context item: {json.dumps(context_item, indent=2)}.")
        score = Common.DBotScore.NONE
        if dbot_scores := context_item.get("DBotScore"):
            demisto.debug(f"Found DBotScore: {dbot_scores}.")
            dbot_scores_context.extend(dbot_scores)
            score = max([score.get("Score") for score in dbot_scores])
        if urls_context := get_from_context(context_item, CONTEXT_PATH[indicator_type]):
            for url_context in urls_context:
                demisto.debug(f"Found URL context: {url_context}.")
                url_context = construct_context_by_keys(url_context, MAIN_KEYS, additional_fields)
                url_context["Brand"] = context_item["Brand"]
                url_context["Score"] = url_context.get("Score") or score
                url_context["Verdict"] = DBOT_SCORE_TO_VERDICT.get(url_context["Score"], "Unknown")
                demisto.debug(f"Restructured URL context: {json.dumps(url_context, indent=2)}.")
                indicators_context[url_context[INDICATOR_VALUE_FIELDS[indicator_type]]].append(url_context)

    context_output["Command"] = {"indicator": indicators_context, "DBotScore": dbot_scores_context}
    demisto.debug("exited execute_url_enrichment")
    demisto.debug(json.dumps(context_output, indent=2))


def search_url_indicator(
    indicator_list: list[str],
    indicator_type: str,
    context_output: dict[str, list],
    verbose_command_results: list,
    additional_fields: bool = False,
) -> None:
    """
    Searches for the URL indicator using the URL value in the Thread Intelligence Module (TIM). If found, it transforms
    the Indicator of Compromise (IOC) into a standard context output by extracting the `URL` dictionary. It also adds source
    brand fields to additional context items.

    Args:
        url (str): URL to search for.
        context_output (dict[str, list]): Dictionary of the entry context (value) of each command name (key).
        verbose_command_results (list[CommandResults]): List of CommandResults with human-readable output.
    """
    demisto.debug(f"Starting to search for {indicator_type} indicator with value: {indicator_list}.")
    try:
        indicators = " or ".join({f"value: {indicator}" for indicator in indicator_list})
        search_results = IndicatorsSearcher(query=f"type:{indicator_type} and ({indicators})", size=len(indicator_list))
    except Exception as e:
        demisto.debug(
            f"Error searching for {indicator_type} indicator with value: {indicator_list}. Error: {str(e)}.\n{traceback.format_exc()}"
        )
        readable_command_results = CommandResults(
            readable_output=f"#### Error for Search Indicators\n{str(e)}", entry_type=EntryType.ERROR
        )
        verbose_command_results.append(readable_command_results)
        return

    iocs = flatten_list([result.get("iocs") or [] for result in search_results])
    if not iocs:
        demisto.debug(f"Could not find indicator with value: {indicator_list}.")
        readable_command_results = CommandResults(readable_output="#### Result for Search Indicators\nNo Indicators found.")
        verbose_command_results.append(readable_command_results)
        return

    tim_output: dict[str, list] = defaultdict(list)
    dbot_output: list[dict[str, Any]] = []
    demisto.debug(f"IOCS Found: {len(iocs)}")
    for ioc_list_per_url in iocs:
        # Prepare context output
        demisto.debug("-----------PER IOCS-------------")
        indicator_context_list = ioc_list_per_url.get("insightCache").get("scores")
        demisto.debug(f"Brands: {indicator_context_list.keys()}")
        for brand, indicators in indicator_context_list.items():
            score = indicators.get("score", 0)
            context = indicators.get("context", {})
            demisto.debug(f"Brand {brand} Score: {score}, Context: {json.dumps(context, indent=2)}")
            url_indicators = flatten_list(
                [value for key, value in context.items() if key.startswith(INDICATOR_PATH[indicator_type])]
            )
            for indicator in url_indicators:
                if indicator.get(INDICATOR_VALUE_FIELDS[indicator_type]):
                    indicator_context = {"Brand": brand, "Score": score, "Verdict": DBOT_SCORE_TO_VERDICT.get(score, "Unknown")}
                    indicator_context.update(construct_context_by_keys(indicator, MAIN_KEYS, additional_fields))
                    demisto.debug(f"Indicator context: {indicator_context}")
                    tim_output[indicator[INDICATOR_VALUE_FIELDS[indicator_type]]].append(indicator_context)

            dbot_list = [value for key, value in context.items() if key.startswith("DBotScore")]
            for dbot in dbot_list:
                demisto.debug(f"DBotScore for brand {brand}: {json.dumps(dbot, indent=2)}")
                dbot_output.extend(dbot)

            table = tableToMarkdown(name="Found Indicators", t=tim_output)
            readable_command_results = CommandResults(readable_output=f"#### Result for Search Indicators\n{table}")

            verbose_command_results.append(readable_command_results)
        demisto.debug("------------End-IOC------------")

    for tim_score in tim_output:
        demisto.debug(f"TIM output: {tim_score}")
        demisto.debug("------------End-TIM------------")
    context_output["TIM"] = {"indicator": tim_output, "DBotScore": dbot_output}
    demisto.debug(json.dumps(context_output, indent=4))


def summarize_command_results(
    url_list: list[str],
    output_context: dict[str, list],
    verbose_command_results: list[CommandResults],
    indicator_type: str,
) -> CommandResults:
    """
    Summarizes the results from all the executed commands.

    Args:
        url_list (list[str]): List of URLs to summarize.
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
    # Write summary Message
    for url in url_list:
        summary = {"URL": url}
        summary["Result"] = result

        tim_brands = []
        command_brands = []

        if tim_context := output_context.get("TIM", {}).get("indicator", {}).get(url, []):
            tim_brands = [context.get("Brand") for context in tim_context]
            summary["TIM Brands"] = ", ".join(tim_brands) if tim_brands else "None"

        if command_context := output_context.get("Command", {}).get("indicator", {}).get(url, []):
            command_brands = [context.get("Brand") for context in command_context]
            summary["Enrichment Successful Brands"] = ", ".join(command_brands) if command_brands else "None"

        if tim_brands or command_brands:
            summary["Message"] = f"Found data on URL from {len(command_brands)} Enrichment Brands and {len(tim_brands)} from TIM."
        else:
            summary["Message"] = "Could not find data on URL."

        summaries.append(summary)

    demisto.debug(f"Summarized results from all executed commands: {summaries}.")

    return CommandResults(
        outputs=merge_context(output_context, url_list, indicator_type),
        readable_output=tableToMarkdown(name=f"URL Enrichment result for {', '.join(url_list)}", t=summaries),
    )


""" COMMAND FUNCTION """


def url_enrichment_script(
    data_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False, indicator_type="url"
):
    """
    Enriches URL data with information from various integrations
    """
    # Validate inputs
    if not data_list:
        raise ValueError("URL is required")

    is_valid_url(data_list)

    # Initialize context and human readable results
    context_output = {}
    verbose_command_results = []

    # 1. TIM search
    search_url_indicator(data_list, indicator_type, context_output, verbose_command_results, additional_fields)
    # 2. External enrichment
    for data in data_list:
        if external_enrichment or enrichment_brands:
            demisto.debug("Getting integration brands on tenant.")
            enabled_brands = list(
                {module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"}
            )
            demisto.debug(f"Enabled brands: {enabled_brands}")
            file_reputation_command = Command(
                name=indicator_type,
                brand=enabled_brands,
                args={indicator_type: data, "using-brand": ",".join(enrichment_brands if enrichment_brands else enabled_brands)},
                indicator_type=indicator_type,
            )
            execute_url_enrichment(
                file_reputation_command, context_output, verbose_command_results, additional_fields, indicator_type
            )

            if "WildFire-v2" in enabled_brands:
                wildfire_command = Command(
                    name="wildfire-get-verdict", brand="WildFire-v2", args={indicator_type: data}, indicator_type=indicator_type
                )
                execute_url_enrichment(
                    wildfire_command, context_output, verbose_command_results, additional_fields, indicator_type
                )
    demisto.debug("-----------------Before Merge Context Output-----------------")
    demisto.debug(json.dumps(context_output, indent=4))

    command_results = summarize_command_results(data_list, context_output, verbose_command_results, indicator_type)
    # Prepare human readable output
    if verbose:
        command_results = [command_results]
        command_results.extend(verbose_command_results)

    return command_results


""" MAIN FUNCTION """


def main():
    args = demisto.args()
    data_list = argToList(args.get("data"))
    indicator_type = args.get("indicator_type")
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = args.get("brands")
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(url_enrichment_script(data_list, external_enrichment, verbose, brands, additional_fields, indicator_type))
    except Exception as ex:
        return_error(f"Failed to execute URLEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
