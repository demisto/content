import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""ClearAndReEnrichIndicatorsBySource
Collects all indicators from a specific source, clears their source data, and re-enriches them.
"""

from CommonServerUserPython import *  # noqa

from typing import Any
import traceback


""" STANDALONE FUNCTIONS """


def get_indicators_by_source(source_name: str, limit: int = 1000) -> list[dict[str, Any]]:
    """
    Retrieve all indicators from a specific source.

    Args:
        source_name: The name of the source/instance to filter by
        limit: Maximum number of indicators to retrieve

    Returns:
        List of indicator dictionaries
    """
    demisto.debug(f"Searching for indicators from source: {source_name}")

    # Search for indicators with the specific source
    search_args = {"query": f'sourceInstances:"{source_name}"', "size": limit}

    res = demisto.executeCommand("searchIndicators", search_args)

    indicators: list[dict[str, Any]] = []
    if isinstance(res, dict) and (total_indicators := res.get("total", 0)) > 0:
        demisto.debug(f"Found {total_indicators} indicators from source {source_name}")
        indicators = res.get("iocs", [])

    return indicators


def extract_indicator_values(indicators: list[dict[str, Any]]) -> list[str]:
    """
    Extract indicator values from indicator objects.

    Args:
        indicators: List of indicator dictionaries

    Returns:
        List of indicator values
    """
    values = []
    for indicator in indicators:
        value = indicator.get("value")
        if value:
            values.append(value)

    demisto.debug(f"Extracted {len(values)} indicator values")
    return values


def clear_indicator_source_data(indicator_values: list[str], source_name: str) -> dict[str, Any]:
    """
    Clear source data for the specified indicators.

    Args:
        indicator_values: List of indicator values to clear
        source_name: Source name to clear from

    Returns:
        Command result
    """
    if not indicator_values:
        return {"success": True, "message": "No indicators to clear"}

    demisto.debug(f"Clearing source data for {len(indicator_values)} indicators from source {source_name}")

    # Join indicator values with comma
    indicators_str = ",".join(indicator_values)

    clear_args = {"indicatorsValues": indicators_str, "source": source_name}

    res = demisto.executeCommand("clearIndicatorSourceData", clear_args)

    if is_error(res):
        raise DemistoException(f"Failed to clear indicator source data: {get_error(res)}")

    return res[0].get("Contents", {})


def enrich_indicators(indicator_values: list[str]) -> dict[str, Any]:
    """
    Re-enrich the specified indicators.

    Args:
        indicator_values: List of indicator values to enrich

    Returns:
        Command result
    """
    if not indicator_values:
        return {"success": True, "message": "No indicators to enrich"}

    demisto.debug(f"Enriching {len(indicator_values)} indicators")

    # Join indicator values with comma
    indicators_str = ",".join(indicator_values)

    enrich_args = {"indicatorsValues": indicators_str}

    res = demisto.executeCommand("enrichIndicators", enrich_args)

    if is_error(res):
        raise DemistoException(f"Failed to enrich indicators: {get_error(res)}")

    return res[0].get("Contents", {})


""" COMMAND FUNCTION """


def clear_and_re_enrich_indicators_by_source_command(args: dict[str, Any]) -> CommandResults:
    """
    Main command function that orchestrates the process.

    Args:
        args: Command arguments

    Returns:
        CommandResults object
    """
    source_name = args.get("source", "")
    if not source_name:
        raise ValueError("source parameter is required")

    limit = arg_to_number(args.get("limit", 1000))
    if not limit or limit <= 0:
        limit = 1000

    # Step 1: Get indicators by source
    demisto.info(f"Starting process for source: {source_name}")
    indicators = get_indicators_by_source(source_name, limit)

    if not indicators:
        return CommandResults(readable_output=f"No indicators found for source: {source_name}")

    # Step 2: Extract indicator values
    indicator_values = extract_indicator_values(indicators)

    if not indicator_values:
        return CommandResults(readable_output=f"No valid indicator values found for source: {source_name}")

    # Step 3: Clear source data
    demisto.info(f"Clearing source data for {len(indicator_values)} indicators")
    clear_result = clear_indicator_source_data(indicator_values, source_name)

    # Step 4: Re-enrich indicators
    demisto.info(f"Re-enriching {len(indicator_values)} indicators")
    enrich_result = enrich_indicators(indicator_values)

    # Prepare output
    readable_output = f"""## Clear and Re-Enrich Indicators by Source Results

**Source:** {source_name}
**Total Indicators Processed:** {len(indicator_values)}

### Steps Completed:
1. ✅ Found {len(indicators)} indicators from source "{source_name}"
2. ✅ Extracted {len(indicator_values)} indicator values
3. ✅ Cleared source data for all indicators
4. ✅ Initiated re-enrichment for all indicators

### Indicator Values Processed:
{chr(10).join([f"- {value}" for value in indicator_values[:10]])}
{"..." if len(indicator_values) > 10 else ""}
"""

    outputs = {
        "ClearAndReEnrichIndicatorsBySource": {
            "Source": source_name,
            "ProcessedCount": len(indicator_values),
            "IndicatorValues": indicator_values,
            "ClearResult": clear_result,
            "EnrichResult": enrich_result,
        }
    }

    return CommandResults(readable_output=readable_output, outputs=outputs)


""" MAIN FUNCTION """


def main():
    try:
        return_results(clear_and_re_enrich_indicators_by_source_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute ClearAndReEnrichIndicatorsBySource. Error: {ex}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
