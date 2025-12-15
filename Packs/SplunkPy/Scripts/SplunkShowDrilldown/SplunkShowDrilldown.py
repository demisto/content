import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def format_raw_data(data: str) -> str:
    """Format raw JSON-like string for better readability."""
    if isinstance(data, str):
        return data.replace("},{", "},\n{").replace("[{", "[\n{").replace("}]", "}\n]")
    return str(data)


def display_error_with_raw_data(title: str, error_msg: str, raw_data: str) -> dict:
    """Display error message with formatted raw data."""
    markdown = f"#### {title}\n\n"
    markdown += f"**Error:** {error_msg}\n\n"

    if raw_data:
        markdown += "**Raw Drilldown Searches Data:**\n```\n"
        markdown += format_raw_data(raw_data) + "\n```"
    else:
        markdown += "*No drilldown searches data found.*"

    return {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": markdown}


def display_json_parsing_error(title: str, error_msg: str, raw_data: str) -> dict:
    """Display detailed error message for JSON parsing issues from Splunk."""
    markdown = f"#### {title}\n\n"
    markdown += "⚠️ **Note:** The drilldown_searches data received from Splunk contains invalid JSON formatting.\n\n"
    markdown += "The data from Splunk has JSON syntax issues (such as unescaped quotes or malformed structure).\n\n"
    markdown += f"**Error Details:** {error_msg}\n\n"

    if raw_data:
        markdown += "**Raw Data from Splunk:**\n```\n"
        markdown += format_raw_data(raw_data) + "\n```\n\n"
        markdown += "**Recommendation:** Check the drilldown configuration in Splunk to ensure it generates valid JSON."
    else:
        markdown += "*No drilldown searches data found.*"

    return {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": markdown}


def main():
    drilldown_results = []
    incident = demisto.incident()
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident from context but returned None")

    labels = incident.get("labels", [])
    custom_fields = incident.get("CustomFields", {})
    drilldown_searches = custom_fields.get("splunkdrilldown", "") or custom_fields.get("notabledrilldown", "")

    # Check if enrichment is configured
    has_enrichment_status = False
    for label in labels:
        if label.get("type") == "successful_drilldown_enrichment":
            has_enrichment_status = True
            is_successful = label.get("value")
            if is_successful == "false":
                return display_error_with_raw_data(
                    "Drilldown Enrichment Not Successful",
                    (
                        "The drilldown enrichment did not complete successfully. "
                        "This could be due to query parsing issues, no results found, or other errors."
                    ),
                    drilldown_searches,
                )
        if label.get("type") == "Drilldown":
            try:
                drilldown_results = json.loads(label.get("value", []))
            except Exception as e:
                return display_json_parsing_error(
                    "Drilldown Searches (Invalid JSON)", f"JSON Parsing Error: {str(e)}", label.get("value", "")
                )

    if not drilldown_results:
        # No enrichment results found in labels

        # Case 1: Enrichment is NOT configured at all
        if not has_enrichment_status:
            markdown = "#### Drilldown Configuration Status\n\n"
            markdown += (
                "⚠️ **Drilldown enrichment is not configured for this integration instance.**\n\n"
                "Enrichment is not enabled, so drilldown results are not available.\n\n"
                "**To enable drilldown enrichment:**\n"
                "1. Go to the integration instance settings\n"
                "2. In the 'Enrichment Types' parameter, select 'Drilldown'\n"
                "3. Save the configuration and fetch new incidents\n\n"
            )

            # Try to show raw configuration if available
            if drilldown_searches:
                try:
                    parsed_json = json.loads(drilldown_searches)
                    markdown += "**Raw Drilldown Searches Configuration (from Splunk):**\n\n"
                    markdown += f"{tableToMarkdown('Drilldown Searches Configuration', parsed_json)}"
                except Exception as e:
                    # Failed to parse raw configuration
                    markdown += "**Raw Drilldown Searches Data (Failed to Parse):**\n\n"
                    markdown += f"⚠️ Failed to parse the raw drilldown configuration. Error: {str(e)}\n\n"
                    markdown += "**Raw Data:**\n```\n"
                    markdown += format_raw_data(drilldown_searches) + "\n```"

            return {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": markdown}

        # Case 2: Enrichment IS configured but no results found
        else:
            markdown = "#### Drilldown Enrichment Results\n\n"
            markdown += (
                "⚠️ **Drilldown enrichment results not found.**\n\n"
                "Enrichment is configured, but the results could not be retrieved from the incident context.\n\n"
            )

            # Try to show raw configuration if available
            if drilldown_searches:
                try:
                    parsed_json = json.loads(drilldown_searches)
                    markdown += "**Drilldown Searches Configuration:**\n\n"
                    markdown += f"{tableToMarkdown('Drilldown Searches Configuration', parsed_json)}"
                except Exception as e:
                    # Failed to parse raw configuration
                    markdown += "**Raw Drilldown Searches Data (Failed to Parse):**\n\n"
                    markdown += f"⚠️ Failed to parse the drilldown configuration. Error: {str(e)}\n\n"
                    markdown += "**Raw Data:**\n```\n"
                    markdown += format_raw_data(drilldown_searches) + "\n```"
            else:
                markdown += "*No drilldown searches configuration data found.*"

            return {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": markdown}

    if isinstance(drilldown_results, list):
        if "query_name" in drilldown_results[0]:
            # Get drilldown results of multiple drilldown searches
            markdown = "#### Drilldown Searches Results\n"

            for drilldown in drilldown_results:
                markdown += (
                    f"**Query Name:** {drilldown.get('query_name','')}\n\n **Query"
                    f"Search:**\n{drilldown.get('query_search','')}\n\n **Results:**\n"
                )

                if drilldown.get("enrichment_status") == "Enrichment failed":
                    markdown += "\nDrilldown enrichment failed."

                elif results := drilldown.get("query_results", []):
                    markdown += tableToMarkdown("", results, headers=results[0].keys())

                else:
                    markdown += "\nNo results found for drilldown search."

                markdown += "\n\n"

        else:
            # Drilldown results of a single drilldown search
            markdown = tableToMarkdown("", drilldown_results, headers=drilldown_results[0].keys())

    else:
        markdown = tableToMarkdown("", drilldown_results)

    return {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": markdown}


if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        return_results(main())
    except Exception as e:
        return_error(f"Got an error while parsing Splunk events: {e}")
