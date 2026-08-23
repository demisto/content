import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def escape_backslashes_in_field_filters(search: str) -> str:
    """Re-escapes backslashes inside the value of `field="value"` filters in an SPL search.

    The drilldown enrichment data is persisted on the incident as a JSON string. When this script
    reads it back with ``json.loads``, backslashes inside a double-quoted field filter value are
    collapsed to a single backslash, which is not valid SPL. We re-escape (double) them so the
    query shown to the user can be copied straight into the Splunk UI.

    Only genuine ``field="value"`` filters are touched - the quoted value must be directly preceded
    by a field-name token and ``=``. Regex/string literals that follow ``(`` or ``,`` inside SPL
    functions (e.g. ``eval x=replace(field,"(\\)","\\\\")``) and free-text / ``rex`` quoted strings
    are left untouched. The operation is idempotent.

    Args:
        search (str): The SPL drilldown search.

    Returns:
        str: The SPL search with backslashes escaped inside field filter values.
    """
    if not isinstance(search, str):
        return search

    def _escape(match: re.Match) -> str:
        prefix = match.group(1)  # the field name, '=' and any surrounding whitespace
        value = match.group(2)  # the value between the double quotes
        normalized = value.replace("\\\\", "\\")  # normalize already-doubled backslashes
        escaped = normalized.replace("\\", "\\\\")  # then double every backslash (idempotent)
        return f'{prefix}"{escaped}"'

    return re.sub(r'([\w.]+\s*=\s*)"([^"]*)"', _escape, search)


QUERY_KEYS = {"search", "query_search"}


def escape_drilldown_data(data):
    """Recursively re-escape backslashes in SPL query fields of parsed drilldown data.

    Applies escape_backslashes_in_field_filters to the values of the 'search' and 'query_search'
    keys so any displayed query is valid for the Splunk UI, regardless of nesting (list/dict).
    """
    if isinstance(data, list):
        return [escape_drilldown_data(item) for item in data]
    if isinstance(data, dict):
        return {
            key: escape_backslashes_in_field_filters(value)
            if key in QUERY_KEYS and isinstance(value, str)
            else escape_drilldown_data(value)
            for key, value in data.items()
        }
    return data


def format_drilldown_config(parsed_json) -> str:
    """Render parsed drilldown configuration as Markdown, showing each SPL query in a fenced code block.

    A fenced code block is used (instead of a Markdown table cell) because tableToMarkdown escapes
    backticks and Markdown collapses backslashes in plain cells, which would corrupt the displayed
    query. Inside a fenced code block the query - including its escaped backslashes - is shown
    verbatim, so the user can copy a Splunk-valid query. Assumes values were re-escaped by
    escape_drilldown_data.
    """
    items = parsed_json if isinstance(parsed_json, list) else [parsed_json]
    sections = []
    for item in items:
        if not isinstance(item, dict):
            sections.append(f"```\n{item}\n```")
            continue
        lines = []
        name = item.get("name") or item.get("query_name")
        if name:
            lines.append(f"**Name:** {name}\n")
        for key in QUERY_KEYS:
            if isinstance(item.get(key), str):
                lines.append(f"**Search:**\n```\n{item[key]}\n```\n")
        # Show any remaining metadata fields (e.g. earliest_offset, disabled) for context.
        for key, value in item.items():
            if key in QUERY_KEYS or key in ("name", "query_name"):
                continue
            lines.append(f"**{key}:** {value}\n")
        sections.append("".join(lines))
    return "\n".join(sections)


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
    drilldown_searches = custom_fields.get("splunkdrilldown", "")

    # If drilldown_searches not found in custom fields, search in labels
    if not drilldown_searches:
        for label in labels:
            if label.get("type") == "drilldown_searches":
                drilldown_searches = label.get("value", "")
                break

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
                # json.loads collapses doubled backslashes in field filter values; re-escape them so the
                # displayed query is valid for the Splunk UI (XSUP-70829).
                drilldown_results = escape_drilldown_data(json.loads(label.get("value", [])))
            except Exception as e:
                return display_json_parsing_error(
                    "Drilldown Searches (Invalid JSON)", f"JSON Parsing Error: {str(e)}", label.get("value", "")
                )

    if not drilldown_results:
        # No enrichment results found in labels

        # Case 1: No enrichment status label AND no configuration data -> enrichment is not configured.
        if not has_enrichment_status and not drilldown_searches:
            markdown = "#### Drilldown Configuration Status\n\n"
            markdown += (
                "⚠️ **Drilldown enrichment is not configured for this integration instance.**\n\n"
                "Enrichment is not enabled, so drilldown results are not available.\n\n"
                "**To enable drilldown enrichment:**\n"
                "1. Go to the integration instance settings\n"
                "2. In the 'Enrichment Types' parameter, select 'Drilldown'\n"
                "3. Save the configuration and fetch new incidents\n\n"
            )
            return {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": markdown}

        # Case 1b: A drilldown configuration exists but produced no results - it is configured, but the
        # search likely failed or returned nothing on the Splunk side (e.g. an invalid query).
        if not has_enrichment_status:
            markdown = "#### Drilldown Configuration Status\n\n"
            markdown += (
                "⚠️ **The drilldown is configured, but no results were returned.**\n\n"
                "The drilldown search was not run successfully on the Splunk side, or it returned no "
                "results. Review the search query below for errors (for example, unbalanced quotes or "
                "invalid syntax) and validate it directly in the Splunk UI.\n\n"
            )

            # Show the configuration so the user can review/fix the query.
            try:
                parsed_json = escape_drilldown_data(json.loads(drilldown_searches))
                markdown += "**Raw Drilldown Searches Configuration (from Splunk):**\n\n"
                markdown += format_drilldown_config(parsed_json)
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
                    parsed_json = escape_drilldown_data(json.loads(drilldown_searches))
                    markdown += "**Drilldown Searches Configuration:**\n\n"
                    markdown += format_drilldown_config(parsed_json)
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
                # Render the query inside a fenced code block so markdown does not collapse the
                # escaped backslashes - the user can copy a Splunk-valid query directly (XSUP-70829).
                markdown += (
                    f"**Query Name:** {drilldown.get('query_name','')}\n\n"
                    f"**Query Search:**\n```\n{drilldown.get('query_search','')}\n```\n\n"
                    f"**Results:**\n"
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
