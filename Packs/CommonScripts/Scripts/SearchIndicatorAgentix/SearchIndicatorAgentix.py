import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

KEYS_TO_EXCLUDE_FROM_QUERY = ["size"]


def prepare_query(args: dict) -> str:
    """
    Prepares a query for list-based searches with safe handling

    Args:
        key (str): Field/attribute to search
        value (str/list): Value or list of values to match

    Returns:
        str: Formatted query string
    """
    query_sections = []
    for key, values in args.items():
        query = ""
        if key in KEYS_TO_EXCLUDE_FROM_QUERY:
            continue

        if not values:
            continue

        if key == "IssuesIDs":
            key = "investigationIDs"

        values_as_list = argToList(values)
        if len(values_as_list) > 1:
            query = " OR ".join(f'{key}:"{str(v).strip()}"' for v in values_as_list)
        else:
            query = f'{key}:"{str(values_as_list[0]).strip()}"'

        query_sections.append(query)

    return " AND ".join(f"({qs})" for qs in query_sections) if query_sections else ""


def search_indicators(args):
    # search for indicators
    query = prepare_query(args)
    indicators = demisto.executeCommand("findIndicators", {"query": query, "size": args.get("size")})[0]["Contents"]

    # return specific information for found indicators
    filtered_indicators = []
    fields = ["id", "indicator_type", "value", "score", "expirationStatus", "investigationIDs", "lastSeen"]
    for indicator in indicators:
        style_indicator = {}
        for field in fields:
            style_indicator[field] = indicator.get(field, indicator.get("CustomFields", {}).get(field, "n/a"))
        style_indicator["verdict"] = scoreToReputation(style_indicator["score"])
        filtered_indicators.append(style_indicator)

    headers = fields + ["verdict"]
    markdown = tableToMarkdown(f"Indicators Found: {query=}", filtered_indicators, headers)
    return markdown, filtered_indicators


def main():
    args = demisto.args()
    try:
        readable_output, outputs = search_indicators(args)
        results = CommandResults(
            outputs_prefix="foundIndicators",
            outputs_key_field="id",
            readable_output=readable_output,
            outputs=outputs,
            ignore_auto_extract=True,
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
