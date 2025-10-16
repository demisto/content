import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

KEYS_TO_EXCLUDE_FROM_QUERY = ["size", "value"]
SCORE_TO_REPUTATION = {0: "Unknown", 1: "Benign", 2: "Suspicious", 3: "Malicious"}


def escape_special_characters(value):
    """
    Escapes special characters in a string value for use in search lucence queries.

    This function escapes characters that have special meaning in query syntax by adding
    appropriate backslash escape sequences. The escaped value can be safely used within
    double-quoted search terms.

    Args:
        value (str): The string value to escape special characters in.

    Returns:
        str: The input value with special characters properly escaped.
    """
    demisto.debug(f"Escaping special characters in value: {value}")

    # Dictionary mapping characters to their escape sequences for more maintainable code
    escape_map = {"\\": "\\\\", "\n": "\\n", "\t": "\\t", "\r": "\\r", '"': '\\"', "^": "\\^", ":": "\\:", " ": "\\ "}

    for char, escaped in escape_map.items():
        value = value.replace(char, escaped)

    demisto.debug(f"After escaping special characters in value: {value}")

    return value


def build_query_for_indicator_values(args: dict) -> list:
    """
    Builds a list of query strings for the 'value' field from the provided arguments.

    This function extracts the 'value' field from the arguments and creates search queries
    for those values. If there are more than 100 values, they are split into chunks of 100
    to optimize query performance. Each chunk generates a separate query string with OR
    operators between the values.

    Args:
        args (dict): Dictionary containing search parameters, expected to have a 'value' key
                    with either a JSON string or list of values to search for.

    Returns:
        list: A list of query strings. Each string contains escaped and quoted values
                joined with OR operators. Returns empty list if no values are provided.
                For large value sets, returns multiple query strings representing chunks.
    """
    values = args.get("value", [])

    if not values:
        return []

    try:
        values_as_list = json.loads(values)
    except (json.JSONDecodeError, TypeError) as e:
        raise DemistoException(f"JSON decode failed for values {values}: {str(e)}.")

    if not values_as_list:
        return []

    # Split the list into chunks of 100 values each
    chunked_lists = [values_as_list[i : i + 100] for i in range(0, len(values_as_list), 100)]
    chunk_queries = []

    for i, chunk in enumerate(chunked_lists):
        chunk_query = split_multiple_values_and_add_or_between("value", chunk)
        chunk_queries.append(f"({chunk_query})")
        demisto.debug(f"indicator values chunk_queries[{i}]: {chunk_query}")

    return chunk_queries


def build_query_excluding_indicator_values(args: dict) -> str:
    """
    Builds a query string from the provided arguments, excluding the 'value' field.

    This function processes all fields in the arguments dictionary except for 'value'
    and creates a search query string. It handles JSON deserialization of field values,
    applies field name transformations (e.g., 'IssuesIDs' to 'investigationIDs'),
    and combines multiple field queries with AND operators.

    Args:
        args (dict): Dictionary containing search parameters. The 'value' field is ignored,
                    and fields listed in KEYS_TO_EXCLUDE_FROM_QUERY are also excluded.
                    Values can be JSON strings or regular strings/lists.

    Returns:
        str: A query string with field conditions joined by AND operators. Each field
                condition is wrapped in parentheses. Returns empty string if no valid
                fields are found or all fields are excluded.
    """
    query_sections = []
    demisto.debug(f"Preparing query fields excluding values for args: {args}")

    for key, values in args.items():
        query = ""

        if key in KEYS_TO_EXCLUDE_FROM_QUERY:
            continue

        if not values:
            continue

        if key == "IssuesIDs":
            key = "investigationIDs"

        values_as_list = argToList(values)

        query = split_multiple_values_and_add_or_between(key, values_as_list)

        demisto.debug(f"excluding values inner query: {query}")
        query_sections.append(query)

    return " AND ".join(f"({qs})" for qs in query_sections) if query_sections else ""


def split_multiple_values_and_add_or_between(key, values_as_list):
    """
    This function constructs a search query for a specific field that can have one or more values.
    For multiple values, it creates an OR-separated query string. For single values, it creates
    a simple field:value query. All values are escaped to handle special characters and wrapped
    in quotes for exact matching.

    Args:
        key (str): The field name to search on (e.g., 'type', 'status', 'investigationIDs').
        values_as_list (list): List of values to search for. Can contain strings, numbers, or
                                other types that will be converted to strings.

    Returns:
        str: A query string in the format 'field:"value1" OR field:"value2" OR ...' for multiple
                values, or 'field:"value"' for a single value. All values are escaped and quoted.
    """
    if not values_as_list:
        return ""

    if len(values_as_list) > 1:
        query = " OR ".join(f'{key}:"{escape_special_characters(str(v).strip())}"' for v in values_as_list)

    else:
        query = f'{key}:"{escape_special_characters(str(values_as_list[0])).strip()}"'

    return query


def prepare_query(args: dict) -> list:
    """
    This function builds search queries by taking value-specific filters (like indicator values)
    and combining them with other field-based filters using AND logic. Each value filter
    creates a separate query to handle large number of indicator values.

    Args:
        args (dict): Dictionary containing search parameters and filters. Should include
                    both value-based filters and other field filters.

    Returns:
        list: List of query strings, where each query combines a value filter with
                common field filters using AND logic. If no field filters exist,
                returns just the value filters.
    """
    queries = []
    query_without_indicator_values = build_query_excluding_indicator_values(args)
    indicator_value_queries = build_query_for_indicator_values(args)

    if not indicator_value_queries and not query_without_indicator_values:
        return []

    if not indicator_value_queries:
        return [query_without_indicator_values]

    for query in indicator_value_queries:
        if query_without_indicator_values:
            full_query = f"{query} AND {query_without_indicator_values}"

        else:
            full_query = query

        queries.append(full_query)

    return queries


def search_indicators(args):
    """
    This function searches for indicators based on the provided arguments and returns formatted results.
    It executes multiple queries generated from the arguments, collects all matching indicators,
    and formats them with specific fields for display and output.

    Args:
        args (dict): Dictionary containing search parameters including query filters and size limit.
                    Used to generate search queries and limit result size.

    Returns:
        tuple: A tuple containing:
            - str: Markdown formatted table showing found indicators with their details
            - list: List of dictionaries containing filtered indicator data with standardized fields
                    including id, indicator_type, value, score, expirationStatus, investigationIDs,
                    lastSeen, and verdict
    """
    list_of_queries = prepare_query(args)
    demisto.debug(f"Generated {len(list_of_queries)} queries: {list_of_queries}")
    indicators = []

    for i, single_query in enumerate(list_of_queries):
        demisto.debug(f"Executing query {i+1}/{len(list_of_queries)}: {single_query}")
        result = demisto.executeCommand("findIndicators", {"query": single_query, "size": args.get("size")})
        if result and result[0].get("Contents"):
            indicators.extend(result[0]["Contents"])

    demisto.debug(f"indicators: {indicators}")
    # return specific information for found indicators
    filtered_indicators = []
    fields = ["id", "indicator_type", "value", "score", "expirationStatus", "investigationIDs", "lastSeen"]

    for indicator in indicators:
        style_indicator = {}

        for field in fields:
            style_indicator[field] = indicator.get(field, indicator.get("CustomFields", {}).get(field, "n/a"))

        style_indicator["verdict"] = SCORE_TO_REPUTATION.get(style_indicator["score"]) or "Unknown"
        filtered_indicators.append(style_indicator)

    headers = fields + ["verdict"]
    hr_query = " OR".join(list_of_queries)
    demisto.debug(f"hr query string: {hr_query}")
    markdown = tableToMarkdown(f"Indicators Found: {hr_query=}", filtered_indicators, headers)

    return markdown, filtered_indicators


def main():  # pragma: no cover
    args = demisto.args()
    demisto.debug(f"Args: {args}")

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
