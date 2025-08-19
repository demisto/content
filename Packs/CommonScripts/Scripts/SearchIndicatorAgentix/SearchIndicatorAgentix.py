import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

KEYS_TO_EXCLUDE_FROM_QUERY = ["size"]


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
    escape_characters = ["\\", "\n", "\t", "\r", '"', "^", ":", " "]

    for char in escape_characters:
        if char == "\\":
            value = value.replace(char, "\\\\")
        elif char == "\n":
            value = value.replace(char, "\\n")
        elif char == "\t":
            value = value.replace(char, "\\t")
        elif char == "\r":
            value = value.replace(char, "\\r")
        elif char == '"':
            value = value.replace(char, '\\"')
        elif char == "^":
            value = value.replace(char, "\\^")
        elif char == ":":
            value = value.replace(char, "\\:")
        elif char == " ":
            value = value.replace(char, "\\ ")

    demisto.debug(f"After escaping special characters in value: {value}")

    return value


def build_query_for_values(args: dict) -> list:
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
    demisto.debug(f"Preparing query values field for args: {args}")
    values = args.get("value", [])

    if not values:
        return []

    try:
        values_as_list = json.loads(values)
    except (json.JSONDecodeError, TypeError) as e:
        demisto.debug(f"JSON decode failed for values {values}: {str(e)}.")

    if not values_as_list:
        return []
    # Split the list into chunks of 100 values each
    if len(values_as_list) > 100:
        chunked_lists = [values_as_list[i : i + 100] for i in range(0, len(values_as_list), 100)]
        chunk_queries = []
        for i, chunk in enumerate(chunked_lists):
            if len(chunk) > 1:
                chunk_query = " OR ".join(f'{"value"}:"{escape_special_characters(str(v).strip())}"' for v in chunk)
            else:
                chunk_query = f'{"value"}:"{escape_special_characters(str(chunk[0])).strip()}"'
            chunk_queries.append(f"({chunk_query})")
            demisto.debug(f"value chunk_queries[{i}] {chunk_queries}")
        return chunk_queries
    else:
        query = split_multiple_values_and_add_or_between("value", values_as_list)
        demisto.debug(f"value query {query}")
        return [query]


def build_query_excluding_values(args: dict) -> str:
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
        if key == "value":
            continue

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
    fields = build_query_excluding_values(args)
    values_fields = build_query_for_values(args)
    if not values_fields and not fields:
        return []
    if not values_fields:
        return [fields]
    for f in values_fields:
        if fields:
            q = f"{f} AND {fields}"
        else:
            q = f
        queries.append(q)
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
    demisto.debug(f"search_indicators list_of_queries: {list_of_queries}")
    indicators = []
    for i, single_query in enumerate(list_of_queries):
        demisto.debug(f"list_of_queries[{i}]: {single_query}")
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
        style_indicator["verdict"] = scoreToReputation(style_indicator["score"])
        filtered_indicators.append(style_indicator)

    headers = fields + ["verdict"]
    query = " OR".join(list_of_queries)
    demisto.debug(f"Final query string: {query}")
    markdown = tableToMarkdown(f"Indicators Found: {query=}", filtered_indicators, headers)
    demisto.debug(f"filtered_indicators: {filtered_indicators}")
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
