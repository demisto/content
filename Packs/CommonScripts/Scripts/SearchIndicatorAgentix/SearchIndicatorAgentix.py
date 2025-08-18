import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

KEYS_TO_EXCLUDE_FROM_QUERY = ["size"]


def escape_special_characters(value):
    demisto.debug(f"Escaping special characters in value: {value}")

    # Characters that need escaping with backslash when in double quotes
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
    demisto.debug(f"Preparing query for args: {args}")
    for key, values in args.items():
        query = ""
        if key in KEYS_TO_EXCLUDE_FROM_QUERY:
            continue

        if not values:
            continue

        if key == "IssuesIDs":
            key = "investigationIDs"

        try:
            values_as_list = json.loads(values)
        except (json.JSONDecodeError, TypeError) as e:
            demisto.debug(f"JSON decode failed for values {values}: {str(e)}.\nTreating as string value.")
            values_as_list = [values]

        if len(values_as_list) > 1:
            query = " OR ".join(f'{key}:"{escape_special_characters(str(v).strip())}"' for v in values_as_list)
        else:
            query = f'{key}:"{escape_special_characters(str(values_as_list[0])).strip()}"'

        demisto.debug(f"inner query: {query}")
        query_sections.append(query)

    return " AND ".join(f"({qs})" for qs in query_sections) if query_sections else ""


def split_or_query(query: str, max_literals: int = 100) -> list[str]:
    """
    Split a Lucene query containing many OR'ed value:"..." literals into smaller queries.
    If the query has a leading (FIELD: ...) AND (...), where FIELD is one of the allowed
    fields, keep that FIELD clause intact and split only the OR-part.

    Supported shapes:
      1) (value:"a" OR value:"b" OR ...)
      2) (FIELD: x) AND (value:"a" OR value:"b" OR ...), where FIELD in allowed_fields

    Returns a list of valid sub-queries with ≤ max_literals value-literals each.
    """
    q = query.strip()

    # Allowed leading fields
    allowed_fields = ["type", "investigationIDs", "expirationStatus"]
    field_alts = "|".join(map(re.escape, allowed_fields))

    # Try to capture a (FIELD: ...) prefix if present
    m_field = re.match(rf"^\(\s*(?:{field_alts})\s*:[^)]+\)\s*AND\s*\((.*)\)\s*$", q, flags=re.IGNORECASE | re.DOTALL)
    if m_field:
        # Match the leading (FIELD: ...) exactly as written
        field_match = re.search(rf"^\(\s*(?:{field_alts})\s*:[^)]+\)", q, flags=re.IGNORECASE)
        if field_match:
            field_clause = field_match.group(0)
        else:
            demisto.debug(f"No leading field clause found in the query: {q!r}")
            field_clause = None

        value_part = m_field.group(1)
    else:
        # Strip outer parentheses if they wrap the whole query
        inner = re.match(r"^\((.*)\)$", q, flags=re.DOTALL)
        field_clause = None
        value_part = inner.group(1) if inner else q

    # Collect all value:"..." literals
    token_re = re.compile(r'(?:value\s*:\s*"(?:[^"\\]|\\.)*")', flags=re.IGNORECASE)
    tokens = token_re.findall(value_part)

    if not tokens:
        return [q]  # Nothing to split

    # Chunk into groups of ≤ max_literals and rebuild queries
    chunks = [tokens[i : i + max_literals] for i in range(0, len(tokens), max_literals)]
    out = []
    for chunk in chunks:
        joined = " OR ".join(chunk)
        out.append(f"{field_clause} AND ({joined})" if field_clause else f"({joined})")
    return out


def search_indicators(args):
    # search for indicators
    query = prepare_query(args)
    demisto.debug(f"search_indicators query: {query}")
    list_of_queries = split_or_query(query)
    for i, q in enumerate(list_of_queries):
        demisto.debug(f"list_of_queries[{i}]: {q}")
    indicators = []
    for single_query in list_of_queries:
        result = demisto.executeCommand("findIndicators", {"query": single_query, "size": args.get("size")})
        if result and result[0].get("Contents"):
            indicators.extend(result[0]["Contents"])
    # indicators = demisto.executeCommand("findIndicators", {"query": query, "size": args.get("size")})[0]["Contents"]
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
