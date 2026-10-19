import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Queries that match every indicator in the tenant. deleteIndicators acts on whatever
# the query matches, so letting one of these through would purge the whole store.
UNSCOPED_QUERIES = {"*", "*:*", "value:*", "value:(*)", "id:*", "id:(*)"}


def quote_term(value: str) -> str:
    """Turn a raw value into a single quoted query term.

    Values reach the query as literal text, never as query syntax. Without quoting,
    characters that are legal inside a URL (``,`` ``*`` ``?`` ``:`` ``&``) are parsed
    as operators -- a value that yields a standalone ``*`` term makes the query match
    every indicator.

    Args:
        value: The raw indicator value or ID.

    Returns:
        The value escaped and wrapped in double quotes.
    """
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def is_unscoped_query(query: str) -> bool:
    """Report whether a query would match every indicator.

    Args:
        query: The resolved query about to be passed to ``deleteIndicators``.

    Returns:
        True if the query is empty or matches the entire indicator store.
    """
    normalized = " ".join(str(query).split())
    if not normalized:
        return True
    return normalized.replace(" ", "").lower() in UNSCOPED_QUERIES


def build_search_query(
    indicator_query: Optional[str] = None,
    indicator_values: Optional[List[str]] = None,
    indicator_ids: Optional[List[str]] = None,
) -> str:
    """Build the ``deleteIndicators`` query from exactly one of the supported inputs.

    ``indicator_values`` and ``indicator_ids`` are caller data and are always quoted.
    ``indicator_query`` is a deliberate, caller-authored query and is passed through
    as-is.

    Args:
        indicator_query: A raw query, used verbatim.
        indicator_values: Indicator values to delete.
        indicator_ids: Indicator IDs to delete.

    Returns:
        The query string to hand to ``deleteIndicators``.

    Raises:
        ValueError: If not exactly one input was supplied.
    """
    provided = [bool(indicator_query), bool(indicator_values), bool(indicator_ids)]
    if sum(provided) != 1:
        raise ValueError(
            "Invalid input: Exactly ONE of the following arguments must be provided: "
            "'indicator_query', 'indicator_values', or 'indicator_ids'."
        )

    if indicator_query:
        return indicator_query
    if indicator_values:
        return f"value:({' '.join(quote_term(value) for value in indicator_values)})"
    return f"id:({' '.join(quote_term(indicator_id) for indicator_id in indicator_ids or [])})"


def main():
    try:
        args = demisto.args()
        search_query = build_search_query(
            indicator_query=args.get("indicator_query"),
            indicator_values=argToList(args.get("indicator_values")),
            indicator_ids=argToList(args.get("indicator_ids")),
        )

        # Last line of defence: never issue a delete that matches the whole tenant.
        if is_unscoped_query(search_query):
            raise ValueError(
                f"Refusing to run an unscoped delete. The resolved query {search_query!r} matches "
                f"every indicator. Narrow the input, or pass an explicit 'indicator_query' if a "
                f"bulk delete is genuinely intended."
            )

        demisto.debug(f"DeleteIndicators: running deleteIndicators with query {search_query!r}")
        res = execute_command(
            "deleteIndicators",
            {
                "query": search_query,
                "doNotWhitelist": not argToBoolean(args.get("exclude", False)),
                "reason": args.get("exclusion_reason", ""),
            },
        )
        if is_error(res):
            raise Exception(res)
        return_results(res)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute DeleteIndicators. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
