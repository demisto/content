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
        value: The raw indicator value.

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


def build_search_query(indicator_values: Any) -> str:
    """Build the ``deleteIndicators`` query from the supplied indicator values.

    Args:
        indicator_values: A comma-separated string, or a list, of indicator values.

    Returns:
        The query string to hand to ``deleteIndicators``.

    Raises:
        ValueError: If no usable indicator value was supplied.
    """
    values = [value.strip() for value in argToList(indicator_values) if str(value).strip()]
    if not values:
        raise ValueError("No indicator values were supplied, so there is nothing to delete.")

    return f"value:({' '.join(quote_term(value) for value in values)})"


def main():
    try:
        args = demisto.args()
        search_query = build_search_query(args.get("indicatorValues"))

        # Last line of defence: never issue a delete that matches the whole tenant.
        if is_unscoped_query(search_query):
            raise ValueError(f"Refusing to run an unscoped delete. The resolved query {search_query!r} matches every indicator.")

        demisto.debug(f"DeleteAndExcludeIndicators: running deleteIndicators with query {search_query!r}")
        res = demisto.executeCommand(
            "deleteIndicators",
            {"query": search_query, "doNotWhitelist": "false", "reason": args.get("reason", "")},
        )
        resp = res[0]
        if isError(resp):
            raise Exception(resp["Contents"])
        demisto.results(resp["Contents"])

    except Exception as ex1:
        return_error(str(ex1))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
