import demistomock as demisto
from CommonServerPython import *

DEFAULT_SIZE = 50


def search_indicators(args):
    keys = [
        "id",
        "value",
        "CustomFields",
        "type",
        "score",
        "firstSeen",
        "lastSeen",
        "expiration",
        "expirationStatus",
        "sourceBrands",
        "sourceInstances",
    ]
    query = args.get("query", None)
    if not query:
        raise ValueError("Query not set!")
    size = int(args.get("size", DEFAULT_SIZE))

    indicators = demisto.executeCommand("findIndicators", {"query": query, "size": size})
    outputs = []
    if not isinstance(indicators, list) or len(indicators) < 1 or "Contents" not in indicators[0]:
        raise ValueError("No content")
    for i in indicators[0]["Contents"]:
        oi = {}
        for k in i:
            if k in keys:
                oi[k] = i[k]
        outputs.append(oi)
    return CommandResults(outputs_prefix="FoundIndicators", outputs_key_field="value", outputs=outputs)


def main(args):
    try:
        return_results(search_indicators(args))
    except Exception as e:
        return_error(f"Error : {e!s}")


if __name__ in ("builtins", "__builtin__"):
    main(demisto.args())
