import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    query = args.get('query')
    size = int(args.get('size'))

    try:
        raw_result = demisto.executeCommand("SearchIncidentsV2", {"query": query,
                                                                  "size": size})
        incidents_len = len(raw_result[0].get("Contents", [{}])[0].get("Contents", {}).get("data"))
    except Exception:
        incidents_len = 0
    outputs = {
        'Query': query,
        'Size': incidents_len,
        'ConditionMet': incidents_len >= size
    }
    return_results(CommandResults(outputs=outputs, outputs_key_field='Query', outputs_prefix='IncidentsCheck'))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
