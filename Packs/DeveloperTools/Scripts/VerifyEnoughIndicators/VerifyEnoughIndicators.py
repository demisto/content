import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    query = args.get('query')
    size = int(args.get('size'))
    query_result = demisto.searchIndicators(query=query, size=1, page=0)
    total = query_result.get('total', 0)
    outputs = {
        'Query': query,
        'Size': total,
        'ConditionMet': total >= size
    }
    return_results(CommandResults(outputs=outputs, outputs_key_field='Query', outputs_prefix='IndicatorsCheck'))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
