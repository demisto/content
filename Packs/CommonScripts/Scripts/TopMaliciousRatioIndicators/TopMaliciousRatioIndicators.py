from typing import Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def select_indicator_columns(indicator: dict) -> Dict:
    display_indicator = {}
    display_indicator['ID'] = indicator['id']
    display_indicator['Type'] = indicator['indicator_type']
    display_indicator['Malicious Ratio'] = '%.2f' % float(indicator['maliciousRatio'])
    display_indicator['Value'] = indicator['value']
    display_indicator['Last Seen'] = indicator['lastSeen']
    return display_indicator


def dedup_by_value(indicators: list) -> List:
    exist_values = set()
    result = []
    for e in indicators:
        value = e['value']
        if value not in exist_values:
            exist_values.add(value)
            result.append(e)
    return result


def find_indicators_with_mal_ratio(
        max_indicators: int, min_number_of_invs: int, max_results: int, from_date: str) -> Tuple[str, list]:
    indicators = execute_command("findIndicators", {'query': f'lastSeen:>={from_date}', 'size': max_indicators})
    indicators = [i for i in indicators if len(i.get('investigationIDs') or []) >= min_number_of_invs]

    if not indicators:
        return json.dumps({"total": 0, "data": []}), []

    indicators_map = {i['id']: i for i in indicators}

    malicious_ratio_result = execute_command("maliciousRatio", {'id': ",".join(indicators_map)})

    for mr in malicious_ratio_result:
        indicators_map[mr['indicatorId']]['maliciousRatio'] = mr['maliciousRatio']
        indicators_map[mr['indicatorId']]['from_date'] = from_date

    sorted_indicators = sorted(indicators_map.values(), key=lambda x: x['maliciousRatio'], reverse=True)
    sorted_indicators = [x for x in sorted_indicators if x['maliciousRatio'] > 0]
    sorted_indicators = dedup_by_value(sorted_indicators)
    sorted_indicators = sorted_indicators[:max_results]
    sorted_indicators = list(map(select_indicator_columns, sorted_indicators))
    widget_table = json.dumps({"total": len(sorted_indicators), "data": sorted_indicators})

    return widget_table, sorted_indicators


def main():
    try:
        args: dict = demisto.args()
        max_indicators = int(args['maxNumberOfIndicators'])
        min_number_of_invs = int(args['minimumNumberOfInvs'])
        max_results = int(args['maximumNumberOfResults'])
        from_date = args.get('from', '"30 days ago"')

        widget_table, sorted_indicators = find_indicators_with_mal_ratio(max_indicators, min_number_of_invs,
                                                                         max_results, from_date)

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': widget_table,
            'ContentsFormat': formats['text'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Top Malicious Ratio Indicators', sorted_indicators)
        })

    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute TopMaliciousRatioIndicators. Error: {traceback.format_exc()}')


if __name__ in ('__builtin__', 'builtins', '__main__'):  # pragma: no cover
    main()
