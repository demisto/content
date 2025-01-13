import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback
import hashlib
import json

from dateutil import parser  # type: ignore[import]


def get_incident_labels_map(labels):
    if labels is None:
        return {}
    labels_map = {}

    for label in labels:
        label_type = label['type'].lower()
        labels_map[label_type] = label['value']
    return labels_map


def hash_object(str_list_dict):
    if str_list_dict == "" or str_list_dict is None:
        return str_list_dict
    if (type(str_list_dict)) is dict:
        return {k_v[0]: hash_object(k_v[1]) for k_v in iter(str_list_dict.items())}
    if (isinstance(str_list_dict, list)):
        return [hash_object(x) for x in str_list_dict]

    if (type(str_list_dict) in [str, str]):
        str_value = str_list_dict.encode('utf-8')
    else:
        str_value = str(str_list_dict)
    return hashlib.md5(str_value).hexdigest()  # guardrails-disable-line  # nosec


def get_indicator_data(indicator):
    return {k: v for k, v in list(indicator.items()) if
            k in ['indicator_type', 'firstSeen', 'lastSeen', 'investigationIDs', 'manualScore', 'id', 'score', 'value']}


def get_incident_data(incident):
    result = {k: v for k, v in list(incident.items()) if k in ['id', 'type', 'occurred', 'CustomFields', 'labels']}
    result['labels'] = hash_object(get_incident_labels_map(result.get('labels')))
    result['CustomFields'] = hash_object(result.get('CustomFields'))
    return result


def parse_datetime(datetime_str):
    try:
        return parser.parse(datetime_str).isoformat()
    except Exception:
        return datetime_str


def build_query_for_incidents_search(base_query, from_date):
    if from_date:
        return '{} created:>="{}"'.format(base_query, parse_datetime(from_date))
    else:
        return base_query


def indicator_malicious_ratio_calculation(args):
    appears_in_min_num_of_incidents = int(args.get('appearsInMinNumberOfIncidents'))
    max_incidents = int(args.get('maxIncidents'))
    max_indicators = int(args.get('maxIndicators'))
    base_query = args.get('query')
    max_results = int(args['maxDisplayResults'])
    generate_file_result = (args['fileResult'] == 'yes')
    from_date = args.get('fromDate', '')

    query = build_query_for_incidents_search(base_query, from_date)
    res = demisto.executeCommand("findIndicators", {'query': base_query, 'size': max_indicators})
    indicators = res[0]['Contents']
    indicators_result = list(map(get_indicator_data, indicators))
    res = demisto.executeCommand("SearchIncidentsV2", {'query': query.replace('incident.', ''), 'size': max_incidents})
    incidents = []
    if res[0].get("Contents") and res[0].get("Contents", [{}])[0].get("Contents"):
        incidents = res[0].get("Contents", [{}])[0].get("Contents", {}).get("data")

    if incidents:
        incidents_result = list(map(get_incident_data, incidents))
        resolved_incident_ids = {x['id'] for x in incidents_result}
        non_resolved_id = set()  # type: Any
        for i in indicators_result:
            resolved = [x for x in i['investigationIDs'] if x in resolved_incident_ids]
            non_resolved_id = non_resolved_id.union(set(i['investigationIDs']).difference(set(resolved)))
            resolved_count = len(resolved)
            total_count = len(i['investigationIDs'])
            i['resolved_incidents_count'] = resolved_count
            i['total_incidents_count'] = total_count
            i['malicious_ratio'] = float(resolved_count) / total_count

        non_resolved_incidents = []
        if non_resolved_id:
            res = demisto.executeCommand("SearchIncidentsV2", {'query': " or ".join(
                ["id:%s" % x for x in non_resolved_id]), 'size': max_incidents})
            if res[0].get("Contents") and res[0].get("Contents", [{}])[0].get("Contents"):
                non_resolved_incidents = res[0].get("Contents", [{}])[0].get("Contents", {}).get("data")
            if non_resolved_incidents:
                non_resolved_incidents = list(map(get_incident_data, non_resolved_incidents))
        else:
            non_resolved_incidents = []

        indicators_result = [x for x in indicators_result if
                             x['total_incidents_count'] >= appears_in_min_num_of_incidents]
        indicators_result.sort(key=lambda x: x['malicious_ratio'], reverse=True)

        results = CommandResults(
            outputs_prefix='IndicatorMaliciousRatioCalculation',
            outputs=indicators_result,
            readable_output=tableToMarkdown('Indicators Malicious Ratio', indicators_result[:max_results],
                                            headers=['value', 'indicator_type', 'malicious_ratio',
                                                     'total_incidents_count',
                                                     'score', 'lastSeen']))

        if generate_file_result:
            for i in indicators_result:
                i['value'] = hash_object(i['value'])

            results = fileResult('MaliciousRatio.json', json.dumps({
                'resolved_incidents': incidents_result,
                'non_resolved_incidents': non_resolved_incidents,
                'indicators': indicators_result
            }))
        return results
    else:
        return "No resolved incidents found"


''' MAIN FUNCTION '''


def main():
    try:
        return_results(indicator_malicious_ratio_calculation(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IndicatorMaliciousRatioCalculation. Error: {ex}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
