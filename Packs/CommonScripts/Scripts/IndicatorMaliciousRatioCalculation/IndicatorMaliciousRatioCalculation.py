import hashlib
import json

from dateutil import parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

APPEARS_IN_MIN_NUMBER_OF_INCIDENTS = int(demisto.args()['appearsInMinNumberOfIncidents'])
MAX_INCIDENTS = int(demisto.args()['maxIncidents'])
MAX_INDICATORS = int(demisto.args()['maxIndicators'])
QUERY = demisto.args()['query']
MAX_RESULTS = int(demisto.args()['maxDisplayResults'])
GENERATE_FILE_RESULT = (demisto.args()['fileResult'] == 'yes')
FROM_DATE = demisto.args().get('fromDate', '')


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
    if (type(str_list_dict)) == dict:
        return dict(map(lambda (k, v): (k, hash_object(v)), str_list_dict.iteritems()))
    if (type(str_list_dict) == list):
        return map(lambda x: hash_object(x), str_list_dict)

    if (type(str_list_dict) in [str, unicode]):
        str_value = str_list_dict.encode('utf-8')
    else:
        str_value = str(str_list_dict)
    return hashlib.md5(str_value).hexdigest()


def get_indicator_data(indicator):
    return {k: v for k, v in indicator.items() if
            k in ['indicator_type', 'firstSeen', 'lastSeen', 'investigationIDs', 'manualScore', 'id', 'score', 'value']}


def get_incident_data(incident):
    result = {k: v for k, v in incident.items() if k in ['id', 'type', 'occurred', 'CustomFields', 'labels']}
    result['labels'] = hash_object(get_incident_labels_map(result.get('labels')))
    result['CustomFields'] = hash_object(result.get('CustomFields'))
    return result


def parse_datetime(datetime_str):
    try:
        return parser.parse(datetime_str).isoformat()
    except Exception:
        return datetime_str


def build_query():
    if FROM_DATE:
        return '%s created:>="%s"' % (QUERY, parse_datetime(FROM_DATE))
    else:
        return QUERY


query = build_query()
res = demisto.executeCommand("findIndicators", {'query': query, 'size': MAX_INDICATORS})
indicators = res[0]['Contents']
indicators_result = map(get_indicator_data, indicators)
res = demisto.executeCommand("SearchIncidentsV2", {'query': query.replace('incident.', ''), 'size': MAX_INCIDENTS})
incidents = []
if res[0].get("Contents") and res[0].get("Contents", [{}])[0].get("Contents"):
    incidents = res[0].get("Contents", [{}])[0].get("Contents", {}).get("data")

if incidents:
    incidents_result = map(get_incident_data, incidents)
    resolved_incident_ids = set(map(lambda x: x['id'], incidents_result))
    non_resolved_id = set()
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
            map(lambda x: "id:%s" % x, non_resolved_id)), 'size': MAX_INCIDENTS})
        if res[0].get("Contents") and res[0].get("Contents", [{}])[0].get("Contents"):
            non_resolved_incidents = res[0].get("Contents", [{}])[0].get("Contents", {}).get("data")
        if non_resolved_incidents:
            non_resolved_incidents = map(get_incident_data, non_resolved_incidents)
    else:
        non_resolved_incidents = []

    indicators_result = [x for x in indicators_result if
                         x['total_incidents_count'] >= APPEARS_IN_MIN_NUMBER_OF_INCIDENTS]
    indicators_result.sort(key=lambda x: x['malicious_ratio'], reverse=True)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': indicators_result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Indicators Malicious Ratio', indicators_result[:MAX_RESULTS],
                                         headers=['value', 'indicator_type', 'malicious_ratio', 'total_incidents_count',
                                                  'score', 'lastSeen'])
    })

    if GENERATE_FILE_RESULT:
        for i in indicators_result:
            i['value'] = hash_object(i['value'])

        demisto.results(fileResult('MaliciousRatio.json', json.dumps({
            'resolved_incidents': incidents_result,
            'non_resolved_incidents': non_resolved_incidents,
            'indicators': indicators_result
        })))
else:
    demisto.results("No resolved incidents found")
