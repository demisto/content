import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# type: ignore

import collections
from dateutil import parser

TIME_FIELD = "created"
MAX_CANDIDATES_IN_LIST = 100


def get_incidents_by_case(case_id, incident_id):

    # find incidents that are not closed and do not have the same incident id.
    query = 'cyrencaseid="%s" and -status:Closed and -cyrenincidentid="%s"' % (case_id, incident_id)
    # raise NameError(query)

    # demisto.log("Find similar incidents based on initial query: %s" % query)

    get_incidents_argument = {'query': query, 'size': 100, 'sort': 'created.desc'}
    # raise NameError(get_incidents_argument)

    res = demisto.executeCommand("getIncidents", get_incidents_argument)
    if res[0]['Type'] == entryTypes['error']:
        return_error(str(res[0]['Contents']))

    incident_list = res[0]['Contents']['data'] or []
    return incident_list


def incident_to_record(incident, time_field):
    def parse_time(date_time_str):
        try:

            if date_time_str.find('.') > 0:
                date_time_str = date_time_str[:date_time_str.find('.')]
            if date_time_str.find('+') > 0:
                date_time_str = date_time_str[:date_time_str.find('+')]
            return date_time_str.replace('T', ' ')
        except Exception:
            return date_time_str

    time = parse_time(incident[time_field])
    # raise NameError(incident['CustomFields']['cyrenincidentid'])
    return {'id': "[%s](#/Details/%s)" % (incident['id'], incident['id']),
            'raw_id': incident['id'],
            'cyren_incident_id': incident['CustomFields']['cyrenincidentid'],
            'name': incident['name'],
            'closed_time': parse_time(incident['closed']) if incident['closed'] != "0001-01-01T00:00:00Z" else "",
            'time': time}


def did_not_find_duplicates():
    context = {
        'isSimilarIncidentFound': False
    }
    demisto.results({'ContentsFormat': formats['markdown'],
                     'Type': entryTypes['note'],
                     'Contents': 'No similar incidents have been found.',
                     'EntryContext': context})
    sys.exit(0)


def main():

    # case id from parameters
    case_id = demisto.args().get('case_id')
    incident_id = ""
    # case id from current incident context
    if not (case_id):
        case_id = demisto.get(demisto.incidents()[0], 'CustomFields.cyrencaseid')
    if not (case_id):
        return did_not_find_duplicates()

    # don't include this incident id in list
    incident_id = demisto.get(demisto.incidents()[0], 'CustomFields.cyrenincidentid')

    # raise NameError(case_id)
    similar_incidents = get_incidents_by_case(case_id, incident_id)

    if len(similar_incidents or []) > 0:
        similar_incidents_rows = map(lambda x: incident_to_record(x, TIME_FIELD), similar_incidents)

        similar_incidents_rows = list(sorted(similar_incidents_rows, key=lambda x: (x['time'], x['id'])))
        # Create another array arr2 with size of arr1
        similar_incidents_raw_ids = [None] * len(similar_incidents_rows)

        # raise NameError(similar_incidents_rows)
        # Copying all elements of one array into another
        for i in range(0, len(similar_incidents_rows)):
            similar_incidents_raw_ids[i] = similar_incidents_rows[i]["raw_id"]

        context = {
            'cyrenSimilarIncidentList': similar_incidents_rows[:MAX_CANDIDATES_IN_LIST],
            'cyrenSimilarIncidentCsv': ",".join(similar_incidents_raw_ids),
            'cyrenSimilarIncident': similar_incidents_rows[0],
            'cyrenIsSimilarIncidentFound': True
        }

        similar_incidents_rows = similar_incidents_rows[:MAX_CANDIDATES_IN_LIST]
        hr_result = map(lambda row: dict(((k).replace("_", " ").upper(), v) for k, v in row.items()), similar_incidents_rows)
        # raise NameError(hr_result)
        markdown_result = tableToMarkdown("Similar incidents in Cyren case: %s" % (case_id),
                                          hr_result,
                                          headers=['ID', 'CYREN INCIDENT ID', 'TIME'])

        markdown_result = ""
        for x in hr_result:

            markdown_result += '**' + x["ID"] + '** &nbsp;&nbsp;' + x["CYREN INCIDENT ID"] + '\n'

        return {'ContentsFormat': formats['markdown'],
                'Type': entryTypes['note'],
                'Contents': markdown_result,
                'EntryContext': context}
    else:
        did_not_find_duplicates()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    entry = main()
    demisto.results(entry)
