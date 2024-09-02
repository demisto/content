import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

TIME_FIELD = "created"
MAX_CANDIDATES_IN_LIST = 1000


def get_incidents_by_case(case_id, incident_id):

    # find incidents that are not closed and do not have the same incident id.
    query = f'cyrencaseid="{case_id}" and -cyrenincidentid="{incident_id}"'

    get_incidents_argument =\
        {'query': query,
         'size': MAX_CANDIDATES_IN_LIST,
         'sort': 'created.desc'
         }

    res = demisto.executeCommand("getIncidents", get_incidents_argument)
    if res[0]['Type'] == EntryType.ERROR:
        raise NameError(str(res[0]['Contents']))

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
    return {'id': "[{}](#/Details/{})".format(incident['id'], incident['id']),
            'raw_id': incident['id'],
            'cyren_incident_id': incident['CustomFields']['cyrenincidentid'],
            'name': incident['name'],
            'closed_time': parse_time(incident['closed'])
            if incident['closed'] != "0001-01-01T00:00:00Z" else "",
            'time': time}


def did_not_find_duplicates():
    context = {
        'isSimilarIncidentFound': False
    }
    demisto.results({'ContentsFormat': formats['markdown'],
                     'Type': EntryType.NOTE,
                     'Contents': 'No similar incidents have been found.',
                     'EntryContext': context})
    sys.exit(0)


def pretty_title(s):
    s = s.replace('_', ' ')
    return s.title()


def main():

    try:
        # case id from parameters
        case_id = demisto.args().get('case_id')
        incident_id = ""
        # case id from current incident context
        if not case_id:
            case_id = demisto.get(demisto.incidents()[0],
                                  'CustomFields.cyrencaseid')
        if not case_id:
            return did_not_find_duplicates()

        # don't include this incident id in list
        incident_id = demisto.get(demisto.incidents()[0],
                                  'CustomFields.cyrenincidentid')

        similar_incidents = get_incidents_by_case(case_id, incident_id)

        if len(similar_incidents or []) > 0:
            similar_incidents_rows =\
                [incident_to_record(x, TIME_FIELD) for x in similar_incidents]
            similar_incidents_rows =\
                sorted(
                    similar_incidents_rows,
                    key=lambda x: (x['time'], x['id'])
                )

            similar_incident_csv = ""
            for i in range(0, len(similar_incidents_rows)):
                similar_incident_csv = similar_incident_csv + ", " + similar_incidents_rows[i]["raw_id"]

            # truncate rows
            similar_incidents_rows =\
                similar_incidents_rows[:MAX_CANDIDATES_IN_LIST]
            context = {
                'cyrenSimilarIncidentList': similar_incidents_rows,
                'cyrenSimilarIncidentCsv': similar_incident_csv,
                'cyrenSimilarIncident': similar_incidents_rows[0],
                'cyrenIsSimilarIncidentFound': True
            }

            # build printed output
            markdown_result =\
                "**Number of Incidents:** " +\
                str(len(similar_incidents_rows)) +\
                "\n"
            markdown_result = markdown_result +\
                tableToMarkdown("", similar_incidents_rows,
                                ["time", "id", "cyren_incident_id", "name"], pretty_title)

            return {'ContentsFormat': formats['markdown'],
                    'Type': EntryType.NOTE,
                    'Contents': markdown_result,
                    'EntryContext': context}
        else:
            did_not_find_duplicates()

    except Exception as e:
        return_error(f'Failed to execute'
                     f' CyrenFindSimilarIncidents. Error: {str(e)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    entry = main()
    return_results(entry)
