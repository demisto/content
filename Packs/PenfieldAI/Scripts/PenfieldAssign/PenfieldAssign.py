import demistomock as demisto
from CommonServerPython import *
# from CommonServerPython import return_results, return_error
from CommonServerUserPython import *
import traceback

''' COMMAND FUNCTION '''


def penfield_assign(analyst_ids, category, created, id, name, severity):
    return demisto.executeCommand("penfield-get-assignee", {
        'analyst_ids': analyst_ids,
        'category': category,
        'created': created,
        'id': id,
        'name': name,
        'severity': severity
    })


''' MAIN FUNCTION '''


def main():
    try:
        assign = demisto.args()['assign']

        # get online analyst ids
        analysts = demisto.executeCommand('getUsers', {'online': True})[0]['Contents']
        usernames = [a['username'] for a in analysts]
        analyst_ids = ''
        analyst_ids += ','.join(usernames)

        # get relevant incident information
        incident = demisto.incidents()[0]
        category = incident['category']
        created = incident['created']
        id = incident['id']
        name = incident['name']
        severity = incident['severity']

        # get assignee
        chosen_one = penfield_assign(
            analyst_ids,
            category,
            created,
            id,
            name,
            severity
        )[0]['Contents']

        # perform action & return response
        if assign == "Yes":
            demisto.executeCommand("setOwner", {'owner': chosen_one})
            return_results('incident assigned to: ' + chosen_one)
        else:
            return_results('penfield suggests: ' + chosen_one)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(ex)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
