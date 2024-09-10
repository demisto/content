import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

''' MAIN FUNCTION '''

DEFAULT_PAGE_SIZE = 50
DEFAULT_NOTE = 'Duplicate. Closed.'
DEFAULT_INCIDENT_TYPE = ['Vectra Account', 'Vectra Host']


def remove_space_from_args(args):
    """Remove space from args."""
    for key in args.keys():
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def main():
    try:
        args = remove_space_from_args(demisto.args())
        remove_nulls_from_dictionary(args)

        page_size: int = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))  # type: ignore
        note = args.get('note', DEFAULT_NOTE)
        incident_types = argToList(args.get('incident_types')) or DEFAULT_INCIDENT_TYPE
        incident_type_query = ' or '.join([f'type:"{incident_type}"' for incident_type in incident_types])
        close_in_vectra = argToBoolean(args.get('close_in_vectra', True))
        query = f'state:inactive and -category:job and status:active and ({incident_type_query}) and vectradetectioncount:=0'
        params = {
            'size': page_size,
            'query': query
        }
        incidents_response = demisto.executeCommand('getIncidents', args=params)
        incidents = incidents_response[0].get('Contents', {}).get('data', [])
        total_incidents = incidents_response[0].get('Contents', {}).get('total', 0)
        closed_incident_ids = []
        count = 0
        if incidents:
            count = len(incidents)
            for incident in incidents:
                incident_id = incident.get('id')
                closed_incident_ids.append(incident_id)
                account_id = incident.get('CustomFields', {}).get('accountid')
                host_id = incident.get('CustomFields', {}).get('deviceid')
                if close_in_vectra:
                    assignment_response = demisto.executeCommand(
                        'vectra-search-assignments', args={'host_ids': host_id, 'account_ids': account_id})
                    assignment_details = assignment_response[0].get('Contents', {}).get('results', [])

                    if assignment_details:
                        assignment_id = assignment_details[0].get('id')
                        command_args = {'assignment_id': assignment_id, 'outcome_id': 1, 'note': note}
                        demisto.executeCommand('vectra-assignment-resolve', args=command_args)

                demisto.executeCommand("closeInvestigation", args={
                    'id': incident_id, 'closeNotes': note, 'closeReason': 'Duplicate'})
            hr = "### Vectra Detect Closed Incidents\n Incident IDs: " + ", ".join(closed_incident_ids)
        else:
            hr = '### No duplicate incidents found.'

        has_more_incidents = total_incidents > count
        outputs = {'count': count, 'closed_incident_ids': closed_incident_ids, 'has_more_incidents': has_more_incidents}
        results = CommandResults(
            outputs_prefix='VectraDetectIncidents',
            outputs=outputs,
            readable_output=hr
        )
        return_results(results)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute VectraDetectCloseDuplicateIncidents. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
