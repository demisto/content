import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Script for Cortex XSOAR (aka Demisto)
This is an empty script with some basic structure according
to the code conventions.
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

from typing import Any
import traceback


''' STANDALONE FUNCTION '''

''' COMMAND FUNCTION '''


def close_linked_signal_incidents_command(args: dict[str, Any]) -> CommandResults:
    if 'id' not in args:
        cur_incident = demisto.incident()
        # print(f"Get current incident {cur_incident}")
    else:
        incident_id = args['id']
        search_raw = demisto.executeCommand("getIncidents", {'query': f'id:{incident_id}'})
        if search_raw[0]['Contents']['total'] == 0:
            result = {'message': f"Incident ID {incident_id} not found"}
            cur_incident = None
        else:
            cur_incident = search_raw[0]['Contents']['data'][0]
            result = {}
            demisto.debug(f"{search_raw[0]['Contents']['total']=} != 0 -> {result=}")
    if cur_incident is not None and cur_incident['rawType'] != 'Sumo Logic Insight':
        result = {'message': 'Please run this on a valid Sumo Logic Insight incident only'}
    elif cur_incident is not None:
        result = {}
        demisto.debug(f"Initializing {result=}")
        linked_incidents = cur_incident.get('linkedIncidents')
        if (linked_incidents):
            # print('Current Linked Signal Incidents:', linked_incidents)
            for signal_incident_id in linked_incidents:
                # print('Closing the signal incident:', signal_incident_id)
                call_result = demisto.executeCommand("closeInvestigation", {"id": signal_incident_id, "closeNotes":
                                                     f"Close becaused Insight Incident {cur_incident.get('id')} is closed",
                                                                            "closeReason": "Resolved"})
                result = {'message': call_result[0]['Contents']}
        else:
            # print('There are no linked Signal Incidents')
            result = {'message': 'There are no linked incidents'}
    else:
        result = {}
        demisto.debug(f"cur_incident is None. {result=}")

    return CommandResults(
        outputs_prefix='BaseScript',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(close_linked_signal_incidents_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute SumoLogicCloseLinkSignalIncidents. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
