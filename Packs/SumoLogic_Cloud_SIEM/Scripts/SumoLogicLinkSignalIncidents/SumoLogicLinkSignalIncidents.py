import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any


''' STANDALONE FUNCTION '''


def find_field_from_labels(labels: list, type_name: str) -> Any:
    for entry in labels:
        if entry['type'] == type_name:
            return entry['value']
    return None


''' COMMAND FUNCTION '''


def link_incidents_command(args: dict[str, Any]) -> CommandResults:
    """Find and link the Signal incidents to the current Insight incident.

    :param args
    :return: Result of link action
    :rtype: CommandResults
    """
    result: dict = {}
    demisto.debug(f"Initializing {result=}")

    if 'id' not in demisto.args():
        cur_incident = demisto.incident()
    else:
        incident_id = demisto.args()['id']
        search_raw = demisto.executeCommand("getIncidents", {'query': f'id:{incident_id}'})
        if search_raw[0]['Contents']['total'] == 0:
            result = {'message': f"Incident ID {incident_id} not found"}
            cur_incident = None
        else:
            cur_incident = search_raw[0]['Contents']['data'][0]
    if cur_incident is not None and cur_incident['rawType'] != 'Sumo Logic Insight':
        result = {'message': 'Please run this on a valid Sumo Logic Insight incident only'}
    elif cur_incident is not None:

        linked_signal_ids = []
        signal_sumoids = []

        signals_str = find_field_from_labels(cur_incident.get('labels'), 'signals')
        if (signals_str is not None):
            signals = safe_load_json(signals_str)
            for signal_obj in signals:
                signal_sumoids.append(signal_obj.get('id'))
        # print('IDs of associated signals on Sumo Logic side:', signal_sumoids)
        query = ' or '.join([f'alertid={id}' for id in signal_sumoids])
        search_results = demisto.executeCommand("SearchIncidentsV2", {'query': query})
        if ('Contents' in search_results[0]):
            content_raw = search_results[0].get('Contents')
            if (content_raw is not None):
                real_search_results = content_raw[0]
                if real_search_results.get('Contents').get('data') is not None:
                    for signal in real_search_results.get('Contents').get('data'):
                        signal_id = signal.get('id')
                        if (signal_id is not None):
                            linked_signal_ids.append(signal_id)
            else:
                # print(search_results)
                result = {'message': 'Cannot find any Signal Incident to link'}
        # print('Current Incident ID:' + cur_incident.get('id'))
        if (len(linked_signal_ids) > 0):
            # print('Found these signal incidents:', linked_signal_ids)
            call_result = demisto.executeCommand("linkIncidents", {"incidentId": cur_incident.get(
                'id'), "linkedIncidentIDs": ",".join(linked_signal_ids)})
            result = {'message': call_result[0]['Contents']}
        else:
            result = {'message': 'Cannot find any Signal Incident to link'}

    return CommandResults(
        outputs_prefix='BaseScript',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(link_incidents_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute SumoLogicLinkSignalIncidents. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
