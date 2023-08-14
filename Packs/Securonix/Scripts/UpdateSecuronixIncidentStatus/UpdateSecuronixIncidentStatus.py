import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Close incident on Securonix."""


def main():
    """Entry point."""
    try:
        # Retrieve the arguments passed with the script.
        script_args = demisto.args()

        xsoar_incident_id = demisto.incident().get('id')
        incident_id = script_args.get('incident_id', '').strip()
        active_state = script_args.get('active_state_status', '').strip()
        close_state = script_args.get('close_state_status', '').strip()
        active_action_name = script_args.get('active_state_action', '').strip()
        close_action_name = script_args.get('close_state_action', '').strip()
        only_active = argToBoolean(script_args.get('only_active', False))
        using_instance = script_args.get('using', '').strip()

        # Retrieve the current status of the Securonix incident.
        incident_custom_fields = demisto.incident().get('CustomFields')
        current_incident_state = incident_custom_fields.get('securonixincidentstatus')

        # Check if the Securonix incident is not in the active state and not in closed state.
        # If incident not in the active or closed state, then only perform this action.
        if current_incident_state.lower() != active_state.lower() and \
                current_incident_state.lower() != close_state.lower():
            # Move the incident to the active state.
            command_args = {'incident_id': incident_id, 'action': active_action_name, 'action_parameters': '',
                            'using': using_instance}
            demisto.debug(f'Moving the incident {incident_id} to {active_state}.')
            command_raw_resp = demisto.executeCommand('securonix-perform-action-on-incident', command_args)
            command_resp = command_raw_resp[0]['Contents']

            # If the response is not 'submitted', then there is an error performing the action.
            if command_resp.lower() != 'submitted':
                demisto.error(command_resp)
                return_error(command_resp)

            comment_str = f'[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n' \
                          f'Added By: Automated XSOAR Playbook\n' \
                          f'Comment: Moved the state of current incident from {current_incident_state} to' \
                          f' {active_state}.'
            command_args = {'incident_id': incident_id, 'comment': comment_str, 'using': using_instance}
            command_raw_resp = demisto.executeCommand('securonix-add-comment-to-incident', command_args)
            command_resp = command_raw_resp[0]['Contents']

            if not isinstance(command_resp, bool):
                demisto.error(command_resp)

            # Update the current state of Securonix incident.
            current_incident_state = active_state

            if only_active:
                return return_results(f'Incident {incident_id} has been moved to {active_state}.')

        if not only_active:

            if current_incident_state.lower() != close_state.lower():
                # Close the incident on the Securonix platform.
                command_args = {'incident_id': incident_id, 'action': close_action_name, 'action_parameters': '',
                                'using': using_instance}
                demisto.debug(f'Moving the incident {incident_id} to {close_state}.')
                command_raw_resp = demisto.executeCommand('securonix-perform-action-on-incident', command_args)
                command_resp = command_raw_resp[0]['Contents']

                if command_resp.lower() != 'submitted':
                    demisto.error(command_resp)
                    return_error(command_resp)

                # Add a comment to the remote incident with the XSOAR incident id.
                comment_str = f'[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n' \
                              f'Added By: Automated XSOAR Playbook\n' \
                              f'Comment: Moved the state of current incident from {active_state} to' \
                              f' {close_state}.'
                command_args = {'incident_id': incident_id, 'comment': comment_str, 'using': using_instance}
                command_raw_resp = demisto.executeCommand('securonix-add-comment-to-incident', command_args)
                command_resp = command_raw_resp[0]['Contents']

                if not isinstance(command_resp, bool):
                    demisto.error(command_resp)
                    return return_results(f'Successfully closed incident {incident_id} on Securonix.\n'
                                          f'Could not able to add comment to the remote incident.'
                                          f'\nReason: {command_resp}')

                return return_results(f'Successfully closed incident {incident_id} on Securonix.')

            return_results(f'Incident {incident_id} is already in {close_state} state on Securonix.')

    except Exception as exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute CloseSecuronixIncidents. Error: {str(exception)}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
