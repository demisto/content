import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# For Turkish
# Bu script Halim ONUR tarafından 06/06/2023 tarihinde yazılmıştır.
# For English
# This script has been written by Halim ONUR on June 6, 2023.

def close_investigation_and_qradar_offense():
    
    # The section titled Get Investigation
    current_investigation_id = demisto.investigation()['id']

    # For entry, a note is required.
    note = demisto.args().get('note')

    # The necessary steps to close the incident.
    close_params = {
        'id': current_investigation_id,
        'status': 'Closed'
    }

    try:
        # The incident is being closed.
        demisto.executeCommand('CloseInvestigation', close_params)
        demisto.results('The incident has been successfully resolved.')

        # Add the note to the Incident in XSOAR.
        demisto.executeCommand('setIncident', {'closeNotes': note})
        demisto.results('Note, the incident has been successfully added.')
    except Exception as e:
        demisto.error(f'incident kapatılırken bir hata oluştu: {str(e)}')

    try:
        # The parameters required to close the QRadar offense.
        incident = demisto.incident()
        qradar_close_params = {
            'offense_id': incident.get('CustomFields', {}).get('alertid', ''),
            'status': 'CLOSED',
            'closing_reason_id': '2'
        }

        # close the QRadar offense
        demisto.executeCommand('qradar-offense-update', qradar_close_params)
        demisto.results('The QRadar offense has been successfully closed.')

        # Add the note to the QRadar offense.
        qradar_note_params = {
            'offense_id': incident.get('CustomFields', {}).get('alertid', ''),
            'note_text': note
        }
        demisto.executeCommand('qradar-offense-note-create', qradar_note_params)
        demisto.results('Note, successfully added to the QRadar offense.')
    except Exception as e:
        demisto.error(f'An error occurred while closing the QRadar offense. {str(e)}')


# Main
if __name__ in ('__main__', '__builtin__', 'builtins'):
    close_investigation_and_qradar_offense()
