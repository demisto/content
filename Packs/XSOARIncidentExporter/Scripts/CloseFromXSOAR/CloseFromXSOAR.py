import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

CLOSE_REASON_MAP = {
    'resolved': 'Resolved',
    'false positive': 'False Positive',
    'duplicate': 'Duplicate',
    'other': 'Other',
}


def extract_field(description: str, field_name: str) -> str:
    pattern = rf'{re.escape(field_name)}:\s*(.+?)(?:\n|$)'
    match = re.search(pattern, description)
    return match.group(1).strip() if match else ''


def map_close_reason(xsoar_reason: str) -> str:
    if not xsoar_reason:
        return 'Other'
    return CLOSE_REASON_MAP.get(xsoar_reason.lower(), 'Other')


def main():
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {}) or {}

    description = custom_fields.get('alertdescription', '') or custom_fields.get('alert_description', '')
    if not description:
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('type') in ('alert_description', 'alertdescription'):
                description = label.get('value', '')
                break
    if not description:
        description = incident.get('details', '') or ''

    status = extract_field(description, 'Status')
    close_reason = extract_field(description, 'Close Reason')
    close_notes = extract_field(description, 'Close Notes')
    xsoar_id = extract_field(description, 'XSOAR Incident ID')

    if status not in ('Done', 'Archive'):
        return_results(CommandResults(
            readable_output=f'XSOAR incident {xsoar_id} is not closed (Status: {status}). No action taken.',
            outputs_prefix='XSOARClose',
            outputs={
                'XSOARIncidentID': xsoar_id,
                'Status': status,
                'Action': 'none',
            },
        ))
        return

    xsiam_reason = map_close_reason(close_reason)
    notes = f'Closed in XSOAR as: {close_reason}'
    if close_notes:
        notes += f'\nXSOAR Close Notes: {close_notes}'

    res = demisto.executeCommand('closeInvestigation', {
        'closeReason': xsiam_reason,
        'closeNotes': notes,
    })
    if is_error(res):
        return_error(f'Failed to close case: {get_error(res)}')

    return_results(CommandResults(
        readable_output=(
            f'### Closed XSIAM Case\n'
            f'- **XSOAR Incident ID:** {xsoar_id}\n'
            f'- **XSOAR Close Reason:** {close_reason}\n'
            f'- **XSIAM Close Reason:** {xsiam_reason}\n'
            f'- **Close Notes:** {close_notes or "(none)"}\n'
        ),
        outputs_prefix='XSOARClose',
        outputs={
            'XSOARIncidentID': xsoar_id,
            'XSOARCloseReason': close_reason,
            'XSIAMCloseReason': xsiam_reason,
            'CloseNotes': close_notes,
            'Action': 'closed',
        },
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
