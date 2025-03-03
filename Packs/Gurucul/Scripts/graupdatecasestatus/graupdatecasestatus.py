import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    return demisto.incidents()[0]


def closeCase():
    incident = _get_incident()
    close_reason = demisto.args().get('closeReason')
    close_notes = demisto.args().get('closeNotes', '')
    action = 'closeCase'
    subOption = 'True Incident'

    if close_reason is not None and close_reason == "False Positive":
        action = "modelReviewCase"
        subOption = "Tuning Required"
    elif close_reason is not None and close_reason == "Other":
        action = "modelReviewCase"
        subOption = "Others"

    _caseId = ""
    for label in incident['labels']:
        if label['type'] == 'caseId':
            _caseId = label['value']
            break

    if _caseId == "":
        raise Exception('caseId was not found in the incident labels')

    res = demisto.executeCommand('gra-validate-api', {'using': incident['sourceInstance']})

    if res is not None and res[0]['Contents'] == 'Error in service':
        raise Exception('Case cannot be closed as GRA services are currently unavailable.')

    demisto.executeCommand('gra-case-action', {
        'action': action,
        'subOption': subOption,
        'caseId': _caseId,
        'caseComment': close_notes,
        'using': incident['sourceInstance']
    })


def main():
    try:
        closeCase()
    except Exception as ex:
        return_error(f'Failed to execute gra-case-close-post-processing. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
