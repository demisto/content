import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    return demisto.incidents()[0]


def closeCase():
    incident = _get_incident()
    close_reason = demisto.args().get('closeReason')
    close_notes = demisto.args().get('closeNotes')
    message = ""

    if close_reason is not None and close_notes is not None and close_reason != "" and close_notes != "":
        message = "Case marked as \"" + close_reason + "\" with comment \"" + close_notes + "\" from XSOAR."
    elif close_notes is not None and close_notes != "":
        message = "Case closed from XSOAR without any reason and comment: \"" + close_notes + "\"."
    elif close_reason is not None and close_reason != "":
        message = "Case marked as \"" + close_reason + "\" from XSOAR without any comment."
    else:
        message = "Case closed from XSOAR without any reason / comment."
    _caseId = ""
    for label in incident['labels']:
        if label['type'] == 'caseId':
            _caseId = label['value']
            break

    if _caseId == "":
        raise Exception('caseId was not found in the incident labels')

    demisto.executeCommand('gra-case-action', {
        'action': 'closeCase',
        'subOption': 'True Incident',
        'caseId': _caseId,
        'caseComment': message
    })


def main():
    try:
        closeCase()
    except Exception as ex:
        return_error(f'Failed to execute gra-case-close-post-processing. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
