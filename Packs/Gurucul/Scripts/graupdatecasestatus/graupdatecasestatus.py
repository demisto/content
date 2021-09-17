import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    return demisto.incidents()[0]


def closeCase():
    demisto.info(str(_get_incident()))
    incident = _get_incident()
    _caseId = ""
    for label in incident['labels']:
        if label['type'] == 'caseId':
            _caseId = label['value']
            break
    demisto.info(_caseId)
    if _caseId == "":
        raise Exception('caseId was not found in the incident labels')

    demisto.executeCommand('gra-case-action', {
        'action': 'closeCase',
        'subOption': 'True Incident',
        'caseId': _caseId,
        'caseComment': 'Case closed from XSoar'
    })


def main():
    try:
        closeCase()
    except Exception as ex:
        return_error(f'Failed to execute gra-case-close-post-processing. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
