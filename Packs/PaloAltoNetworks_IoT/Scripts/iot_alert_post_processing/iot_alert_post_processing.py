import demistomock as demisto


def _get_incident():
    return demisto.incidents()[0]


def iot_resolve_alert():
    incident = _get_incident()

    _id = ""
    for label in incident['labels']:
        if label['type'] == 'id':
            _id = label['value']
            break

    if _id == "":
        raise Exception('id was not found in the incident labels')

    args = demisto.args()
    close_reason = args.get('closeReason')

    demisto.executeCommand('iot-resolve-alert', {
        'id': _id,
        'reason': f'resolved by XSOAR incident {incident["id"]}',
        'reason_type': 'Issue Mitigated' if close_reason == "Resolved" else 'No Action Needed'
    })


def main():
    try:
        iot_resolve_alert()
    except Exception as ex:
        demisto.error(f'Failed to execute iot-alert-post-processing. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
