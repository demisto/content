import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    return demisto.incidents()[0]


def iot_resolve_vuln():
    incident = _get_incident()

    zb_ticketid = ""
    vulnerability_name = ""
    for label in incident['labels']:
        if label['type'] == 'zb_ticketid':
            zb_ticketid = label['value']
        if label['type'] == 'vulnerability_name':
            vulnerability_name = label['value']

    if zb_ticketid == "":
        raise Exception('zb_ticketid was not found in the incident labels')
    if vulnerability_name == "":
        raise Exception('vulnerability_name was not found in the incident labels')

    demisto.executeCommand('iot-security-resolve-vuln', {
        'id': zb_ticketid,
        'full_name': vulnerability_name,
        'reason': f'resolved by XSOAR incident {incident["id"]}'
    })


def main():
    try:
        iot_resolve_vuln()
    except Exception as ex:
        return_error(f'Failed to execute iot-security-vuln-post-processing. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
