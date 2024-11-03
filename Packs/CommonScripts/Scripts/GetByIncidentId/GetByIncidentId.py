import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from functools import reduce


def get_by_incident_id(incident_id, get_key, set_key=""):
    set_key = get_key if not set_key else set_key
    keys = get_key.split('.')

    try:
        context = demisto.executeCommand("getContext", {"id": incident_id})[0]['Contents']['context']
        res = reduce(lambda x, y: x[y], keys, context)
    except KeyError:
        error_msg = f"Cannot find {get_key} in incident #{incident_id}"
        return_error(message=error_msg,
                     error='GetByIncidentId: ' + error_msg,
                     outputs={set_key: error_msg})

    entry_context = {set_key: res}

    return_outputs(
        readable_output=f"Key '{get_key}' successfully retrieved and set into current incident at '{set_key}'.",
        outputs=entry_context)


def main():
    '''Get arguments and call primary function'''
    inc_id = demisto.args().get('incident_id', demisto.incidents()[0]['id'])
    get_k = demisto.args()['get_key']
    set_k = demisto.args().get('set_key', get_k)

    get_by_incident_id(inc_id, get_k, set_k)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
