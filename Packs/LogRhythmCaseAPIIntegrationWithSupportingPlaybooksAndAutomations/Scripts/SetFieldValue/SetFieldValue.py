import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# SetFieldValue takes in two arguments from demisto.
#
# @param field: the field being set by this automation
#
# @param value: the value for which a specific field is being set


def main():
    # Parse the arguments from XSOAR
    field = demisto.args()['field']
    value = demisto.args()['value']

    # Construct a list of arguments to be passed to SetIncident
    args = {field: value}

    # Call SetIncident with the appropriate arguments
    demisto.executeCommand('setIncident', args)


main()
