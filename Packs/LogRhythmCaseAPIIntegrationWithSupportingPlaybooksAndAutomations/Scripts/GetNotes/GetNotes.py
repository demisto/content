import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# Locates the notes associated with an incident given the incident ID
#
# @param incident_id: The id of the incident that notes are being pulled from.
#
# @return results as XSOAR.Investigation.Notes


def main():
    # parse the incident_id from the paramaters
    inc_id = demisto.args()['incident_id']

    # use the associated Incident Id to get a list of entries.
    entries = demisto.executeCommand('getEntries', {'id': inc_id})
    results = []

    # itterate over all entries and if the entry is marked as a Note
    # append that entry to the results field
    for entry in entries:
        if entry['Note'] == True:
            results.append(entry['Contents'])
    # Return the results as output.
    return_outputs(readable_output="My work here is done.", outputs={"XSOAR.Investigation.Notes": results}, raw_response=results)


main()
