import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
This script is used to simplify the process of creating a new record in Archer.
You can add fields that you want in the record as script arguments and or in the
code and have a newly created record easily.

This automation is currently used for Archer application 75 (Security Incidents)
but can be altered to any other application by entering another application Id as
input or modifying the ApplicationId argument default value.Another option would
be to duplicate this script and adjust it to the new application Id.

Mandatory fields in your Archer setting should be changed to be mandatory arguments in this script.
You can identify such fields by trying to create a new record, you would receive a response
stating that Archer is missing a certain field.

Please note that if you will change it to work with another application some of the argument
defined fields might need to be changed as they belong to application 75.
"""

"""
Demisto script arguments cannot have spaces or special char such '/' in their name.
Therefore, we are transforming some values which are have such structure in Archer
from their script argument structure to their Archer structure.

If you add such arguments to the script add them to this dictionary as well.
"""

keysToChange = {
    'dateTimeOccurred': 'Date/Time Occurred',
    'dateTimeIdentified': 'Date/Time Identified',
    'dateTimeReported': 'Date/Time Reported',
    'executiveSummary': 'Executive Summary',
    'incidentReport': 'Incident Report'
}

"""
Adding the argument fields to the fieldsToValues dictionary.
If the key is in keysToChange we would add the Archer form, else we will add it as it is
"""


"""
If you want to add some constant args you can modify fieldsToValues
and add them inside it as key:value pairs
"""
createRecordArgs = {
    'applicationId': 75,
    'fieldsToValues': ({(keysToChange[k] if k in keysToChange else k): v for k, v in demisto.args().items()})
}
createRecordResult = demisto.executeCommand("archer-create-record", createRecordArgs)
demisto.results(createRecordResult)
