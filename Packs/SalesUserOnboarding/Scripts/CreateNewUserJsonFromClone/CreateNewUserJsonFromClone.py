import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# This script is used to prep the ingestion of a Salesforce Create User API POST call
# It returns an actual JSON string for calling salesforce-create-object
# using the replaced values from the user we cloned from and passed into dArgs{}.


# Python template - reading arguments,
# calling a command, handling errors and returning results
# Constant and mandatory arguments
dArgs = {"MirroredUserJSONString": demisto.args()["MirroredUserJSONString"],
         "Username": demisto.args()["Username"],
         "CommunityNickname": demisto.args()["CommunityNickname"]

         }

# Initialize MirroredUserJSON from MirroredUserString
# outputs a list
dictIsolate = json.loads(dArgs['MirroredUserJSONString'])


# isolates the list that is within the 'Records' Value
#MirroredUserJSON = dictIsolate[0]["records"][0]
try:
    MirroredUserJSON = dictIsolate["records"][0]
# changed from overall to KeyError
except KeyError:
    MirroredUserJSON = dictIsolate[0]["records"][0]

# Optional arguments
if "Phone" in demisto.args():
    dArgs["Phone"] = demisto.args()["Phone"]

if "FirstName" in demisto.args():
    dArgs["FirstName"] = demisto.args()["FirstName"]

if "LastName" in demisto.args():
    dArgs["LastName"] = demisto.args()["LastName"]

if "Alias" in demisto.args():
    dArgs["Alias"] = demisto.args()["Alias"]

if "Email" in demisto.args():
    dArgs["Email"] = demisto.args()["Email"]

if "MobilePhone" in demisto.args():
    dArgs["MobilePhone"] = demisto.args()["MobilePhone"]

if "EmployeeNumber" in demisto.args():
    dArgs["EmployeeNumber"] = demisto.args()["EmployeeNumber"]

if "Address" in demisto.args():
    dArgs["Address"] = demisto.args()["Address"]

# Optional arguments with defaults - sometimes the arg is mandatory for our executeCommand
#dArgs["myargwithdefault"] = demisto.args()["myotherscriptarg"] if "myotherscriptarg" in demisto.args() else "10"

# deletes the values fronm MirroredUSerJSON for the following keys:
MirroredUserJSON.pop('CPQ_User_Name__c', None)
MirroredUserJSON.pop('SoxNotes', None)
MirroredUserJSON.pop('CPQUserMessage__c', None)
MirroredUserJSON.pop('Id', None)
MirroredUserJSON.pop('attributes', None)

# Initialize new empty dict for new user
ClonedUserJSON = {}

# Copy contents from MirroredUserJSON to ClonedUserJSON
ClonedUserJSON = MirroredUserJSON.copy()

# Replace the "new user" values in ClonedUserJSON with the passed-in "new user" argument values
for sub in ClonedUserJSON:

    # checking if key present in dArgs
    if sub in dArgs:
        ClonedUserJSON[sub] = dArgs[sub]
# Read through the dict and ensure mandatory fields exist and are properly defined

# Pass into demisto.output() to be used in future playbook tasks

# results = CommandResults(
# outputs_prefix='VirusTotal.IP',
# outputs_key_field='Address',
# outputs= ClonedUserJSON)
# return_results(results)

ClonedUserJsonString = json.dumps(ClonedUserJSON)
# assigns to Context Data
demisto.executeCommand("SetContext", {"key": "ClonedUserJsonString.", "value": ClonedUserJsonString})
demisto.results({"QueryString": ClonedUserJsonString})
