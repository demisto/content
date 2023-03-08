import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Retrieves a command / script arguments dict, and then we can "get" the argument from that dict
email = demisto.args().get("email")

# get the user details, using the email argument
user = demisto.executeCommand("ad-get-user", {"email": email})

# get the rawjson Contents of the executeCommand, so we can utilize it within our script.
user = user[0].get("Contents")

# get the manager details, using the DN of the Manager, since that's what we have!
# then grab the Contents key from the response, so we can utilize it within our script.
manager = demisto.executeCommand("ad-get-user", {"dn": user.get("attributes").get("manager")[0]})[0]["Contents"]

# create our own "Contents" to be returned by this automation.
result = {
    "UserName": user.get('attributes').get('displayName')[0],
    "UserEmail": user.get('attributes').get('mail')[0],
    "UserGroups": user.get('attributes').get('memberOf'),
    "UserSamAccountName": user.get('attributes').get('sAMAccountName')[0],
    "ManagerName": manager.get('attributes').get('displayName')[0],
    "ManagerEmail": manager.get('attributes').get('mail')[0]
}

# table to markdown creates a slick markdown war room entry with a dictionary or a list of the same dictionaries,
readable = tableToMarkdown("Active Directory User and Manager Details", result, headers=[
                           "UserName", "UserEmail", "UserGroups", "UserSamAccountName", "ManagerName", "ManagerEmail"])

# command results creates the object for return_results
# readable_output = human readable markdown that will be used for the war room entry
# outputs_prefix = The Context Key that our results will be placed under in context
# outputs_key_field = The key in the result that will be used to determine if the existing item already exists in Context, if so it will update.
# outputs = The raw data, in this case the "result" dict from above.
# ignore_auto_extract = When set to True, disables auto-extract on the results from this command. (Default is False)

results = CommandResults(
    readable_output=readable,
    outputs_prefix='ADUserAndManager',
    outputs_key_field="UserName",
    outputs=result,
    ignore_auto_extract=True
)

return_results(results)
