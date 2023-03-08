import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This example script will request a users email, and execute the ad-get-user command via an Incident action button

# get the argument for the email
email = demisto.args().get("email")

# # get user, return result the easy way.
result = demisto.executeCommand("ad-get-user", {"email": email})
return_results(result)

# can also use the older demisto.results(result)
# demisto.results(result)

# ## ADVANCED
# # harder way, manipulating the data, and returning our own context.
# result = demisto.executeCommand("ad-get-user", {"email":email})

# # debug, to show the structure of the contents from executeCommand
# print(result)

# # get the Contents of the executeCommand
# result = result[0].get("Contents")

# # create our own output, and return results
# output = {
#     "Name": result.get('attributes').get('displayName')[0],
#     "Email": result.get('attributes').get('mail')[0]
# }

# # Log stuff for debugging... verbose will print it to the war room, also goes to the server.log
# LOG(f"debug:{output}")
# LOG.print_log(verbose=True)

# # table to markdown creates a slick war room entry with a dict or a list of the same dictionaries.
# readable = tableToMarkdown("Active Directory User", output)

# # command results creates the object for return_results, which is the better version of demisto.results
# results = CommandResults(
#         readable_output=readable,
#         outputs_prefix=f'ADButtonLookup',
#         outputs_key_field="Name",
#         outputs=output
#     )

# return_results(results)
