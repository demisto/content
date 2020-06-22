import demistomock as demisto
from CommonServerPython import *


"""
This script is used to get the owner of the incidents email

"""


def get_owner_email():
    owner_username = demisto.incidents()[0].get("owner")
    if owner_username:
        try:
            owner_info = demisto.executeCommand('getUserByUsername', {"username": owner_username})[0]
            owner_email = owner_info.get("EntryContext").get("UserByUsername").get("email")
            readable_output = "# Incident Owners Email \n" + owner_email
            outputs = {'IncOwnerEmail': owner_email}
            return return_outputs(readable_output, outputs, owner_email)
        except Exception as ex:
            return_error("Error: {}".format(ex))
    else:
        return_error("Error: Email for owner of incident was not found")


get_owner_email()
