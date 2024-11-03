import demistomock as demisto
from CommonServerPython import *

"""
Pass in JSON key value lookup then fetches the incident owner and finds the bonusly user

"""

json_lookup = demisto.args().get('json')
if isinstance(json_lookup, str):
    json_lookup = json.loads(json_lookup)


def inc_owner_bonusly_user():
    owner_username = demisto.args().get('owner')
    if owner_username:
        try:
            owner_info = demisto.executeCommand('getUserByUsername', {"username": owner_username})[0]
            owner_email = owner_info.get("EntryContext").get("UserByUsername").get("email")
            bonusly_user = json_lookup[owner_email]
            readable_output = "# Incident Owners Email \n" + owner_email + '\n # Bonusly User ' + bonusly_user
            outputs = {'IncOwnerEmail': owner_email, 'BonuslyUser': bonusly_user}
            return return_outputs(readable_output, outputs, owner_email)
        except Exception as ex:
            return_error(f"Error: {ex}")
    else:
        return_error("Error: Email for owner of incident was not found")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    inc_owner_bonusly_user()
