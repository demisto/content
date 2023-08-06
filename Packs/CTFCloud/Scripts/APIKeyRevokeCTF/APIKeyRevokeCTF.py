import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import secrets


def validate(username):
    if (username.upper() == "AKIAZVSI4536365AD6WCJC"):
        return "You got it right.Removed previous access keys to this user.\nFlag: keepcalmandstaysecure"
    else:
        string="You got it wrong, the attacker still has an access to the organization.\nFlag:"
        flag =  secrets.token_hex(21)
        return string + " " + flag



def main():
    args = demisto.args()
    username = args.get('accesskey')
    try:
        return_results(validate(username))
    except Exception as ex:
        return_error(f'Failed to execute APIKeyRevokeCTF. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
