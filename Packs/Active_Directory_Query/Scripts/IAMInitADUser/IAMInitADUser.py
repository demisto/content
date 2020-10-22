import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback

SUBJECT = 'Active Directory Account Created'
EMAIL_NOTIFICATION_LIST_NAME = 'ad-create-user-email-notification-list'

DEFAULT_OUTGOING_MAPPER = "User Profile - Active Directory (Outgoing)"
MAPPING_TYPE = "'User Profile'"


def main():
    try:
        args = demisto.args()
        pwd_generation_script = args.get("pwdGenerationScript")
        user_profile = args.get("userProfile")
        email = args.get("email")
        mapper_in = args.get("mapperIn", DEFAULT_OUTGOING_MAPPER)

        if not user_profile:
            # no user was created
            return

        # Generate a random password
        outputs = demisto.executeCommand(pwd_generation_script, {})
        password = demisto.get(outputs[0], 'Contents')

        user = demisto.mapObject(json.loads(user_profile), mapper_in, MAPPING_TYPE)
        username = user.get("samaccountname")
        display_name = user.get("displayname")

        # setting a new password
        ad_create_user_arguments = {
            'username': username,
            'password': password,
            'attribute-name': 'pwdLastSet',
            'attribute-value': -1
        }
        demisto.executeCommand("ad-set-new-password", ad_create_user_arguments)
        demisto.executeCommand("ad-enable-account", ad_create_user_arguments)
        demisto.executeCommand("ad-update-user", ad_create_user_arguments)
        send_email(display_name, username, email, password)
        return return_results("User was enabled and a password was set")

    except Exception as e:
        demisto.log(traceback.format_exc())
        return_error(str(e))


def send_email(name, sAMAccountName, email, password):
    try:
        email_notification_list_response = demisto.executeCommand("getList", {'listName': EMAIL_NOTIFICATION_LIST_NAME})
        if isError(email_notification_list_response[0]):
            return

        to = email_notification_list_response[0]['Contents']
        subject = SUBJECT + ': ' + sAMAccountName
        email_body = 'Hello,\n\n' \
                     'The following account has been created in Active Directory:\n\n' \
                     'Name: ' + name + '\n' \
                     'sAMAccountName: ' + sAMAccountName + '\n' \
                     'Email: ' + email + '\n' \
                     'Password: ' + password + '\n\n' \
                     'Regards,\nIAM Team'

        demisto.executeCommand("send-mail", {"to": to, "subject": subject, "body": email_body})
    except Exception as e:
        # Absorb the exception. We can just log error if send email failed.
        demisto.error('Failed to send email. Exception: ' + traceback.format_exc())


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
