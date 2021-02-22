import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback

SUBJECT = 'Active Directory Account Created'
DEFAULT_OUTGOING_MAPPER = "User Profile - Active Directory (Outgoing)"
MAPPING_TYPE = "'User Profile'"


def main():
    try:
        args = demisto.args()
        pwd_generation_script = args.get("pwdGenerationScript")
        user_profile = args.get("userProfile")
        to_email = args.get("email")
        mapper_in = args.get("mapperIn", DEFAULT_OUTGOING_MAPPER)

        if not user_profile:
            # no user was created
            return

        # Generate a random password
        outputs = demisto.executeCommand(pwd_generation_script, {})
        password_dict = demisto.get(outputs[0], 'Contents')
        password = password_dict.get("NEW_PASSWORD")

        user = demisto.mapObject(json.loads(user_profile), mapper_in, MAPPING_TYPE)
        user_email = user.get("email")
        username = user_email.split("@")[0]
        display_name = user.get("displayname")

        # setting a new password
        ad_create_user_arguments = {
            'username': username,
            'password': password,
            'attribute-name': 'pwdLastSet',
            'attribute-value': -1
        }
        flow_worked = True

        password_outputs = demisto.executeCommand("ad-set-new-password", ad_create_user_arguments)
        if is_error(password_outputs):
            flow_worked = False
            return_results(password_outputs)

        enable_outputs = demisto.executeCommand("ad-enable-account", ad_create_user_arguments)
        if is_error(enable_outputs):
            flow_worked = False
            return_results(enable_outputs)

        update_outputs = demisto.executeCommand("ad-update-user", ad_create_user_arguments)
        if is_error(update_outputs):
            flow_worked = False
            return_results(update_outputs)

        send_email(display_name, username, user_email, password, to_email)

        if flow_worked:
            return return_results("User was enabled and a password was set.")
        else:
            return return_results("Some commands failed, please check the errors.")

    except Exception as e:
        demisto.log(traceback.format_exc())
        return_error(str(e))


def send_email(name, sAMAccountName, user_email, password, to_email):
    try:
        if not to_email:
            return

        subject = f'{SUBJECT}: {sAMAccountName}'
        email_body = 'Hello,\n\n' \
                     'The following account has been created in Active Directory:\n\n' \
                     'Name: ' + name + '\n' \
                     'sAMAccountName: ' + sAMAccountName + '\n' \
                     'Email: ' + user_email + '\n' \
                     'Password: ' + password + '\n\n' \
                     'Regards,\nIAM Team'

        demisto.executeCommand("send-mail", {"to": to_email, "subject": subject, "body": email_body})

    except Exception as e:
        # Absorb the exception. We can just log error if send email failed.
        demisto.error(f'Failed to send email. Exception: {e}.\n' + traceback.format_exc())
        return_results(e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
