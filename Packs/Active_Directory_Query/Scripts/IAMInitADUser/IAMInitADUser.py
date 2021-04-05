import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback

SUBJECT = 'Active Directory Account Created'


def main():
    try:
        args = demisto.args()
        pwd_generation_script = args.get("pwdGenerationScript")
        username = args.get("sAMAccountName")
        user_email = args.get("email")
        display_name = args.get("displayname")
        to_email = args.get("to_email")

        # Generate a random password
        outputs = demisto.executeCommand(pwd_generation_script, {})
        password_dict = demisto.get(outputs[0], 'Contents')
        password = password_dict.get("NEW_PASSWORD")

        # set a new password
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

        if flow_worked:
            send_email(display_name, username, user_email, password, to_email)
            return_results("User was enabled and a password was set.")
        else:
            return_results("Some commands failed, please check the errors. "
                           "If you cannot determine the cause of the error, make sure that:\n"
                           "* You've added a transformer script which determines the OU where the user will be "
                           "created, in the Active Directory outgoing mapper, in the User Profile incident type "
                           "and schema type, under the \"ou\" field.\n"
                           "* You're using LDAPS in the Active Directory (port 636) integration.\n"
                           "* You've specified a password generation script in the \"IAM - Activate User In "
                           "Active Directory\" playbook inputs, under the \"PasswordGenerationScriptName\", "
                           "and that script complies with your domain's password complexity policy.")

    except Exception as e:
        return_error(str(e))


def send_email(name, sAMAccountName, user_email, password, to_email):
    try:
        if not to_email:
            return

        subject = f'{SUBJECT}: {sAMAccountName}'
        email_body = 'Hello,\n\n' \
                     'The following account has been created in Active Directory:\n\n'
        if name:
            email_body += 'Name: ' + name + '\n'

        email_body += 'sAMAccountName: ' + sAMAccountName + '\n' \
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
