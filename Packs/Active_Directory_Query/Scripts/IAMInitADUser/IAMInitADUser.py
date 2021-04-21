import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    outputs: Dict[str, Any] = {}
    readable_output = ''
    err = None

    try:
        args = demisto.args()
        pwd_generation_script = args.get("pwdGenerationScript")
        username = args.get("sAMAccountName")
        user_email = args.get("email")
        display_name = args.get("displayname")
        to_email = args.get("to_email")
        inc_id = args.get("inc_id")
        email_subject = args.get("email_subject")

        # Generate a random password
        pwd_generation_script_output = demisto.executeCommand(pwd_generation_script, {})
        if is_error(pwd_generation_script_output):
            err = 'An error occurred while trying to generate a new password for the user. Error is:\n' \
                  + str(demisto.get(pwd_generation_script_output[0], 'Contents'))
            password = None
        else:
            password_dict = demisto.get(pwd_generation_script_output[0], 'Contents')
            password = password_dict.get("NEW_PASSWORD")

            # set a new password
            ad_create_user_arguments = {
                'username': username,
                'password': password,
                'attribute-name': 'pwdLastSet',
                'attribute-value': -1
            }

            password_outputs = demisto.executeCommand("ad-set-new-password", ad_create_user_arguments)
            if is_error(password_outputs):
                outputs['success'] = False
                err = 'An error occurred while trying to set a new password for the user. Error is:\n' \
                      + str(demisto.get(pwd_generation_script_output[0], 'Contents'))
                if '5003' in err:
                    err += "\nPlease make sure that the \"PasswordGenerationScriptName\" playbook input complies " \
                       "with your domain's password complexity policy."
            else:
                enable_outputs = demisto.executeCommand("ad-enable-account", ad_create_user_arguments)
                if is_error(enable_outputs):
                    err = 'An error occurred while trying to enable the user account. Error is:\n' \
                          + str(demisto.get(enable_outputs[0], 'Contents'))
                else:
                    update_outputs = demisto.executeCommand("ad-update-user", ad_create_user_arguments)
                    if is_error(update_outputs):
                        err = 'An error occurred while trying to update the user account. Error is:\n' \
                              + str(demisto.get(update_outputs[0], 'Contents'))

        send_mail_outputs = send_email(display_name, username, user_email, err,
                                       to_email, password, inc_id, email_subject)

        success = err is None
        sent_mail = not is_error(send_mail_outputs)
        outputs = {
            'sentMail': sent_mail,
            'success': success
        }

        if not success:
            outputs['errorDetails'] = err
            readable_output = err
        if not sent_mail:
            outputs['sendMailError'] = str(demisto.get(send_mail_outputs[0], 'Contents'))
            if readable_output:
                readable_output = '\n\nIn addition, the following error returned from send-mail command:\n'
            readable_output += outputs['sendMailError']

        if success and sent_mail:
            readable_output = 'Successfully activated user ' + username + '.'

        result = CommandResults(
            outputs_prefix='IAM.InitADUser',
            outputs=outputs,
            readable_output=readable_output
        )
        return_results(result)

    except Exception as e:
        outputs['success'] = False
        outputs['errorDetails'] = str(e)
        result = CommandResults(
            outputs_prefix='IAM.InitADUser',
            outputs=outputs,
            readable_output=outputs['errorDetails']
        )
        return_results(result)


def send_email(display_name, username, user_email, err, to_email, password, inc_id, email_subject):
    if not err:
        if not email_subject:
            email_subject = f'[IAM] User {display_name} was successfully activated in Active Directory'

        email_body = 'Hello,\n\n' \
                     'The following account has been created in Active Directory:\n\n'
        if display_name:
            email_body += 'Name: ' + display_name + '\n'

        email_body += 'Username: ' + username + '\n' \
                      'Email: ' + user_email + '\n' \
                      'Password: ' + password + '\n\n' \
                      'Regards,\nIAM Team'
    else:
        email_subject = f'"IAM - Activate User In Active Directory" incident {inc_id} failed with user {display_name}'
        email_body = 'Hello,\n\n' \
                     'This message was sent to update you that an error occurred while trying ' \
                     'to activate the user account of ' + username + ' in the active Directory.\n\n' \
                     'The error is: ' + err + '\n\nRegards,\nIAM Team'

    return demisto.executeCommand("send-mail", {"to": to_email, "subject": email_subject, "body": email_body})


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
