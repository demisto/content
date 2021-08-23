import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    outputs: Dict[str, Any] = {}
    readable_output = ''
    err = None

    args = demisto.args()
    pwd_generation_script = args.get("pwdGenerationScript")
    username = args.get("sAMAccountName")
    user_email = args.get("email")
    display_name = args.get("displayname")
    to_email = args.get("to_email")
    inc_id = args.get("inc_id")
    email_subject = args.get("email_subject")
    password = None

    try:
        # Generate a random password
        pwd_generation_script_output = demisto.executeCommand(pwd_generation_script, {})
        if is_error(pwd_generation_script_output):
            raise Exception(f'An error occurred while trying to generate a new password for the user. '
                            f'Error is:\n{get_error(pwd_generation_script_output)}')
        else:
            password_output = demisto.get(pwd_generation_script_output[0], 'Contents')
            if isinstance(password_output, dict):
                password = password_output.get("NEW_PASSWORD")
            elif isinstance(password_output, str):
                password = password_output
            else:
                raise Exception(f'Could not parse the generated password from {pwd_generation_script} outputs. '
                                f'Please make sure the output of the script is a string.')

            # set a new password
            ad_create_user_arguments = {
                'username': username,
                'password': password,
                'attribute-name': 'pwdLastSet',
                'attribute-value': -1
            }

            set_password_outputs = demisto.executeCommand("ad-set-new-password", ad_create_user_arguments)
            if is_error(set_password_outputs):
                err = get_error(set_password_outputs)
                if '5003' in err:
                    raise Exception(f"An error occurred while trying to set a new password for the user. "
                                    f"Please make sure that \"{pwd_generation_script}\" script "
                                    f"complies with your domain's password complexity policy.")
                raise Exception(f"An error occurred while trying to set a new password for the user. "
                                f"Error is:\n{err}")
            else:
                enable_outputs = demisto.executeCommand("ad-enable-account", ad_create_user_arguments)
                if is_error(enable_outputs):
                    raise Exception(f'An error occurred while trying to enable the user account. '
                                    f'Error is:\n{get_error(enable_outputs)}')
                else:
                    update_outputs = demisto.executeCommand("ad-update-user", ad_create_user_arguments)
                    if is_error(update_outputs):
                        raise Exception(f'An error occurred while trying to update the user account. '
                                        f'Error is:\n{get_error(update_outputs)}')
        outputs['success'] = True

    except Exception as e:
        outputs['success'] = False
        outputs['errorDetails'] = str(e)
        err = str(e)

    try:
        send_mail_outputs = send_email(display_name, username, user_email, err,
                                       to_email, password, inc_id, email_subject)

        if is_error(send_mail_outputs):
            raise Exception(f'An error occurred while trying to send mail. Error is:\n{get_error(send_mail_outputs)}')
        outputs['sentMail'] = True

    except Exception as e:
        outputs['sentMail'] = False
        outputs['sendMailError'] = str(e)

    if outputs['success'] and outputs['sentMail']:
        readable_output = f'Successfully activated user {username}. ' \
            f'An email with the user details was sent to {to_email}.'
    else:
        if outputs.get('errorDetails'):
            readable_output += f"{outputs.get('errorDetails')}\n"
        if outputs.get('sendMailError'):
            readable_output += str(outputs.get('sendMailError'))

    result = CommandResults(
        outputs_prefix='IAM.InitADUser',
        outputs=outputs,
        readable_output=readable_output
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
                     'This message was sent to inform you that an error occurred while trying ' \
                     'to activate the user account of ' + username + ' in the active Directory.\n\n' \
                     'The error is: ' + err + '\n\nRegards,\nIAM Team'

    return demisto.executeCommand("send-mail", {"to": to_email, "subject": email_subject, "body": email_body})


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
