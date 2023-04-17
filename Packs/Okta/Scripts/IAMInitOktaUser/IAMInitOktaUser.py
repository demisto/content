import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pyminizip


DEFAULT_PWD_GENERATION_SCRIPT = "GeneratePassword"


def main():
    outputs: Dict[str, Any] = {}
    readable_output = ''
    err = None

    args = demisto.args()
    pwd_generation_script = args.get("pwdGenerationScript")
    username = args.get("username")
    display_name = args.get("displayname")
    to_email = args.get("to_email")
    email_subject = args.get("email_subject")
    email_body = args.get("email_body")
    min_lcase = args.get("min_lcase", 0)
    max_lcase = args.get("max_lcase", 10)
    min_ucase = args.get("min_ucase", 0)
    max_ucase = args.get("max_ucase", 10)
    min_digits = args.get("min_digits", 0)
    max_digits = args.get("max_digits", 10)
    min_symbols = args.get("min_symbols", 0)
    max_symbols = args.get("max_symbols", 10)
    password = None
    zip_protect_with_password = args.get("ZipProtectWithPassword", '')
    temporary_password = argToBoolean(args.get('temporary_password', False))

    try:
        # Generate a random password
        if pwd_generation_script == DEFAULT_PWD_GENERATION_SCRIPT:
            pwd_generation_script_output = demisto.executeCommand(pwd_generation_script, {"min_lcase": min_lcase,
                                                                                          "max_lcase": max_lcase,
                                                                                          "min_ucase": min_ucase,
                                                                                          "max_ucase": max_ucase,
                                                                                          "min_digits": min_digits,
                                                                                          "max_digits": max_digits,
                                                                                          "min_symbols": min_symbols,
                                                                                          "max_symbols": max_symbols})
        else:
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
                                f'Please make sure the output of the script is a string, or a dictionary containing '
                                f'a key named NEW_PASSWORD.')

            # Set args for setting the new passsword
            okta_set_pwd_args = {
                'username': username,
                'password': password,
                'temporary_password': temporary_password
            }

            # Set args for activating the user
            okta_activate_user_args = {
                'username': username
            }

            set_password_outputs = demisto.executeCommand("okta-set-password", okta_set_pwd_args)
            if is_error(set_password_outputs):
                err = get_error(set_password_outputs)
                if '400' in err:
                    raise Exception(f"An error occurred while trying to set a new password for the user. "
                                    f"Please make sure that \"{pwd_generation_script}\" script "
                                    f"complies with your domain's password complexity policy.")
                raise Exception(f"An error occurred while trying to set a new password for the user. "
                                f"Error is:\n{err}")
            else:
                enable_outputs = demisto.executeCommand("okta-activate-user", okta_activate_user_args)
                if is_error(enable_outputs):
                    err = get_error(enable_outputs)
                    if "the user is already active" in err:
                        err = None
                    else:
                        raise Exception(f'An error occurred while trying to enable the user account. '
                                        f'Error is:\n{get_error(enable_outputs)}')
        outputs['success'] = True

    except Exception as e:
        outputs['success'] = False
        outputs['errorDetails'] = str(e)
        err = str(e)

    try:
        send_mail_outputs = send_email(display_name, username, err,
                                       to_email, password, email_subject, email_body,
                                       zip_protect_with_password)

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
        outputs_prefix='IAM.InitOktaUser',
        outputs=outputs,
        readable_output=readable_output
    )
    return_results(result)


def send_email(display_name, username, err, to_email, password, email_subject, email_body, zip_with_password):
    if not err:
        if not email_subject:
            email_subject = f'User {display_name or username} was successfully activated in Okta'

        email_password = 'Available in the attached zip file' if zip_with_password else password
        if not email_body:
            email_body = 'Hello,\n\n' \
                         'The following account has been activated in Okta:\n\n'
            if display_name:
                email_body += f'Name: {display_name}\n'

            email_body += f'Username: {username}\nPassword: {email_password}\n\nRegards,\nIAM Team'
        else:
            email_body += f'\nUsername: {username}\nPassword: {email_password}'

        if zip_with_password:
            zip_file = create_zip_with_password(password, zip_with_password)
            result = fileResult('Okta_Password.zip', zip_file)
            file_id = result['FileID']

    else:
        email_subject = f'"User Activation In Okta" failed with user {display_name}'
        email_body = 'Hello,\n\n' \
                     'This message was sent to inform you that an error occurred while trying ' \
                     'to activate the user account of ' + username + ' in Okta.\n\n' \
                     'The error is: ' + err + '\n\nRegards,\nIAM Team'

    send_email_args = {"to": to_email, "subject": email_subject, "body": email_body}
    if zip_with_password:
        send_email_args |= {"attachIDs": file_id, "attachNames": 'Okta_Password.zip'}

    return demisto.executeCommand("send-mail", send_email_args)


def create_zip_with_password(generated_password, zip_password):
    text_file_name = 'Okta_Password.txt'
    zip_file_name = 'Okta_Password.zip'

    try:
        with open(text_file_name, 'w') as text_file:
            text_file.write(generated_password)

        pyminizip.compress(text_file_name, '', zip_file_name, zip_password, 1)

        with open(zip_file_name, 'rb') as zip_file:
            zip_content = zip_file.read()

    except Exception as e:
        raise Exception(f'An error occurred while trying to create a zip file. Error is:\n{str(e)}')

    finally:
        for file_name in (text_file_name, zip_file_name):
            if os.path.exists(file_name):
                os.remove(file_name)

    return zip_content


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
