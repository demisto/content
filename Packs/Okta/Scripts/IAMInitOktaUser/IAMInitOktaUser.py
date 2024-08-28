import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import uuid
from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES

DEFAULT_PWD_GENERATION_SCRIPT = "GeneratePassword"
TEXT_FILE_NAME = "Okta_Password"  # File name for the text file (within the zip file) to use
EMAIL_ZIP_NAME = "Okta_Password"  # File name to use for the zip file when attaching it to the email


def find_file_entry_id(file_name: str) -> str:
    """
    Find the entry ID of a file in the context by its name.

    Args:
        file_name (str): The name of the file to find.

    Returns:
        str: The entry ID of the file.
    """
    file_entries = demisto.context().get('File', [])

    if isinstance(file_entries, dict):  # In case of a single entry
        file_entries = [file_entries]

    for item in file_entries:
        if item['Name'] == file_name:
            return item['EntryID']

    raise DemistoException(f"Could not find file '{file_name}' in the context.")


def generate_password(password_generation_script: str, min_lcase: str, max_lcase: str, min_ucase: str, max_ucase: str,
                      min_digits: str, max_digits: str, min_symbols: str, max_symbols: str) -> str:
    """
    Generate a random password using a script.

    Args:
        password_generation_script (str): The name of the script to use for generating the password.
        min_lcase (str): The minimum number of lowercase characters to use in the password.
        max_lcase (str): The maximum number of lowercase characters to use in the password.
        min_ucase (str): The minimum number of uppercase characters to use in the password.
        max_ucase (str): The maximum number of uppercase characters to use in the password.
        min_digits (str): The minimum number of digits to use in the password.
        max_digits (str): The maximum number of digits to use in the password.
        min_symbols (str): The minimum number of symbols to use in the password.
        max_symbols (str): The maximum number of symbols to use in the password.

    Returns:
        str: The generated password.
    """
    # Generate a random password
    if password_generation_script == DEFAULT_PWD_GENERATION_SCRIPT:
        script_params = {
            "min_lcase": min_lcase,
            "max_lcase": max_lcase,
            "min_ucase": min_ucase,
            "max_ucase": max_ucase,
            "min_digits": min_digits,
            "max_digits": max_digits,
            "min_symbols": min_symbols,
            "max_symbols": max_symbols
        }

        pwd_generation_script_output = demisto.executeCommand(password_generation_script, script_params)

    else:
        pwd_generation_script_output = demisto.executeCommand(password_generation_script, {})

    if is_error(pwd_generation_script_output):
        raise Exception(f'An error occurred while trying to generate a new password for the user. '
                        f'Error is:\n{get_error(pwd_generation_script_output)}')

    else:
        password_output = pwd_generation_script_output[0]['Contents']

        if isinstance(password_output, dict):
            return password_output["NEW_PASSWORD"]

        elif isinstance(password_output, str):
            return password_output

        else:
            raise Exception(f'Could not parse the generated password from {password_generation_script} outputs. '
                            f'Please make sure the output of the script is a string, or a dictionary containing '
                            f'a key named NEW_PASSWORD.')


def okta_update_user(username: str, password: str, temporary_password: str, password_generation_script: str) -> None:
    """
    Update user's password in Okta, and enable the user account in case it was disabled.

    Args:
        username (str): The username of the user to update.
        password (str): The new password.
        temporary_password (str): Whether the password is temporary or not ("true" or "false").
        password_generation_script (str): The name of the script that generates the password (used for error handling).

    Raises:
        DemistoException: In case of a known potential error.
    """
    # Update user password
    set_password_outputs = demisto.executeCommand(
        'okta-set-password', {
            'username': username,
            'password': password,
            'temporary_password': temporary_password,
        }
    )

    if is_error(set_password_outputs):
        error_message = get_error(set_password_outputs)
        if '400' in error_message:
            raise DemistoException(f"An error occurred while trying to set a new password for the user. "
                                   f"Please make sure that the '{password_generation_script}' script "
                                   f"complies with your domain's password complexity policy.")

        raise DemistoException(f"An error occurred while trying to set a new password for the user:\n"
                               f"{error_message}")

    # Enable user (in case it was disabled)
    enable_outputs = demisto.executeCommand("okta-activate-user", {'username': username})

    if is_error(enable_outputs):
        error_message = get_error(enable_outputs)

        if "the user is already active" not in error_message:
            raise DemistoException(f'An error occurred while trying to enable the user account. '
                                   f'Error:\n{error_message}')


def send_email(username: str, email_recipient: str, email_subject: str,
               email_body: str, display_name: str | None, error_message: str | None = None,
               password: str | None = None, zip_file_entry_id: str | None = None) -> list | dict:
    """
    Email the user with the password (plain text or encrypted).
    One of 'error_message', 'password' or 'zip_file_entry_id' must be provided.

    Args:
        username (str): The username of the user.
        email_recipient (str): The email address of the recipient.
        email_subject (str): The subject of the email.
        email_body (str): The body of the email.
        display_name (str | None, optional): The display name of the user.
        error_message (str | None, optional): An error message to include in the email.
        password (str | None, optional): The password to send in the email (plain text).
        zip_file_entry_id (str | None, optional): The entry ID of the zip file to send in the email (encrypted).

    Returns:
        list | dict: The outputs of the send-mail command.
    """
    if not any((error_message, password, zip_file_entry_id)):
        raise ValueError("Either 'password' or 'zip_file_entry_id' must be provided.")

    if error_message:
        email_subject = f"'User Activation In Okta' failed for user '{display_name}'"
        email_body = ('Hello,\n\n'
                      'This message was sent to inform you that an error occurred while trying '
                      f"'to activate the user account of '{username}' in Okta.\n\n'"
                      f"'The error is: '{error_message}'\n\nRegards,\nIAM Team'")

    else:
        if not email_subject:
            email_subject = f"User '{display_name or username}' was successfully activated in Okta"

        email_password = 'Available in the attached zip file' if zip_file_entry_id else password

        if not email_body:
            email_body = ('Hello,\n\n'
                          'The following account has been activated in Okta:\n\n')
            if display_name:
                email_body += f'Name: {display_name}\n'

            email_body += f'Username: {username}\nPassword: {email_password}\n\nRegards,\nIAM Team'
        else:
            email_body += f'\nUsername: {username}\nPassword: {email_password}'

    send_email_args = {"to": email_recipient, "subject": email_subject, "body": email_body}

    if zip_file_entry_id:
        send_email_args |= {"attachIDs": zip_file_entry_id, "attachNames": f"{EMAIL_ZIP_NAME}.zip"}

    return demisto.executeCommand("send-mail", send_email_args)


@polling_function(
    name="IAMInitOktaUser",
    interval=10,
    requires_polling_arg=False,
)
def create_zip_with_password(args: dict, generated_password: str, zip_password: str) -> PollResult:
    """
    Create a zip file with a password.
    The function returns a zip file to the war room, and calls this script recursively using polling.

    Args:
        args (dict): The arguments passed to the script.
        generated_password (str): The password to encrypt.
        zip_password (str): The password to use for encrypting the zip file.

    Returns:
        PollResult: The polling result.
    """
    text_file_name = f'{TEXT_FILE_NAME}.txt'
    zip_file_name = f'{EMAIL_ZIP_NAME}_{uuid.uuid4()}.zip'

    try:
        with open(text_file_name, 'w') as text_file:
            text_file.write(generated_password)

        demisto.debug(f'zipping {text_file_name=}')
        with AESZipFile(zip_file_name, mode='w', compression=ZIP_DEFLATED, encryption=WZ_AES) as zf:
            zf.pwd = bytes(zip_password, 'utf-8')
            zf.write(text_file_name)

        with open(zip_file_name, 'rb') as zip_file:
            zip_content = zip_file.read()

    except Exception as e:
        raise DemistoException(f'Could not generate zip file. Error:\n{str(e)}')

    finally:
        for file_name in (text_file_name, zip_file_name):
            if os.path.exists(file_name):
                os.remove(file_name)

    return_results(fileResult(zip_file_name, zip_content))

    return PollResult(
        response=None,
        continue_to_poll=True,
        partial_result=CommandResults(readable_output=f"Encrypted zip file generated. File name: '{zip_file_name}'."),
        args_for_next_run={**args, 'zip_file_name': zip_file_name},
    )


def main():
    args = demisto.args()
    password_generation_script = args.get("pwdGenerationScript", DEFAULT_PWD_GENERATION_SCRIPT)
    username = args.get("username")
    display_name = args.get("displayname")
    email_recipient = args.get("to_email")
    email_subject = args.get("email_subject")
    email_body = args.get("email_body")
    zip_password = args.get("ZipProtectWithPassword")
    temporary_password = args.get("temporary_password", "false")
    zip_file_name = args.get("zip_file_name")

    generated_password: str | None = None
    file_entry_id: str | None = None
    context_outputs: dict[str, str] = {'success': 'true'}
    error_message: str | None = None

    if not zip_password:
        return_warning("It is highly recommended to run the script using the 'ZipProtectWithPassword' argument,"
                       "as sending a plain text password in an email is an insecure practice.")

    # If zip file is already generated and this is the second iteration, we skip this section
    if not (zip_password and zip_file_name):
        try:
            generated_password = generate_password(
                password_generation_script=password_generation_script,
                min_lcase=args.get("min_lcase", "0"),
                max_lcase=args.get("max_lcase", "10"),
                min_ucase=args.get("min_ucase", "0"),
                max_ucase=args.get("max_ucase", "10"),
                min_digits=args.get("min_digits", "0"),
                max_digits=args.get("max_digits", "10"),
                min_symbols=args.get("min_symbols", "0"),
                max_symbols=args.get("max_symbols", "10"),
            )

            okta_update_user(username=username, password=generated_password, temporary_password=temporary_password,
                             password_generation_script=password_generation_script)

            if zip_password:
                # Rerun the script using polling (with a 'zip_file_name' value)
                return_results(
                    create_zip_with_password(args=args, generated_password=generated_password, zip_password=zip_password)
                )
                return

        except Exception as e:
            context_outputs['success'] = 'false'
            error_message = str(e)
            context_outputs['errorDetails'] = error_message
            demisto.error(traceback.format_exc())

    else:
        file_entry_id = find_file_entry_id(zip_file_name)

    try:
        send_mail_outputs = send_email(display_name=display_name, username=username, error_message=error_message,
                                       email_recipient=email_recipient, email_subject=email_subject,
                                       email_body=email_body, password=generated_password, zip_file_entry_id=file_entry_id)

        if is_error(send_mail_outputs):
            raise DemistoException(f'An error occurred while trying to send mail:\n{get_error(send_mail_outputs)}')

        context_outputs['sentMail'] = 'true'

    except Exception as e:
        demisto.error(traceback.format_exc())
        context_outputs['sentMail'] = 'false'
        context_outputs['sendMailError'] = str(e)

    if context_outputs['success'] and context_outputs['sentMail']:
        readable_output = (f'Successfully activated user {username}. '
                           f'An email with the user details was sent to {email_recipient}.')
    else:
        readable_output = ''

        if error_message:
            readable_output += f"{error_message}\n"

        if context_outputs.get('sendMailError'):
            readable_output += context_outputs['sendMailError']

    return_results(CommandResults(
        outputs_prefix='IAM.InitOktaUser',
        outputs=context_outputs,
        readable_output=readable_output
    ))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
