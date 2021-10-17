import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from string import Template


EMAIL_SUBJECT = "New Hire Account Created: {}"

DEFAULT_EMAIL_TEMPLATE = """Hello,<br/><br/>
The following account has been created in Active Directory:<br/>
Name: ${displayname}<br/>
sAMAccountName: ${sAMAccountName}<br/>
Email: ${email}<br/>
Password: ${password}<br/><br/>
Regards,<br/>
IAM Team
"""


def main():
    outputs: Dict[str, Union[str, bool]] = {
        'action': 'IAMInitADUser',
        'brand': 'Active Directory Query v2'
    }

    args = demisto.args()
    pwd_generation_script = args.get('pwdGenerationScript')

    user_profile = safe_load_json(args.get('user_profile'))
    sam_account_name = args.get('sAMAccountName')

    should_enable_user = args.get('enable_user') == 'true'

    manager_email_template_list_name = args.get('manager_email_template_list_name')

    notification_emails_list = args.get('notification_email_addresses')
    notification_email_template_list_name = args.get('notification_email_template_list_name')

    try:
        user_data = safe_load_json(user_profile)

        manager_email = user_data.get('manageremailaddress')
        manager_email_template = get_list(manager_email_template_list_name)

        notification_email_template = get_list(notification_email_template_list_name)

        password = generate_password(pwd_generation_script)

        ad_user_arguments = {
            'username': sam_account_name,
            'password': password,
            'attribute-name': 'pwdLastSet',
            'attribute-value': -1
        }

        set_new_password(ad_user_arguments, pwd_generation_script)
        if should_enable_user:
            enable_user(ad_user_arguments)

        user_data.update({
            'password': password,
            'sAMAccountName': sam_account_name
        })

        email_subject = EMAIL_SUBJECT.format(sam_account_name)
        # Send email to manager, unless the user is an acquisition hire
        if user_data.get('acquisitionhire', '').lower() != 'yes' and manager_email:
            email_body = Template(manager_email_template or DEFAULT_EMAIL_TEMPLATE).safe_substitute(**user_data)
            send_email(manager_email, email_subject, email_body)
            demisto.debug(f'IAMInitADUser: Sent email with user {sam_account_name} details to manager.')

        # Send email to notification_emails_list
        email_body = Template(notification_email_template or DEFAULT_EMAIL_TEMPLATE).safe_substitute(**user_data)
        send_email(notification_emails_list, email_subject, email_body)
        demisto.debug(f'IAMInitADUser: Sent a notification email with user {sam_account_name} details.')

        outputs['success'] = True
        readable_output = f'Successfully initiated user {sam_account_name}'
        if not should_enable_user:
            readable_output += ' in disabled mode.'
        else:
            readable_output += '.'

    except Exception as e:
        outputs['success'] = False
        outputs['errorMessage'] = readable_output = f'Error: {e}\nTraceback: {traceback.format_exc()}'

    result = CommandResults(
        outputs_prefix='IAM.Vendor',
        outputs=outputs,
        readable_output=readable_output
    )
    return_results(result)


def get_list(list_name: str) -> Optional[str]:
    if not list_name:
        demisto.debug('IAMInitADUser: No list name input was provided, will use default template for email')
        return None
    return execute_command('getList', args={'listName': list_name})


def generate_password(pwd_generation_script: str) -> Optional[str]:
    success, res = execute_command(pwd_generation_script, args={}, fail_on_error=False)
    if not success:
        raise Exception(f'An error occurred while trying to generate a new password for the user. '
                        f'Error is:\n{res}')

    if isinstance(res, dict):
        return res.get('NEW_PASSWORD')
    elif isinstance(res, str):
        return res
    else:
        raise Exception(f'Could not parse the generated password from {pwd_generation_script} outputs. '
                        f'Please make sure the output of the script is a string.')


def enable_user(args: dict) -> None:
    success, res = execute_command('ad-enable-account', args, fail_on_error=False)
    if not success:
        raise Exception(f'An error occurred while trying to enable the user account. '
                        f'Error is:\n{res}')

    success, res = execute_command('ad-update-user', args, fail_on_error=False)
    if not success:
        raise Exception(f'An error occurred while trying to update the user account. '
                        f'Error is:\n{res}')


def set_new_password(args: dict, pwd_generation_script: str) -> None:
    success, res = execute_command('ad-set-new-password', args, fail_on_error=False)
    if not success:
        if '5003' in res:
            raise Exception(f"An error occurred while trying to set a new password for the user. "
                            f"Please make sure that \"{pwd_generation_script}\" script "
                            f"complies with your domain's password complexity policy.")
        else:
            raise Exception(f"An error occurred while trying to set a new password for the user. "
                            f"Error is:\n{res}")


def send_email(to_email, email_subject, email_body):
    send_email_args = {"to": to_email, "subject": email_subject, "htmlBody": email_body}
    success, res = execute_command('send-mail', send_email_args, fail_on_error=False)
    if not success:
        raise Exception(f'An error occurred while trying to send email to {to_email}. Error is:\n{res}')
    return res


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
