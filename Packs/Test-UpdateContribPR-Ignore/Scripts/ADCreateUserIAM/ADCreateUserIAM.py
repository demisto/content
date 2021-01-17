import secrets
import string
import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SUBJECT = 'Active Directory Account Created'
EMAIL_NOTIFICATION_LIST_NAME = 'ad-create-user-email-notification-list'


def main():
    try:
        args = demisto.args()

        # Generate a random password
        password = generate_password()

        custom_attributes = get_custom_attributes(args)
        dn = get_dn(args)

        ad_create_user_arguments = {
            'sAMAccountName': args.get('sAMAccountName'),
            'user-dn': dn,
            'email': args.get('email'),
            'password': password,
            'custom-attributes': custom_attributes
        }
        ad_create_user_response = demisto.executeCommand("ad-create-user", ad_create_user_arguments)
        if not isError(ad_create_user_response[0]):
            send_email(custom_attributes.get('displayName', ''), args.get('sAMAccountName'), args.get('email'),
                       password)

        demisto.results(ad_create_user_response)

    except Exception as e:
        demisto.log(traceback.format_exc())
        return_error(str(e))


def get_dn(args):
    ad_locationregion_ou_mapping = args.get('ad_locationregion_ou_mapping')
    location_region = args.get('location_region')

    if type(ad_locationregion_ou_mapping) != dict:
        ad_locationregion_ou_mapping = json.loads(ad_locationregion_ou_mapping)
    user_base_ou = ad_locationregion_ou_mapping.get(location_region)

    if not user_base_ou:
        raise Exception('Unable to find mapping for AD OU. Location Region={}, Mapping='
                        .format(location_region, ad_locationregion_ou_mapping))
    user_dn = 'CN=' + args.get('cn') + ',' + user_base_ou
    return user_dn


def get_custom_attributes(args):
    custom_attributes = args.get('custom_attributes')

    if custom_attributes:
        custom_attributes = json.loads(custom_attributes) if type(custom_attributes) != dict else custom_attributes
    else:
        custom_attributes = {}

    manager_email = args.get('manager_email')
    if manager_email:
        manager_dn = get_manager_dn(manager_email)
        if manager_dn:
            custom_attributes['manager'] = manager_dn

    return custom_attributes


def get_manager_dn(manager_email):
    manager_dn = ''
    samaccountname = manager_email.split('@')[0]
    ad_get_user_response = demisto.executeCommand("ad-get-user", {"sAMAccountName": samaccountname})
    if ad_get_user_response and not isError(ad_get_user_response[0]):
        ad_search_response_contents = demisto.get(ad_get_user_response[0], "Contents")
        if len(ad_search_response_contents) != 0:
            manager_dn = ad_search_response_contents[0]['dn']
    return manager_dn


def generate_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(12))  # for a 12-character password
    return password


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
