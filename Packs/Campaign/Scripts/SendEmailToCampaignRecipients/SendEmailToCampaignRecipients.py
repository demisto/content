import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

INVALID_EMAIL_TO_MSG = 'The email to field should contain valid value'


def main():
    try:
        incident = demisto.incidents()[0]
        custom_fields = incident.get('CustomFields', {})
        emailto = custom_fields.get('campaignemailto')
        subject = custom_fields.get('campaignemailsubject')
        email_body = custom_fields.get('campaignemailbody')
        if not emailto:
            return_error(INVALID_EMAIL_TO_MSG)

        demisto.executeCommand("send-mail", {"to": emailto, "subject": subject, "body": email_body})
    except Exception as ex:
        return_error(f'Failed to execute SendEmailToCampaignRecipients. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
