import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# import demistomock as demisto  # noqa: F401
# from CommonServerPython import *  # noqa: F401
"""This is an automation script for sending an email whenever a particular incident is encountered.
This incident is identified by its remediation action. If the remediation action is ALERT or NEEDS REVIEW, an email
is automatically sent to the desired admin email/group.
"""

from typing import Dict, Any
import traceback
import smtplib

''' STANDALONE FUNCTION '''


# TODO: REMOVE the following dummy function:
def send_email(email: str, incident_id: str, remediation_action: str) -> str:
    """Returns a string acknowledging the status of email sending procedure.
    :param email: email id of the recipient
    :param incident_id: The incident under the investigation, whose remediation action is being checked
    :param remediation_action: The remediation action of the incident under inspection.

    """
    if remediation_action:
        port = demisto.args().get('smtp_port')  # 465
        smtp_server = demisto.args().get('smtp_server')  # 'smtp.gmail.com'
        sender_email = demisto.args().get('sender_mail_address')
        password = demisto.args().get('sender_mail_password')
        receiver_email = email
        subject = 'Remediation Action '
        body = f'The incident id: {incident_id} NEEDS REVIEW.'
        message = 'Subject: {}\n\n{}'.format(subject, body)
        with smtplib.SMTP_SSL(smtp_server, port) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)

        return f"Email Sent to {email}"
    else:
        return "Does not require to be reviewed"


''' COMMAND FUNCTION '''


def send_email_command(args: Dict[str, Any]) -> CommandResults:

    email = args.get('recipient_mail_address', None)
    incident_id = args.get('incident_id', None)
    remediation_action = args.get('remediation_action', None)
    if not incident_id:
        raise ValueError('Incident Id not specified')

    if not email:
        raise ValueError('Email not specified')

    # Call the standalone function and get the raw response
    result = send_email(email, incident_id, remediation_action)
    markdown = f'## {result}'
    outputs = {
        'Armorblox': {
            'send_report': result
        }
    }

    return CommandResults(
        readable_output=markdown,
        outputs_key_field=None,
        outputs=outputs,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(send_email_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
