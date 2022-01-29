import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
This script is used to send an email about a breached SLA. The script, by default, sends the email to the assignee of the
incident. The email is sent using the send-email command, using all enabled integrations that support the command.
"""


def get_owner_email():
    owner_username = demisto.incidents()[0].get("owner")
    if owner_username:
        try:
            owner_info = demisto.executeCommand('getUserByUsername', {"username": owner_username})[0]
            owner_email = owner_info.get("EntryContext").get("UserByUsername").get("email")
            return owner_email
        except Exception, ex:
            demisto.results
            ({
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": "Could not retrieve user email. Maybe the user has no associated email to it.\
            Error: {}".format(ex)

            })
            return
    else:
        demisto.results
        ({
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": "An email can't be sent to the owner of the incident, because no owner was assigned."

        })


def get_subject():
    incident_name = demisto.incidents()[0].get("name")
    incident_id = demisto.incidents()[0].get("id")
    subject = "SLA Breached in incident \"{}\" #{}".format(incident_name, incident_id)
    return subject


def send_email(to, subject, body):
    demisto.results(demisto.executeCommand('send-mail', {
        "to": to,
        "subject": subject,
        "body": body}))


def get_body():
    field_name = demisto.args().get("field").get("cliName")
    sla = demisto.args().get("fieldValue").get("sla")
    start_date = demisto.args().get("fieldValue").get("startDate")
    body = "We have detected a breach in your SLA \"{}\".\nThe SLA was set to {} minute and was started on {}.".format(
        field_name, sla, start_date.split(".")[0])
    return body


email_to = get_owner_email()
email_subject = get_subject()
email_body = get_body()

if email_to:
    send_email(email_to, email_subject, email_body)
