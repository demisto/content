from CommonServerPython import *
import json


def add_entries(single_reply, email_related_incident):
    """Add the entries to the related incident
    Args:
        single_reply: The email reply.
        email_related_incident: The related incident.
    """
    entries_str = json.dumps([{"Type": 1, "ContentsFormat": 'markdown', "Contents": single_reply, "tags": ['email'
                                                                                                           '-thread']}])
    res = demisto.executeCommand("addEntries", {"entries": entries_str, 'id': email_related_incident})
    if is_error(res):
        demisto.results('ERROR: PreprocessEmail - addEntries: {}'.format(res['Contents']))
        raise DemistoException


def set_email_reply(email_from, email_to, email_cc, email_body):
    """Set the email reply from the given details.
    Args:
        email_from: The email author mail.
        email_to: The email recipients.
        email_cc: The email cc.
        email_body: The email body.
    Returns:
        str. Email reply.

    """
    single_reply = f"""
    From: *{email_from}*
    To: *{email_to}*
    CC: *{email_cc}*


    ----

    {email_body}
    """
    return single_reply


def get_incident_by_query(query):
    """
    Get incident id and return it's details.
    Args:
        query: Query for the incident id.
    Returns:
        dict. Incident details.
    """
    res = demisto.executeCommand("GetIncidentsByQuery", {"query": query, "Contents": "id,status"})[0]

    if is_error(res):
        demisto.results('ERROR: PreprocessEmail - GetIncidentsByQuery: {}'.format(res['Contents']))
        raise DemistoException

    incident_details = json.loads(res['Contents'])[0]
    return incident_details


def check_incident_status(incident_details, email_related_incident):
    """Get the incident details and checks the incident status.
    Args:
        incident_details: The incident details.
        email_related_incident: The related incident.
    """

    status = incident_details.get('status')
    if status == 2:  # closed incident status
        res = demisto.executeCommand("reopenInvestigation", {"id": email_related_incident})
        if is_error(res):
            demisto.results('ERROR: PreprocessEmail - Reopen incident: {}'.format(res['Contents']))
            raise DemistoException


def get_attachments_using_instance(email_related_incident, labels):
    """Use the instance from which the email was received to fetch the attachments.
        Only supported with: EWS V2, Gmail

    Args:
        email_related_incident (int): ID of the incident to attach the files to.
        labels (Dict): Incidnet's labels to fetch the relevant data from.

    """
    message_id = ''
    instance_name = ''
    integration_name = ''

    for label in labels:
        if label.get('type') == 'Email/ID':
            message_id = label.get('value')
        elif label.get('type') == 'Instance':
            instance_name = label.get('value')
        elif label.get('type') == 'Brand':
            integration_name = label.get('value')

    if integration_name == 'EWS v2':
        demisto.executeCommand("executeCommandAt",
                               {'command': 'ews-get-attachment', 'incidents': str(email_related_incident),
                                'arguments': {'item-id': str(message_id), 'using': instance_name}})

    elif integration_name == 'Gmail':
        demisto.executeCommand("executeCommandAt",
                               {'command': 'gmail-get-attachments', 'incidents': str(email_related_incident),
                                'arguments': {'user-id': 'me', 'message-id': str(message_id), 'using': instance_name}})

    else:
        demisto.debug('Attachments could only be retrieved from EWS v2 or Gmail')


def main():
    incident = demisto.incidents()[0]
    custom_fields = incident.get('CustomFields')
    email_body = custom_fields.get('emailbody')
    email_from = custom_fields.get('emailfrom')
    email_cc = custom_fields.get('emailcc')
    email_to = custom_fields.get('emailto')
    email_subject = custom_fields.get('emailsubject')

    try:
        email_related_incident = int(email_subject.split('#')[1].split()[0])
        query = f"id:{email_related_incident}"
        incident_details = get_incident_by_query(query)
        check_incident_status(incident_details, str(email_related_incident))
        email_reply = set_email_reply(email_from, email_to, email_cc, email_body)
        add_entries(email_reply, str(email_related_incident))
        get_attachments_using_instance(email_related_incident, incident.get('labels'))

        # False - to not create new incident
        demisto.results(False)

    except (IndexError, ValueError) as e:
        # True - For creating new incident
        demisto.results(True)
        return_error(f"Upon encountering an issue the PreprocessEmail script opens a new incident {e}")

    except DemistoException as e:
        # True - For creating new incident
        demisto.results(True)
        return_error(f"Upon encountering an issue the PreprocessEmail script opens a new incident- {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
