import json
import re
import random
import demistomock as demisto

ERROR_TEMPLATE = 'ERROR: PreprocessEmail - {function_name}: {reason}'
QUOTE_MARKERS = ['<div class="gmail_quote">',
                 '<hr tabindex="-1" style="display:inline-block; width:98%"><div id="divRplyFwdMsg"']


def get_query_window():
    """
    Check if the user defined the list `XSOAR - Email Communication Days To Query` to give a custom value for the time
    to query back for related incidents. If yes, use this value, else use the default value of 60 days.
    """
    user_defined_time = demisto.executeCommand('getList', {'listName': 'XSOAR - Email Communication Days To Query'})
    if is_error(user_defined_time):
        demisto.debug('Error occurred while trying to load the `XSOAR - Email Communication Days To Query` list. Using'
                      ' the default query time - 60 days')
        return '60 days'

    try:
        query_time = user_defined_time[0].get('Contents')
        return f'{int(query_time)} days'
    except ValueError:
        demisto.error('Invalid input for number of days to query in the `XSOAR - Email Communication Days To Query` '
                      'list. Input should be a number only, representing the number of days to query back.\nUsing the '
                      'default query time - 60 days')
        return '60 days'


def add_entries(email_reply, email_related_incident, email_topic):
    """Add the entries to the related incident
    Args:
        email_reply: The email reply.
        email_related_incident: The related incident.
        email_topic: The formatted email topic
    """
    topic = generate_email_topic(email_topic)

    entries_str = json.dumps(
        [{"Type": 1, "ContentsFormat": 'html', "Contents": email_reply, "tags": [topic]}])

    res = demisto.executeCommand("addEntries", {"entries": entries_str, 'id': email_related_incident})

    if is_error(res):
        demisto.error(ERROR_TEMPLATE.format('addEntries', res[0]['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('addEntries', res[0]['Contents']))


# Add header fields information to the reply email body
def set_email_reply(email_from, email_to, email_cc, html_body, attachments, current_time, email_subject):
    """Set the email reply from the given details.
    Args:
        email_from: The email author mail.
        email_to: The email recipients.
        email_cc: The email cc.
        html_body: The email body.
        attachments: The email attachments.
        current_time: Current system time to mark the Sent field
        email_subject: The email subject

    Returns:
        str. Email reply.

    """
    email_reply = f'<p><b>From:</b> {email_from} <br>' \
    + f"<b>Sent:</b> {current_time} <br>" \
    + f"<b>To:</b> {email_to} <br>"\
    + f"<b>CC:</b> {email_cc} <br>"\
    + f"<b>Subject:</b> {email_subject} <br>"\
    + "</p>"


    if attachments:
        attachment_names = [attachment.get('name', '') for attachment in attachments]
        email_reply += f'Attachments: {attachment_names}\n\n'

    email_reply += f'{html_body}\n'

    return re.sub('>\W+<','><',email_reply)


def get_incident_by_query(query):
    """
    Get a query and return all incidents details matching the given query.
    Args:
        query: Query for the incidents that should be returned.
    Returns:
        dict. The details of all incidents matching the query.
    """
    # In order to avoid performance issues, limit the number of days to query back for modified incidents. By default
    # the limit is 60 days and can be modified by the user by adding a list called
    # `XSOAR - Email Communication Days To Query` (see README for more information).
    query_time = get_query_window()

    query_from_date = str(parse_date_range(query_time)[0])

    res = demisto.executeCommand("GetIncidentsByQuery", {"query": query, "fromDate": query_from_date,
                                                         "timeField": "modified", "Contents": "id,status"})[0]
    if is_error(res):
        demisto.results(ERROR_TEMPLATE.format('GetIncidentsByQuery', res['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('GetIncidentsByQuery', res['Contents']))

    incidents_details = json.loads(res['Contents'])
    return incidents_details


def get_attachments_using_instance(email_related_incident, labels):
    """Use the instance from which the email was received to fetch the attachments.
        Only supported with: EWS V2, Gmail

    Args:
        email_related_incident (str): ID of the incident to attach the files to.
        labels (Dict): Incidnet's labels to fetch the relevant data from.
    Returns:
        message_id: The email message ID which can be used for send-reply
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

    if integration_name in ('EWS v2','EWSO365'):
        demisto.executeCommand("executeCommandAt",
                               {'command': 'ews-get-attachment', 'incidents': email_related_incident,
                                'arguments': {'item-id': str(message_id), 'using': instance_name}})

    elif integration_name == 'Gmail':
        demisto.executeCommand("executeCommandAt",
                               {'command': 'gmail-get-attachments', 'incidents': email_related_incident,
                                'arguments': {'user-id': 'me', 'message-id': str(message_id), 'using': instance_name}})

    # Note: attachments are downloaded by default when emails are fetched using the graph integrations,
    # so this method isn't needed for them.
    else:
        demisto.debug('Attachments could only be retrieved from EWS v2 or Gmail')

    return(message_id)


def store_topics(email_related_incident, email_subject, email_from, email_to, email_content, message_id, email_cc: None, original_email_from: None):
    """
    Collect the updated email fields and store in the context key EmailCommunication as metadata
    Args:
        email_related_incident: The incident ID of the original incident to store topic
        email_subject: The email subject
        email_from: The email of the user
        email_to: The email to fields value from the replied email from user
        email_content: The email content
        message_id: The message id that can be used to reply-mail
        email_cc: The email CC
        original_email_from: Email from field of the original incident, which is the email address 
        configured on XSOAR integration
    """
    inc = demisto.incidents()[0]['CustomFields']
    # Add new topic to the topic list if this is the new email
    email_topics = []
    if "emailtopicslist" in inc:
        email_topics = inc.get('emailtopicslist')

    if email_subject not in email_topics:
        email_topics.append(email_subject)

    # Remove XSOAR integration email and add sender's email to email_to metadata to prepare for email reply
    # The email to in XSOAR will be: email from user + email to that remove the email XSOAR uses
    if original_email_from:
        email_to_list = email_to.split(",")
        email_to_list.remove(original_email_from)
        new_email_to = email_from + "," + ",".join(email_to_list) if email_to_list else email_from
    else:
        new_email_to = email_from + "," + email_to

    # Store the data in the target incident
    metadata_key = "EmailCommunication." + generate_email_topic(email_subject)
    metadata_value = {
        "to": new_email_to,
        "cc": email_cc,
        "subject": email_subject,
        "content": email_content,
        "team": '',
        "message_id": message_id
    }
    demisto.executeCommand("executeCommandAt",
                        {'command': 'Set', 'incidents': email_related_incident,
                        'arguments': {'key': metadata_key, 'value': metadata_value}})

    demisto.executeCommand("setIncident", {"emailtopicslist": email_topics})


# Remove the [.] character in the email_subject to support using it as context key
def generate_email_topic(email_subject):
    email_topic = email_subject.replace(".","[dot]").replace(" ","_") if email_subject \
        else ""
    return email_topic


def get_email_topic_from_subject(email_subject):
    """
    Get email topic from subject. The subject format for normal incident will be 
    [SOC #<incident-id>] <email-topic>
    Args:
        email_subject: raw email subject from email
    Returns:
        email_related_incident: the incident ID that which starts the conversation
        email_topic: the email topic extracted from email_subject

    """
    # Extract ID and Topic from subject
    get_incident_id = re.findall("(?<=\[SOC #)\d+(?=\])",email_subject)
    get_email_ask_user_incident_id = re.findall("(?<=- #)\d+",email_subject)

    if get_email_ask_user_incident_id: # Email reply is from EmailAskUser flow
        demisto.debug("EmailAskUser flow processing")
        email_related_incident = get_email_ask_user_incident_id[0]  # Get incident ID from email subject
        get_email_topic = re.findall("[^(Re: )].+(?= - #)", email_subject)  # Get topic from email subject
        

    else: # Normal email reply or new email incident
        demisto.debug("Normal email flow processing")
        email_related_incident = get_incident_id[0] if get_incident_id else None  # Get incident ID from email subject
        get_email_topic = re.findall("(?<=\] ).+", email_subject)  # Get topic from email subject

    email_topic = get_email_topic[0] if get_email_topic else None
    
    return email_related_incident, email_topic


def main():
    incident = demisto.incident()
    new_incident_id = incident.get('id')
    custom_fields = incident.get('CustomFields')
    current_time = str(incident.get('occurred'))
    email_from = custom_fields.get('emailfrom')
    email_cc = custom_fields.get('emailcc')
    email_to = custom_fields.get('emailto')
    email_subject = custom_fields.get('emailsubject')
    email_html = custom_fields.get('emailhtml')
    attachments = incident.get('attachment', [])
    original_email_from = '' # Email from field of the original incident, which is the email address configured on XSOAR integration

    # Extract ID and Topic from subject
    email_related_incident, email_topic = get_email_topic_from_subject(email_subject)

    # Create email content to store and display
    email_reply = set_email_reply(email_from, email_to, email_cc, email_html, attachments, current_time, email_topic)

    # Get attachment and return message_id
    message_id = get_attachments_using_instance(email_related_incident, incident.get('labels'))

    # Search for current incident with incident ID in the subject
    query = f"id:{email_related_incident}"
    incident_details = get_incident_by_query(query)[0] if email_related_incident else None

    if incident_details: # If incident found, then store email reply to that incident
        # Store email metadata to context
        original_email_from = incident_details.get('CustomFields').get('emailfrom')
        store_topics(email_related_incident, email_topic, email_from, email_to, email_reply, message_id, email_cc, original_email_from)
        # Add entry to war room and tag it with email topic. The entry will contain email message
        add_entries(email_reply, email_related_incident, email_topic)

        # If the user is currently viewing the topic, then push the message directly to emailhtml field
        # on the layout so the analyst can see it immediately.
        if incident_details.get('CustomFields').get('emailtopic') == email_topic:
            demisto.executeCommand('setIncident', {
                'id': email_related_incident,
                'customFields': {
                    'emailshowtrigger': str(random.randrange(1, 999)) + f"#{email_topic}#&{email_to}#&{email_cc}#&{email_from}#&{message_id}#&{original_email_from}"
                }
            })
        
        # If this is newly send-in email, not initiated from XSOAR then add this new 
        # topic to topic list
        email_topics_list = incident_details.get('CustomFields').get('emailtopicslist')
        if email_topics_list:
            if email_topic not in email_topics_list:
                email_topics_list.append(email_topic)
                demisto.executeCommand('setIncident', {
                    'id': email_related_incident,
                    'customFields': {
                        'emailtopicslist': email_topics_list
                    }
                })

        # To drop and link data to current incident ID
        demisto.debug("Found incident")
        demisto.results(False)

    else: # If no incident found, then create new incident then store information
        # Create new incident and set information
        # Display information to Email layout
        title_html = "<h2>" + email_subject + "</h2><br>"
        demisto.executeCommand('setIncident',
        {
            'id': new_incident_id,
            'customFields': {
                'emailthreadhtml': title_html + email_reply,
                'emailtopic': email_subject
            }
        }),
        # Store email as war room entry
        add_entries(email_reply, new_incident_id, email_subject)
        # Store email metadata to context
        store_topics(email_related_incident, email_subject, email_from, email_to, email_reply, message_id, email_cc)
        # To create new email incident
        demisto.debug("Not found incident")
        demisto.results(True)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()