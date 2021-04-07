''' IMPORTS '''

from CommonServerPython import *
import urllib3
from pyotrs import Article, Attachment, Client, DynamicField, Ticket
from urllib.parse import unquote


# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''

SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
USE_SSL = not demisto.params().get('unsecure', False)
FETCH_QUEUE = demisto.params().get('fetch_queue', 'Any')
FETCH_PRIORITY = demisto.params().get('fetch_priority')
FETCH_TIME_DEFAULT = '3 days'
FETCH_TIME = demisto.params().get('fetch_time', FETCH_TIME_DEFAULT)
FETCH_TIME = FETCH_TIME if FETCH_TIME and FETCH_TIME.strip() else FETCH_TIME_DEFAULT
otrs_client = None  # type: Client


''' HELPER FUNCTIONS '''


def ticket_to_incident(ticket):

    attachments_list = []
    articles = ticket.get('Article')
    if articles:
        for article in articles:
            attachments = article.get('Attachment')
            if attachments:
                for attachment in attachments:
                    file_name = attachment['Filename']
                    attachment_file = fileResult(file_name, base64.b64decode(attachment['Content']))
                    attachments_list.append({
                        'path': attachment_file['FileID'],
                        'name': file_name
                    })

    incident = {
        'attachment': attachments_list,
        'rawJSON': unquote(json.dumps(ticket)),
        'name': 'OTRS ticket {}'.format(ticket['TicketID'])
    }
    return incident


def translate_state(state):
    state_dict = {
        'ClosedSuccessful': 'closed successful',
        'ClosedUnsuccessful': 'closed unsuccessful',
        'Open': 'open',
        'PendingReminder': 'pending reminder',
        'New': 'new'
    }
    return state_dict[state]


def translate_priority(priority):
    priority_dict = {
        '1VeryLow': '1 very low',
        '2Low': '2 low',
        '3Normal': '3 normal',
        '4High': '4 high',
        '5VeryHigh': '5 very high'
    }
    return priority_dict[priority]


def calculate_age(seconds):
    """
    Convert seconds to time period string
    e.g. 6000 -> 1 h 40 m
    """
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return '%d h %02d m' % (h, m)


def demisto_entry_to_otrs_attachment(entry_list):
    """
    Convert Demisto file entry to OTRS attachment object
    """
    attachments = []
    for file in entry_list:
        file_path = demisto.getFilePath(file)
        with open(file_path['path'], 'rb') as file_content:
            encoded_file = base64.b64encode(file_content.read()).decode('utf-8')  # Encoding file content in base64,
            # as required by OTRS and then decode it as mentioned in https://gitlab.com/rhab/PyOTRS/-/issues/18

        # Getting file type from context
        context_files = demisto.get(demisto.context(), 'File')
        if isinstance(context_files, dict):  # If there's only one file in context, we will get a dict and we convert it to list
            context_files = [context_files]
        content_type = None
        for context_file in context_files:  # Looking for file entry in context
            if context_file['EntryID'] == file:
                content_type = context_file['Info']
                break
        if content_type is None:
            return_error('Could not find file in context')
        otrs_attachment = Attachment.create_basic(  # Creating OTRS attachment object
            Filename=file_path['name'],
            Content=encoded_file,
            ContentType=content_type
        )
        attachments.append(otrs_attachment)
    return attachments


''' FUNCTIONS '''


def get_ticket_command():

    ticket_id = demisto.args().get('ticket_id')
    ticket_number = demisto.args().get('ticket_number')

    if (ticket_id and ticket_number is None):
        ticket = get_ticket(ticket_id)
    elif (ticket_id is None and ticket_number):
        ticket = get_ticket_by_number(ticket_number)
    else:
        return_error('Exactly one ticket identifier is required in order to retrieve a ticket, ticket_id or ticket_number!')

    output = {
        'ID': str(ticket['TicketID']),
        'Number': ticket['TicketNumber'],
        'Created': ticket['Created'],
        'CustomerID': ticket['CustomerUserID'],
        'Owner': ticket['Owner'],
        'Priority': ticket['Priority'],
        'Queue': ticket['Queue'],
        'State': ticket['State'],
        'Title': ticket['Title'],
        'Type': ticket['Type'],
        'Lock': ticket['Lock'],
        'Age': calculate_age(ticket['Age'])
    }

    df = ticket.get('DynamicField')
    if df:
        output['DynamicField'] = {}
        for field in df:
            value = field['Value']
            if value:
                name = field['Name']
                output['DynamicField'][name] = value

    title = 'OTRS Ticket ' + str(ticket['TicketID'])
    headers = ['ID', 'Number', 'Age', 'Title', 'State', 'Lock', 'Queue',
               'Owner', 'CustomerID', 'Priority', 'Type', 'Created', 'DynamicField']
    human_readable = tableToMarkdown(title, output, headers=headers, removeNull=True)

    attachments_list = []
    articles = ticket.get('Article')
    if articles:
        articles_list = []
        human_readable_articles = []
        for article in articles:

            # Get article details
            current_article = {
                'ID': str(article['ArticleID']),
                'Subject': article.get('Subject'),
                'Body': article.get('Body'),
                'CreateTime': article.get('CreateTime'),
                'From': article.get('From'),
                'ContentType': article.get('ContentType')
            }
            currect_human_readable_article = dict(current_article)

            # Get attachments
            attachments = article.get('Attachment')
            if attachments:

                attachments_output = []
                attachments_str = ''
                for attachment in attachments:
                    file_name = attachment['Filename']
                    file_size = attachment['FilesizeRaw']
                    content_type = attachment['ContentType']
                    current_attachment = {
                        'Name': file_name,
                        'Size': file_size,
                        'ContentType': content_type
                    }
                    attachments_str += 'Name: {0}, Size: {1}, ContentType: {2}'.format(file_name, file_size, content_type)
                    attachments_str += '\n\n'
                    attachments_list.append(fileResult(file_name, base64.b64decode(attachment['Content'])))
                    attachments_output.append(current_attachment)
                currect_human_readable_article['Attachment'] = attachments_str
                current_article['Attachment'] = attachments_output

            human_readable_articles.append(currect_human_readable_article)
            articles_list.append(current_article)

        human_readable += tableToMarkdown('Articles', human_readable_articles,
                                          headers=['ID', 'From', 'Subject', 'Body', 'CreateTime',
                                                   'ContentType', 'Attachment'], removeNull=True)
        output['Article'] = articles_list

    ec = {
        'OTRS.Ticket(val.ID===obj.ID)': output
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': ticket,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': ec
    })

    demisto.results(attachments_list)


def get_ticket(ticket_id):
    args = {'ticket_id': ticket_id, 'articles': True, 'attachments': True, 'dynamic_fields': True}
    response = execute_otrs_method(otrs_client.ticket_get_by_id, args)
    raw_ticket = response.to_dct()['Ticket']
    return raw_ticket


def get_ticket_by_number(ticket_number):
    args = {'ticket_number': ticket_number, 'articles': True, 'attachments': True, 'dynamic_fields': True}
    response = execute_otrs_method(otrs_client.ticket_get_by_number, args)
    raw_ticket = response.to_dct().get('Ticket')
    return raw_ticket


def search_ticket_command():

    states = demisto.args().get('state')
    if states:
        states = argToList(states)
    created_before = demisto.args().get('created_before')
    if created_before:
        created_before, _ = parse_date_range(created_before)
    created_after = demisto.args().get('created_after')
    if created_after:
        created_after, _ = parse_date_range(created_after)
    title = demisto.args().get('title')
    queue = demisto.args().get('queue')
    if queue:
        queue = argToList(queue)
    priority = demisto.args().get('priority')
    if priority:
        priority_list = argToList(priority)
        priority = [translate_priority(p) for p in priority_list]
    ticket_type = demisto.args().get('type')

    tickets = search_ticket(states, created_before, created_after, title, queue, priority, ticket_type)

    if tickets:
        output = []
        for ticket_id in tickets:
            raw_ticket = get_ticket(ticket_id)
            ticket = {
                'ID': str(raw_ticket['TicketID']),
                'Number': raw_ticket['TicketNumber'],
                'Created': raw_ticket['Created'],
                'Owner': raw_ticket['Owner'],
                'Priority': raw_ticket['Priority'],
                'Queue': raw_ticket['Queue'],
                'State': raw_ticket['State'],
                'Title': raw_ticket['Title'],
                'Type': raw_ticket['Type']
            }
            output.append(ticket)
        ec = {
            'OTRS.Ticket(val.ID===obj.ID)': output
        }
        title = 'OTRS Search Results'
        headers = ['ID', 'Number', 'Title', 'Type', 'State', 'Priority', 'Queue', 'Created', 'Owner']

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': raw_ticket,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, output, headers),
            'EntryContext': ec
        })
    else:
        demisto.results('No results found')


def search_ticket(states=None, created_before=None, created_after=None, title=None, queue=None, priority=None, ticket_type=None):
    args = {'States': states,
            'TicketCreateTimeOlderDate': created_before,
            'TicketCreateTimeNewerDate': created_after,
            'Title': title,
            'Queues': queue,
            'Priorities': priority,
            'Types': ticket_type}
    return execute_otrs_method(otrs_client.ticket_search, args)


def create_ticket_command():

    title = demisto.args().get('title')
    queue = demisto.args().get('queue')
    state = translate_state(demisto.args().get('state'))
    priority = translate_priority(demisto.args().get('priority'))
    customer_user = demisto.args().get('customer_user')
    article_subject = demisto.args().get('article_subject')
    article_body = demisto.args().get('article_body')
    ticket_type = demisto.args().get('type')
    dynamic_fields = demisto.args().get('dynamic_fields')
    attachment = demisto.args().get('attachment')

    df = []
    df_output = []
    if dynamic_fields:
        dynamic_fields_list = argToList(dynamic_fields)
        for field in dynamic_fields_list:
            splitted_field = field.split('=')
            current_field, current_value = splitted_field[0], splitted_field[1]
            df.append(DynamicField(current_field, current_value))
            df_output.append({current_field: current_value})

    attachments = []
    if attachment:
        attachments_list = argToList(attachment)
        attachments = demisto_entry_to_otrs_attachment(attachments_list)

    new_ticket = Ticket.create_basic(
        Title=title,
        Queue=queue,
        State=state,
        Priority=priority,
        CustomerUser=customer_user,
        Type=ticket_type
    )

    article = Article({
        'Subject': article_subject,
        'Body': article_body
    })

    ticket = create_ticket(new_ticket, article, df, attachments)

    context = {
        'ID': str(ticket['TicketID']),
        'Number': ticket['TicketNumber'],
        'CustomerUser': customer_user,
        'Priority': priority,
        'Queue': queue,
        'State': state,
        'Title': title,
        'Article': {
            'Subject': article_subject,
            'Body': article_body
        },
        'Type': ticket_type,
        'DynamicField': df_output
    }
    ec = {
        'OTRS.Ticket(val.ID===obj.ID)': context
    }
    output = 'Created ticket {} successfully'.format(ticket['TicketID'])

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': output,
        'EntryContext': ec
    })


def create_ticket(new_ticket, article, df, attachments):
    args = {'ticket': new_ticket, 'article': article, 'dynamic_fields': df, 'attachments': attachments}
    return execute_otrs_method(otrs_client.ticket_create, args)


def update_ticket_command():

    ticket_id = demisto.args().get('ticket_id')
    title = demisto.args().get('title')
    queue = demisto.args().get('queue')
    state = demisto.args().get('state')
    priority = demisto.args().get('priority')
    article_subject = demisto.args().get('article_subject')
    article_body = demisto.args().get('article_body')
    ticket_type = demisto.args().get('type')
    dynamic_fields = demisto.args().get('dynamic_fields')
    attachment = demisto.args().get('attachment')

    if all(v is None for v in [title, queue, state, priority, article_subject,
                               article_body, ticket_type, dynamic_fields, attachment]):
        return_error('No fields to update were given')

    if (article_subject and article_body is None) or (article_subject is None and article_body):
        return_error('Both article subject and body are required in order to add article')
    elif article_subject and article_body:
        article_obj = {
            'Subject': article_subject,
            'Body': article_body
        }
        article = Article(article_obj)
    else:
        article = None

    if state:
        state = translate_state(state)

    if priority:
        priority = translate_priority(priority)

    df = []
    if dynamic_fields:
        dynamic_fields_list = argToList(dynamic_fields)
        for field in dynamic_fields_list:
            splitted_field = field.split('=')
            current_field, current_value = splitted_field[0], splitted_field[1]
            df.append(DynamicField(current_field, current_value))

    attachments = []
    if attachment:
        attachments_list = argToList(attachment)
        attachments = demisto_entry_to_otrs_attachment(attachments_list)

    ticket = update_ticket(ticket_id, title, queue, state, priority, article, ticket_type, df, attachments)

    context = {
        'ID': ticket['TicketID'],
    }
    if priority:
        context['Priority'] = priority
    if queue:
        context['Queue'] = queue
    if state:
        context['State'] = state
    if title:
        context['Title'] = title
    if article:
        context['Article'] = article.to_dct()
    if ticket_type:
        context['Type'] = ticket_type
    ec = {
        'OTRS.Ticket(val.ID===obj.ID)': context
    }
    output = 'Updated ticket {} successfully'.format(ticket['TicketID'])

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': output,
        'EntryContext': ec
    })


def close_ticket_command():

    ticket_id = demisto.args().get('ticket_id')
    article_subject = demisto.args().get('article_subject')
    article_body = demisto.args().get('article_body')

    article_object = {
        'Subject': article_subject,
        'Body': article_body
    }

    article = Article(article_object)

    ticket = update_ticket(ticket_id, article=article, state='closed successful')

    context = {
        'ID': ticket['TicketID'],
        'State': 'closed successful',
        'Article': article_object
    }
    ec = {
        'OTRS.Ticket(val.ID===obj.ID)': context
    }
    output = 'Closed ticket {} successfully'.format(ticket['TicketID'])

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': output,
        'EntryContext': ec
    })


def update_ticket(ticket_id, title=None, queue=None, state=None, priority=None,
                  article=None, ticket_type=None, df=None, attachments=None):
    kwargs = {'Type': ticket_type}
    args = {'ticket_id': ticket_id,
            'Title': title,
            'Queue': queue,
            'State': state,
            'Priority': priority,
            'article': article,
            'dynamic_fields': df,
            'attachments': attachments,
            'kwargs': kwargs}
    return execute_otrs_method(otrs_client.ticket_update, args)


def fetch_incidents():
    last_run = demisto.getLastRun() and demisto.getLastRun()['time']
    if last_run:
        last_run = datetime.strptime(last_run, '%Y-%m-%d %H:%M:%S')
        last_run += timedelta(seconds=1)
    else:
        last_run, _ = parse_date_range(FETCH_TIME)

    queue_list = argToList(FETCH_QUEUE)
    if 'Any' in queue_list:
        queue = None
    else:
        queue = queue_list

    priority = None
    if FETCH_PRIORITY:
        priority = [translate_priority(p) for p in FETCH_PRIORITY]

    tickets = search_ticket(created_after=last_run, queue=queue, priority=priority)
    incidents = []

    first_ticket = True
    last_created = ''

    for ticket_id in tickets:
        ticket = get_ticket(ticket_id)
        incident = ticket_to_incident(ticket)
        incidents.append(incident)
        if first_ticket:
            # First ticket fetched is the last created, so should set its creation time as last fetched ticket
            last_created = ticket['Created']
            first_ticket = False

    demisto.incidents(incidents)

    if not last_created:
        last_created = datetime.strftime(last_run, '%Y-%m-%d %H:%M:%S')

    demisto.setLastRun({'time': last_created})


def update_session():
    otrs_client.session_create()
    sessionID = otrs_client.session_id_store.value
    demisto.setIntegrationContext({'SessionID': sessionID})
    otrs_client.session_id_store.write(sessionID)


def execute_otrs_method(method, args):
    try:
        response = method(**args)
    except Exception:
        update_session()
        response = method(**args)
    return response


def main():
    global otrs_client
    handle_proxy(demisto.params().get('proxy'))

    cache = demisto.getIntegrationContext()
    otrs_client = Client(SERVER, USERNAME, PASSWORD, https_verify=USE_SSL)

    # OTRS creates new session for each request, to avoid that behavior -
    # save the sessionId in integration context to use it multiple times
    if cache.get('SessionID'):
        otrs_client.session_id_store.write(cache['SessionID'])
    else:
        update_session()

    LOG('command is %s' % (demisto.command(), ))

    try:
        if demisto.command() == 'test-module':
            # Testing connectivity and credentials
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()

        elif demisto.command() == 'otrs-get-ticket':
            get_ticket_command()

        elif demisto.command() == 'otrs-search-ticket':
            search_ticket_command()

        elif demisto.command() == 'otrs-create-ticket':
            create_ticket_command()

        elif demisto.command() == 'otrs-update-ticket':
            update_ticket_command()

        elif demisto.command() == 'otrs-close-ticket':
            close_ticket_command()

    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
