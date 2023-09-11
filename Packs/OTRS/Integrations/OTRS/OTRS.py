''' IMPORTS '''

from CommonServerPython import *
import urllib3
from pyotrs import Article, Attachment, Client, DynamicField, Ticket
from urllib.parse import unquote
from typing import Any, Callable


# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''


''' HELPER FUNCTIONS '''


def ticket_to_incident(ticket: dict[str, Any]):

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


def translate_state(state: str):
    state_dict = {
        'ClosedSuccessful': 'closed successful',
        'ClosedUnsuccessful': 'closed unsuccessful',
        'Open': 'open',
        'PendingReminder': 'pending reminder',
        'New': 'new'
    }
    return state_dict[state]


def translate_priority(priority: str):
    priority_dict = {
        '1VeryLow': '1 very low',
        '2Low': '2 low',
        '3Normal': '3 normal',
        '4High': '4 high',
        '5VeryHigh': '5 very high'
    }
    return priority_dict[priority]


def calculate_age(seconds: int):
    """
    Convert seconds to time period string
    e.g. 6000 -> 1 h 40 m
    """
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return '%d h %02d m' % (h, m)


def demisto_entry_to_otrs_attachment(entry_list: list[Any]):
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
            raise Exception('Could not find file in context')
        otrs_attachment = Attachment.create_basic(  # Creating OTRS attachment object
            Filename=file_path['name'],
            Content=encoded_file,
            ContentType=content_type
        )
        attachments.append(otrs_attachment)
    return attachments


''' CLASS '''


class OTRSClient:
    def __init__(self, base_url: str, username: str, password: str, https_verify: bool, use_legacy_sessions: bool):
        self.client = Client(base_url, username, password, https_verify=https_verify, use_legacy_sessions=use_legacy_sessions)
        cache = demisto.getIntegrationContext()
        # OTRS creates new session for each request, to avoid that behavior -
        # save the sessionId in integration context to use it multiple times
        if cache.get('SessionID'):
            self.client.session_id_store.write(cache['SessionID'])
        else:
            self.update_session()

    def get_ticket(self, ticket_id: str):
        args = {'ticket_id': ticket_id, 'articles': True, 'attachments': True, 'dynamic_fields': True}
        response = self.execute_otrs_method(self.client.ticket_get_by_id, args)
        raw_ticket = response.to_dct()['Ticket']
        return raw_ticket

    def get_ticket_by_number(self, ticket_number: str):
        args = {'ticket_number': ticket_number, 'articles': True, 'attachments': True, 'dynamic_fields': True}
        response = self.execute_otrs_method(self.client.ticket_get_by_number, args)
        raw_ticket = response.to_dct().get('Ticket')
        return raw_ticket

    def search_ticket(self, states: list[Any] | None = None, created_before: datetime | None = None,
                      created_after: datetime | None = None, title: str | None = None, queue: list[Any] | None = None,
                      priority: list[Any] | None = None, ticket_type: str | None = None):
        args = {'States': states,
                'TicketCreateTimeOlderDate': created_before,
                'TicketCreateTimeNewerDate': created_after,
                'Title': title,
                'Queues': queue,
                'Priorities': priority,
                'Types': ticket_type}
        return self.execute_otrs_method(self.client.ticket_search, args)

    def create_ticket(self, new_ticket: Ticket, article: Article | None, df: list[Any] | None, attachments: list[Any] | None):
        args = {'ticket': new_ticket, 'article': article, 'dynamic_fields': df, 'attachments': attachments}
        return self.execute_otrs_method(self.client.ticket_create, args)

    def update_ticket(self, ticket_id: str, title: str | None = None, queue: str | None = None, state: str | None = None,
                      priority: str | None = None, article: Article | None = None, ticket_type: str | None = None,
                      df: list[Any] | None = None, attachments: list[Any] | None = None):
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
        return self.execute_otrs_method(self.client.ticket_update, args)

    def update_session(self):
        self.client.session_create()
        sessionID = self.client.session_id_store.value
        demisto.setIntegrationContext({'SessionID': sessionID})
        self.client.session_id_store.write(sessionID)

    def execute_otrs_method(self, method: Callable[..., Any], args: dict[str, Any]):
        try:
            response = method(**args)
        except Exception:
            self.update_session()
            response = method(**args)
        return response


''' FUNCTIONS '''


def get_ticket_command(client: Client, args: dict[str, str]):

    ticket_id = args.get('ticket_id')
    ticket_number = args.get('ticket_number')

    if (ticket_id and ticket_number is None):
        ticket = client.get_ticket(ticket_id)
    elif (ticket_id is None and ticket_number):
        ticket = client.get_ticket_by_number(ticket_number)
    else:
        raise Exception('Exactly one ticket identifier is required in order to retrieve a ticket, ticket_id or ticket_number!')

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

    return_results(
        CommandResults(
            outputs=output,
            outputs_prefix="OTRS.Ticket",
            outputs_key_field=["ID"],
            readable_output=human_readable,
            raw_response=ticket
        )
    )

    return_results(attachments_list)


def search_ticket_command(client: Client, args: dict[str, str]):

    states = args.get('state')
    if states:
        states = argToList(states)
    created_before = args.get('created_before')
    if created_before:
        created_before, _ = parse_date_range(created_before)
    created_after = args.get('created_after')
    if created_after:
        created_after, _ = parse_date_range(created_after)
    title = args.get('title')
    queue = args.get('queue')
    if queue:
        queue = argToList(queue)
    priority: list[Any] | None = None
    if args.get('priority'):
        priority_list: list[str] = argToList(args.get('priority'))
        priority = [translate_priority(p) for p in priority_list]
    ticket_type = args.get('type')

    tickets = client.search_ticket(states, created_before, created_after, title, queue, priority, ticket_type)

    if tickets:
        output = []
        raw_output = []
        for ticket_id in tickets:
            raw_ticket = client.get_ticket(ticket_id)
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
            raw_output.append(raw_ticket)

        title = 'OTRS Search Results'
        headers = ['ID', 'Number', 'Title', 'Type', 'State', 'Priority', 'Queue', 'Created', 'Owner']

        return_results(
            CommandResults(
                outputs=output,
                outputs_prefix="OTRS.Ticket",
                outputs_key_field=["ID"],
                readable_output=tableToMarkdown(title, output, headers),
                raw_response=raw_output
            )
        )
    else:
        return_results('No results found')


def create_ticket_command(client: Client, args: dict[str, str]):

    title = args.get('title')
    queue = args.get('queue')
    state = translate_state(args['state'])
    priority = translate_priority(args['priority'])
    customer_user = args.get('customer_user')
    article_subject = args.get('article_subject')
    article_body = args.get('article_body')
    ticket_type = args.get('type')
    dynamic_fields = args.get('dynamic_fields')
    attachment = args.get('attachment')

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

    ticket = client.create_ticket(new_ticket, article, df, attachments)

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

    output = 'Created ticket {} successfully'.format(ticket['TicketID'])

    return_results(
        CommandResults(
            outputs=context,
            outputs_prefix="OTRS.Ticket",
            outputs_key_field=["ID"],
            readable_output=output,
            raw_response=context
        )
    )


def update_ticket_command(client: Client, args: dict[str, str]):

    ticket_id = args.get('ticket_id')
    title = args.get('title')
    queue = args.get('queue')
    state = args.get('state')
    priority = args.get('priority')
    article_subject = args.get('article_subject')
    article_body = args.get('article_body')
    ticket_type = args.get('type')
    dynamic_fields = args.get('dynamic_fields')
    attachment = args.get('attachment')

    if all(v is None for v in [title, queue, state, priority, article_subject,
                               article_body, ticket_type, dynamic_fields, attachment]):
        raise Exception('No fields to update were given')

    if (article_subject and article_body is None) or (article_subject is None and article_body):
        raise Exception('Both article subject and body are required in order to add article')
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

    ticket = client.update_ticket(ticket_id, title, queue, state, priority, article, ticket_type, df, attachments)

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
    output = 'Updated ticket {} successfully'.format(ticket['TicketID'])

    return_results(
        CommandResults(
            outputs=context,
            outputs_prefix="OTRS.Ticket",
            outputs_key_field=["ID"],
            readable_output=output,
            raw_response=context
        )
    )


def close_ticket_command(client: Client, args: dict[str, str]):

    ticket_id = args.get('ticket_id')
    article_subject = args.get('article_subject')
    article_body = args.get('article_body')

    article_object = {
        'Subject': article_subject,
        'Body': article_body
    }

    article = Article(article_object)

    ticket = client.update_ticket(ticket_id, article=article, state='closed successful')

    context = {
        'ID': ticket['TicketID'],
        'State': 'closed successful',
        'Article': article_object
    }
    output = 'Closed ticket {} successfully'.format(ticket['TicketID'])

    return_results(
        CommandResults(
            outputs=context,
            outputs_prefix="OTRS.Ticket",
            outputs_key_field=["ID"],
            readable_output=output,
            raw_response=context
        )
    )


def fetch_incidents(client: Client, fetch_queue: str, fetch_priority: str, fetch_time: str, look_back_days: int):
    last_run_obj = demisto.getLastRun()
    last_run_time = last_run_obj.get('time')
    is_first_fetch = last_run_time is None
    last_fetched_ids = last_run_obj.get('last_fetched_ids', [])

    if is_first_fetch:
        last_run_time, _ = parse_date_range(fetch_time)
    else:
        last_run_time = datetime.strptime(last_run_time, '%Y-%m-%d %H:%M:%S') + timedelta(seconds=1)

    # in case that a specific queue is provided - we also look back in the search to find incidents created before the last run
    # but moved to the queue after the fetch and the fetch missed them.
    # the looked_back_last_run will be used only for search,
    # while in demisto.setLastRun the original last_run will be saved if no incident fetched.
    looked_back_last_run = last_run_time
    queue = None if 'Any' in fetch_queue else argToList(fetch_queue)
    if queue and not is_first_fetch:
        looked_back_last_run -= timedelta(days=look_back_days)

    demisto.debug(f'the base time will be used in search: {datetime.strftime(looked_back_last_run, "%Y-%m-%d %H:%M:%S")}')

    priority = None
    if fetch_priority:
        priority = [translate_priority(p) for p in fetch_priority]

    raw_tickets = client.search_ticket(created_after=looked_back_last_run, queue=queue, priority=priority)
    tickets = [ticket_id for ticket_id in raw_tickets if ticket_id not in last_fetched_ids]
    demisto.debug(f'filter out {len(raw_tickets) - len(tickets)} already fetched tickets')
    incidents = []

    first_ticket = True
    last_created = ''

    for ticket_id in tickets:
        ticket = client.get_ticket(ticket_id)
        incident = ticket_to_incident(ticket)
        incidents.append(incident)
        if first_ticket:
            # First ticket fetched is the last created, so should set its creation time as last fetched ticket
            last_created = ticket['Created']
            first_ticket = False

    demisto.incidents(incidents)

    if not last_created:
        last_created = datetime.strftime(last_run_time, '%Y-%m-%d %H:%M:%S')

    demisto.setLastRun({'time': last_created, 'last_fetched_ids': raw_tickets})


def main():
    params = demisto.params()
    base_url = params.get('server', '').strip('/')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    use_legacy_sessions = argToBoolean(params.get('use_legacy_sessions', False))
    verify = not params.get('unsecure', False)
    fetch_queue = params.get('fetch_queue', 'Any')
    fetch_priority = params.get('fetch_priority')
    fetch_time_default = '3 days'
    fetch_time = params.get('fetch_time', fetch_time_default)
    fetch_time = fetch_time if fetch_time and fetch_time.strip() else fetch_time_default
    look_back_days = int(params.get('look_back', 1))
    handle_proxy(params.get('proxy'))

    otrs_client = OTRSClient(base_url, username, password, https_verify=verify, use_legacy_sessions=use_legacy_sessions)

    args = demisto.args()

    LOG('command is %s' % (demisto.command(), ))

    try:
        if demisto.command() == 'test-module':
            # Testing connectivity and credentials
            return_results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(otrs_client, fetch_queue, fetch_priority, fetch_time, look_back_days)

        elif demisto.command() == 'otrs-get-ticket':
            get_ticket_command(otrs_client, args)

        elif demisto.command() == 'otrs-search-ticket':
            search_ticket_command(otrs_client, args)

        elif demisto.command() == 'otrs-create-ticket':
            create_ticket_command(otrs_client, args)

        elif demisto.command() == 'otrs-update-ticket':
            update_ticket_command(otrs_client, args)

        elif demisto.command() == 'otrs-close-ticket':
            close_ticket_command(otrs_client, args)
        else:
            raise NotImplementedError(f'Command not implemented: {demisto.command()}')

    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
