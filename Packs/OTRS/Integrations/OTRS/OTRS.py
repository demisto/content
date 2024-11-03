import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''


import urllib3
from pyotrs import Article, Attachment, Client, DynamicField, Ticket
from urllib.parse import unquote
from typing import Any
from collections.abc import Callable


# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

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
    return state_dict.get(state, state)


def translate_priority(priority: str):
    priority_dict = {
        '1VeryLow': '1 very low',
        '2Low': '2 low',
        '3Normal': '3 normal',
        '4High': '4 high',
        '5VeryHigh': '5 very high'
    }
    return priority_dict.get(priority, priority)


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


def get_mirroring():
    """
    Get tickets mirroring.
    """
    params = demisto.params()

    return {
        'mirror_direction': MIRROR_DIRECTION.get(params.get('mirror_direction')),
        'mirror_tags': [
            params.get('tag'),  # tag to otrs
        ],
        'mirror_instance': demisto.integrationInstance()
    }


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
                      priority: list[Any] | None = None, ticket_type: str | None = None,
                      article_create_time_newer_minutes: int | None = None, pattern: str | None = None):
        args = {'States': states,
                'TicketCreateTimeOlderDate': created_before,
                'TicketCreateTimeNewerDate': created_after,
                'Title': title,
                'Queues': queue,
                'Priorities': priority,
                'Types': ticket_type,
                'ArticleCreateTimeNewerMinutes': article_create_time_newer_minutes}

        if pattern:
            args["FullTextIndex"] = "1"
            args["ContentSearch"] = "OR"
            args["MIMEBase_Body"] = f"%{pattern}%"
            args["MIMEBase_Subject"] = f"%{pattern}%"

        return self.execute_otrs_method(self.client.ticket_search, args)

    def create_ticket(self, new_ticket: Ticket, article: Article | None, df: list[Any] | None, attachments: list[Any] | None):
        args = {'ticket': new_ticket, 'article': article, 'dynamic_fields': df, 'attachments': attachments}
        return self.execute_otrs_method(self.client.ticket_create, args)

    def update_ticket(self, ticket_id: str, title: str | None = None, queue: str | None = None, state: str | None = None,
                      priority: str | None = None, article: Article | None = None, ticket_type: str | None = None,
                      df: list[Any] | None = None, attachments: list[Any] | None = None, owner: str | None = None,
                      customer_user: str | None = None, lock: str | None = None):
        args = {
            'ticket_id': ticket_id,
            'Title': title,
            'Queue': queue,
            'State': state,
            'Priority': priority,
            'article': article,
            'dynamic_fields': df,
            'attachments': attachments,
            'Owner': owner,
            'CustomerUser': customer_user,
            'Type': ticket_type,
            'Lock': lock
        }
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
                    attachments_str += f'Name: {file_name}, Size: {file_size}, ContentType: {content_type}'
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
            outputs_key_field="ID",
            readable_output=human_readable,
            raw_response=ticket
        )
    )

    return attachments_list


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
    pattern = args.get("pattern")

    tickets = client.search_ticket(states, created_before, created_after, title, queue, priority, ticket_type, pattern=pattern)

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

        return CommandResults(
            outputs=output,
            outputs_prefix="OTRS.Ticket",
            outputs_key_field="ID",
            readable_output=tableToMarkdown(title, output, headers),
            raw_response=raw_output
        )
    else:
        return 'No results found'


def create_ticket_command(client: Client, args: dict[str, str]):

    title = args.get('title')
    queue = args.get('queue')
    state = translate_state(args['state'])
    priority = translate_priority(args['priority'])
    customer_user = args.get('customer_user')
    owner = args.get("owner")
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

    new_ticket = Ticket(
        {
            "Title": title,
            "Queue": queue,
            "State": state,
            "Priority": priority,
            "CustomerUser": customer_user,
            "Type": ticket_type,
            "Owner": owner
        }
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

    return CommandResults(
        outputs=context,
        outputs_prefix="OTRS.Ticket",
        outputs_key_field="ID",
        readable_output=output,
        raw_response=context
    )


def update_ticket_command(client: Client, args: dict[str, str]):

    ticket_id = args.get('ticket_id')
    title = args.get('title')
    queue = args.get('queue')
    state = args.get('state')
    owner = args.get("owner")
    lock = args.get("lock", "").lower() if args.get("lock", "").lower() in ["lock", "unlock"] else None
    customer_user = args.get("customer_user")
    priority = args.get('priority')
    article_subject = args.get('article_subject')
    article_body = args.get('article_body')
    ticket_type = args.get('type')
    dynamic_fields = args.get('dynamic_fields')
    attachment = args.get('attachment')

    if all(v is None for v in [title, queue, state, priority, article_subject,
                               article_body, ticket_type, dynamic_fields, attachment,
                               owner, customer_user]):
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

    ticket = client.update_ticket(ticket_id, title, queue, state, priority, article, ticket_type, df, attachments, owner=owner,
                                  customer_user=customer_user, lock=lock)

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

    return CommandResults(
        outputs=context,
        outputs_prefix="OTRS.Ticket",
        outputs_key_field=["ID"],
        readable_output=output,
        raw_response=context
    )


def close_ticket_command(client: Client, args: dict[str, str]):

    ticket_id = args.get('ticket_id')
    article_subject = args.get('article_subject')
    article_body = args.get('article_body')
    state = args.get('state', 'closed successful')

    article_object = {
        'Subject': article_subject,
        'Body': article_body
    }

    article = Article(article_object)

    ticket = client.update_ticket(ticket_id, article=article, state=state)

    context = {
        'ID': ticket['TicketID'],
        'State': state,
        'Article': article_object
    }
    output = 'Closed ticket {} successfully'.format(ticket['TicketID'])

    return CommandResults(
        outputs=context,
        outputs_prefix="OTRS.Ticket",
        outputs_key_field=["ID"],
        readable_output=output,
        raw_response=context
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
        ticket.update(get_mirroring())
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


def get_remote_data_command(client: Client, args: dict[str, str]):
    params = demisto.params()
    ticket_id = args.get("id")
    headers = ["ArticleID", "To", "Cc", "Subject", "CreateTime", "From", "ContentType", "Body"]
    demisto.debug(f"Getting update for remote {ticket_id}")
    if args.get("lastUpdate"):
        last_update = round(
            datetime.strptime(
                args["lastUpdate"].split(".")[0], "%Y-%m-%dT%H:%M:%S"
            ).timestamp()
        )
    else:
        last_update = 0
    retry_count = 3

    demisto.debug(f"last_update is {last_update}")

    while retry_count:
        ticket = client.get_ticket(ticket_id)
        if not ticket:
            demisto.debug(f"Ticket with id {ticket_id} was not found.")
            retry_count -= 1
        else:
            break
    if ticket:
        ticket_last_update = ticket["UnlockTimeout"]
        entries = []

        if last_update > ticket_last_update:
            demisto.debug(f"Nothing new in the ticket since {last_update}")
            ticket = {}
        else:
            demisto.debug(f"ticket is updated: {ticket}")
            # get latest comments and files
            articles = ticket.get("Article")
            if articles:
                for article in articles:

                    # Get article details
                    description = tableToMarkdown("OTRS Mirroring Update", article, headers=headers, removeNull=True)

                    if article["IncomingTime"] > last_update:
                        entries.append({
                            'Type': EntryType.NOTE,
                            'Contents': description,
                            'ContentsFormat': EntryFormat.MARKDOWN,
                            'Tags': [params.get('tag_from_otrs', "FromOTRS")],  # the list of tags to add to the entry
                            'Note': False  # boolean, True for Note, False otherwise
                        })
                        if article.get('Attachment'):
                            for attachment in article.get('Attachment'):
                                file = fileResult(attachment['Filename'], base64.b64decode(attachment['Content']))
                                file["Tags"] = [params.get('tag_from_otrs')]
                                entries.append(file)

        return GetRemoteDataResponse(ticket, entries)
    else:
        return None


def update_remote_system_command(client: Client, args: dict[str, str]):
    parsed_args = UpdateRemoteSystemArgs(args)
    demisto.debug(
        f"Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system\n"
    )
    ticket_id: str = parsed_args.remote_incident_id

    if parsed_args.delta:
        demisto.debug(f"Got the following delta keys {list(parsed_args.delta.keys())}")

    if parsed_args.entries:
        for entry in parsed_args.entries:
            demisto.debug(f'Sending entry {entry.get("id")}')
            article_object = {
                "Subject": "Update from Cortex XSOAR",
                "Body": "File from XSOAR" if entry.get("file") else str(entry.get("contents", "")),
            }

            article = Article(article_object)
            if entry.get("file"):
                file_path = demisto.getFilePath(entry.get("id"))
                with open(file_path['path'], 'rb') as file_content:
                    encoded_file = base64.b64encode(file_content.read()).decode('utf-8')  # Encoding file content in base64,
                    # as required by OTRS and then decode it as mentioned in https://gitlab.com/rhab/PyOTRS/-/issues/18

                otrs_attachment = Attachment.create_basic(  # Creating OTRS attachment object
                    Filename=file_path['name'],
                    Content=encoded_file,
                    ContentType=entry['fileMetadata']['type']
                )
                client.update_ticket(ticket_id, article=article, attachments=[otrs_attachment])
            else:
                client.update_ticket(ticket_id, article=article)

    # Close incident if relevant
    demisto.debug(f"Incident Status {parsed_args.inc_status}")
    if parsed_args.inc_status == 2:
        demisto.debug(f"Sending closure message to remote incident {ticket_id}")
        article_object = {
            "Subject": "Cortex XSOAR Alert closed - " + parsed_args.data.get("closeReason"),
            "Body": parsed_args.data.get("closeNotes"),
        }
        article = Article(article_object)
        client.update_ticket(ticket_id, article=article)

    return ticket_id


def get_modified_remote_data_command(client: Client, args: dict[str, str]):
    demisto.debug('Performing get-modified-remote-data command for last 5 minutes.')

    raw_incidents = client.search_ticket(article_create_time_newer_minutes=5)

    demisto.debug(f"raw tickets: {raw_incidents}")

    return GetModifiedRemoteDataResponse(raw_incidents)


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

    demisto.info(f'command is {demisto.command()}')

    commands = {
        'otrs-get-ticket': get_ticket_command,
        'otrs-search-ticket': search_ticket_command,
        'otrs-create-ticket': create_ticket_command,
        'otrs-update-ticket': update_ticket_command,
        'otrs-close-ticket': close_ticket_command,
        'get-remote-data': get_remote_data_command,
        'update-remote-system': update_remote_system_command,
        'get-modified-remote-data': get_modified_remote_data_command
    }

    try:
        if demisto.command() == 'test-module':
            # Testing connectivity and credentials
            return_results('ok')

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(otrs_client, fetch_queue, fetch_priority, fetch_time, look_back_days)

        elif demisto.command() in commands:
            return_results(commands[demisto.command()](otrs_client, args))

        else:
            raise NotImplementedError(f'Command not implemented: {demisto.command()}')

    except Exception as e:
        demisto.info(str(e))
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
