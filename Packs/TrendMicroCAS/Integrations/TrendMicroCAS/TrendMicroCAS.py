import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser
import urllib3


import json
from typing import Any, Dict, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
MAX_INCIDENTS_TO_FETCH = 500

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client to use in the integration. Overrides BaseClient
    makes the connection to the trendMicro server
    """

    def security_events_list(self, service: str, event_type: str, start=None, end=None, limit=None) -> dict:
        """
        Handle security events request.
        Args:
            service(str): Name of the protected service whose logs you want to retrieve.
            event_type(str): Type of the security event whose logs you want to retrieve.
            start(str): Start time during which logs are to retrieve.
            end(str): End time during which logs are to retrieve.
            limit(str): Number of log items to display at a time.

        Returns:
            The security events response.
        """
        params = assign_params(service=service, event=event_type, start=start, end=end, limit=limit)
        result = self._http_request(
            method='GET',
            url_suffix='siem/security_events',
            params=params
        )
        return result

    def email_sweep(self, mailbox=None, lastndays=None, start=None, end=None, subject=None, file_sha1=None,
                    file_name=None, file_extension=None, url=None, sender=None, recipient=None, message_id=None,
                    source_ip=None, source_domain=None, limit=None) -> dict:
        """
        Handle email sweep request.
        Args:
            mailbox(str): Email address of the mailbox to search in.
            lastndays(str): Number of days (n × 24 hours) before the point of time when the request is sent.
            start(str): Start time which email message are to search.
            end(str): End time which email message are to search.
            limit(str): Number of email messages whose meta information is to display at a time.
            subject(str): Subject of email messages to search for To search for.
            file_sha1(str): SHA-1 hash value of the attachment file to search for.
            file_name(str): Name of the attachment file to search for.
            file_extension(str): Filename extension of attachment files to search for.
            url(str): URL in email body or attachments to search for.
            sender(str): Sender email address of email messages to search for.
            recipient(str): Recipient email address of email messages to search for.
            message_id(str): Internet message ID of the email message to search for.
            source_ip(str): Source IP address of email messages to search for.
            source_domain(str): Source domain of email messages to search for.

        Returns:
            The email sweep response.
        """
        params = assign_params(mailbox=mailbox, lastndays=lastndays, start=start, end=end, subject=subject,
                               file_sha1=file_sha1, file_name=file_name, file_extension=file_extension, url=url,
                               sender=sender, recipient=recipient, message_id=message_id, source_ip=source_ip,
                               source_domain=source_domain, limit=limit)
        result = self._http_request(
            method='GET',
            url_suffix='sweeping/mails',
            params=params
        )
        return result

    def user_take_action(self, action_type: str, account_list: list) -> dict:
        """
        Handle user take action request.
        Args:
            action_type(str): Type of the action to take.
            account_list(list): List Email addresses to take action on.

        Returns:
            The user take action response.
        """
        data = []
        for account in account_list:
            data.append({
                "action_type": action_type,
                "service": "exchange",
                "account_provider": "office365",
                "account_user_email": account
            })

        result = self._http_request(
            method='POST',
            url_suffix='mitigation/accounts',
            json_data=data
        )
        return result

    def email_take_action(self, action_type: str, mailbox: str, mail_message_id: str, mail_unique_id: str,
                          mail_message_delivery_time: str) -> dict:
        """
        Handle email_take_action request.
        Args:
            action_type(str): Action to take on an email message.
            mailbox(str): Email address of an email message to take action on.
            mail_message_id(str): Internet message ID of an email message to take action on.
            mail_unique_id(str): Unique ID of an email message to take action on.
            mail_message_delivery_time(str): Date and time when an email message to take action on.

        Returns:
            The email_take_action response.
        """
        data = [{
            "action_type": action_type,
            "service": "exchange",
            "account_provider": "office365",
            "mailbox": mailbox,
            "mail_message_id": mail_message_id,
            "mail_unique_id": mail_unique_id,
            "mail_message_delivery_time": mail_message_delivery_time
        }]

        result = self._http_request(
            method='POST',
            url_suffix='mitigation/mails',
            json_data=data
        )
        return result

    def action_result_query(self, batch_id: str, start: str, end: str, limit: str, action_type: str) -> dict:
        """
        Handle action_result_query request.
        Args:
            batch_id(str): The id to check the status for.
            action_type(str): Type searching his status.
            start(str): Start time during which action results are to retrieve.
            end(str): End time during which action results are to retrieve.
            limit(str): Number of action results to display at a time.

        Returns:
            The action_result_query response.
        """
        params = assign_params(batch_id=batch_id, start=start, end=end, limit=limit)
        data = self._http_request(
            method='GET',
            url_suffix=f'mitigation/{action_type}',
            params=params
        )
        return data

    def blocked_lists_get(self):
        """
        Handle get blocked lists request.
        Returns:
            The get blocked lists response.
        """
        result = self._http_request(
            method='GET',
            url_suffix='remediation/mails'
        )
        return result

    def blocked_lists_update(self, action_type: str, senders_list: List[str], urls_list: List[str],
                             filehashes_list: List[str]) -> dict:
        """
        Handle update blocked lists request.
        Args:
            action_type(str): action to take.
            senders_list(list): mail address that an email message is sent from..
            urls_list(list): URL that is included in an email message..
            filehashes_list(list): SHA-1 hash value of an email attachment..

        Returns:
            The update blocked lists response.
        """
        rules = assign_params(senders=senders_list, urls=urls_list, filehashes=filehashes_list)
        data = {
            "action_type": action_type,
            "rules": rules
        }
        result = self._http_request(
            method='POST',
            url_suffix='remediation/mails',
            json_data=data
        )
        return result

    def next_link(self, link: str) -> dict:
        """
        Handle next link request.
        Args:
            link(str): Link from previous request.

        Returns:
            The next link response.
        """
        data = self._http_request(
            method='GET',
            full_url=link,
            url_suffix=''
        )
        return data


''' HELPER FUNCTIONS '''


def parse_date_to_isoformat(arg: str, arg_name: str):
    """
        Parses date_string to iso format date strings ('%Y-%m-%dT%H:%M:%SZ'). Input Can be any date that is valid or
        'number date range unit' for Examples: (2 hours, 4 minutes, 6 month, 1 day, etc.)
        Args:
            arg (str): The date to be parsed.
            arg_name (str): the name of the argument for error output.
        Returns:
            str: The parsed date in isoformat strings ('%Y-%m-%dT%H:%M:%SZ').
    """
    if arg is None:
        return None

    # we use dateparser to handle strings either in ISO8601 format, or [number] [time unit].
    # For example: 2019-10-23T00:00:00 or "3 days", etc

    date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
    if not date:
        return_error(f'invalid date value for: {arg_name}\n{arg} should be in the format of:'
                     f' "2016-07-22T01:51:31.001Z." or "10 minutes"')
    assert date is not None
    date = f'{date.isoformat()}Z'
    return date


def creates_empty_dictionary_of_last_run(list_services: list, list_event_type: list):
    return {service: {event_type: {} for event_type in list_event_type} for service in list_services}


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params) -> str:
    if params.get('isFetch'):
        fetch_incidents_command(client, params, is_test_module=True)
    else:
        try:
            client.security_events_list(service='exchange', event_type='securityrisk')
        except DemistoException as e:
            if 'authentication token not found' in str(e):
                return 'Authorization Error: make sure Token Key or Service URL are correctly set'
            else:
                raise e
    return 'ok'


def fetch_incidents(client: Client, max_results: int, last_run, list_services: List[str], first_fetch_time: str,
                    list_event_type: List[str], is_test_module: bool) -> Tuple[Dict[str, dict], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).
    This function has to implement the logic of making sure that incidents are
    fetched only once and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp and ids of the last
    incident it processed.

    Args
        client (Client): client to use
        max_results (int): Maximum numbers of incidents per fetch
        last_run (Optional[Dict[str, int]]): A dict with a key containing the latest incident created time we got
            from last fetch
        first_fetch_time (str): If last_run is None (first time we are fetching), it contains
            the date in iso format on when to start fetching incidents
        ist_services (str): list services of the alerts to search for.
            Options are: 'exchange,sharepoint,onedrive,dropbox,box,googledrive,gmail,teams'
        list_event_type (str): list types of events to search for.
            Options are: securityrisk, virtualanalyze, ransomware, dlp

    return:
        Tuple[Dict[str, int], List[dict]]: A tuple containing two elements:
            next_run (``Dict[str, dict]``): Contains the timestamp that will be used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    """
    next_run = last_run.copy()
    incidents: List[Dict[str, Any]] = []
    end = parse_date_to_isoformat('now', 'end')

    quota = False
    for service in list_services:
        if max_results <= len(incidents) or quota:
            break
        for event_type in list_event_type:
            last_fetch_time = last_run.get(service, {}).get(event_type, {}).get('last_fetch_time', first_fetch_time)
            last_fetch_ids = last_run.get(service, {}).get(event_type, {}).get('last_fetch_ids', [])
            if max_results <= len(incidents) or quota:
                break
            result = {}
            try:
                """Sends a request and calculates the limit according to
                 the ״max_results״ minus the "incident" already collected
                 plus the events that will return duplicate "(len(last_fetch_ids))"""
                result = client.security_events_list(
                    service=service,
                    event_type=event_type,
                    start=last_fetch_time,
                    end=end,
                    limit=str((max_results + len(last_fetch_ids)) - len(incidents))
                )
            except Exception as e:
                if 'Maximum allowed requests exceeded' in str(e):
                    quota = True
                    if is_test_module:
                        return_error(
                            'The integration was successfully configured.'
                            ' However, too many services and event_types Were selected,'
                            ' this exceeds you user license rate limit')
                    demisto.info('quota_error - maximum allowed requests exceeded - All incidents collected were saved')
                    break
                elif 'Authentication token not found' in str(e):
                    return_error('Authorization Error: make sure Token Key or Service URL are correctly set')
                else:
                    raise e
            security_events = result.get('security_events')
            if not security_events:
                continue
            new_latest_ids = []
            for event in security_events:
                if event.get('log_item_id') not in last_fetch_ids:
                    message = event.get("message")
                    incident_name = f"{event.get('event')} on {message.get('affected_user')} at" \
                                    f" {message.get('location')} - {event.get('log_item_id')}"
                    incident = {
                        'name': incident_name,
                        'occurred': message.get('detection_time'),
                        'rawJSON': json.dumps(event)
                    }
                    incidents.append(incident)
                    if event.get('message').get('detection_time') == result.get('last_log_item_generation_time'):
                        new_latest_ids.append(event.get('log_item_id'))

            latest_created_time = result.get('last_log_item_generation_time', '')
            if latest_created_time != last_fetch_time:
                next_run[service][event_type] = {'last_fetch_time': latest_created_time,
                                                 'last_fetch_ids': new_latest_ids}
            else:
                next_run[service][event_type] = {'last_fetch_time': last_fetch_time,
                                                 'last_fetch_ids': last_fetch_ids + new_latest_ids}

    return next_run, incidents


def security_events_list_command(client, args):
    next_link = args.get('next_link')
    if next_link:
        result = client.next_link(next_link)

    else:
        service = args.get('service')
        event_type = args.get('event_type')
        limit = args.get('limit')
        start = parse_date_to_isoformat(args.get('start'), 'start')
        end = parse_date_to_isoformat(args.get('end'), 'end')
        if start and not end:
            end = parse_date_to_isoformat('now', 'end')

        result = client.security_events_list(service, event_type, start, end, limit)

    security_events = result.get('security_events')
    if not security_events:
        return ["no events"]
    else:
        message_list = []
        for event in security_events:
            message = event.get('message')
            message['log_item_id'] = event.get('log_item_id')
            message_list.append(message)
        headers = ['log_item_id', 'detection_time', 'security_risk_name', 'affected_user', 'action', 'action_result']
        readable_output = tableToMarkdown(f'{event_type} events in {service}', message_list, headers=headers)

        entries = []
        entries.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='TrendMicroCAS.Events',
            outputs_key_field='log_item_id',
            outputs=security_events,
            raw_response=result
        ))
        if result.get('next_link'):
            meta_data = {
                'next_link': result.get('next_link'),
                'traceId': result.get('traceId')
            }
            entries.append(CommandResults(
                readable_output=tableToMarkdown('Events MetaData.', meta_data),
                outputs_prefix='TrendMicroCAS.EventsMetaData',
                outputs_key_field='traceId',
                outputs=meta_data,
                raw_response=result))

        return entries


def email_sweep_command(client, args):
    mailbox = args.get('mailbox')
    lastndays = args.get('lastndays')
    start = parse_date_to_isoformat(args.get('start'), 'start')
    end = parse_date_to_isoformat(args.get('end'), 'end')
    subject = args.get('subject')
    file_sha1 = args.get('file_sha1')
    file_name = args.get('file_name')
    file_extension = args.get('file_extension')
    url = args.get('url')
    sender = args.get('sender')
    recipient = args.get('recipient')
    message_id = args.get('message_id')
    source_ip = args.get('source_ip')
    source_domain = args.get('source_domain')
    limit = args.get('limit')
    next_link = args.get('next_link')

    if next_link:
        result = client.next_link(next_link)
    else:
        result = client.email_sweep(mailbox, lastndays, start, end, subject, file_sha1, file_name, file_extension, url,
                                    sender, recipient, message_id, source_ip, source_domain, limit)

    value = result.get('value')
    if not value:
        return "Emails were not found for the given filters"
    else:

        headers = ["mail_message_delivery_time", "mail_message_id", "mail_message_sender", "mail_message_subject",
                   "mail_unique_id", "mailbox"]
        readable_output = tableToMarkdown('Search Results', value, headers=headers)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='TrendMicroCAS.EmailSweep',
            outputs_key_field='traceId',
            outputs=result,
            raw_response=result
        )


def user_take_action_command(client, args):
    action_type = args.get('action_type')
    account_list = argToList(args.get('account_user_email'))
    result = client.user_take_action(action_type, account_list)
    output = {
        'action_type': action_type,
        'account_user_email': account_list,
        'batch_id': result.get('batch_id'),
        'traceId': result.get('traceId')
    }
    readable_output = tableToMarkdown(f'Action: {action_type} on users: {account_list} was initiated', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroCAS.UserTakeAction',
        outputs_key_field='batch_id',
        outputs=output,
        raw_response=result
    )


def email_take_action_command(client, args):
    action_type = args.get('action_type')
    mailbox = args.get('mailbox')
    mail_message_id = args.get('mail_message_id')
    mail_unique_id = args.get('mail_unique_id')
    mail_message_delivery_time = args.get('mail_message_delivery_time')

    result = client.email_take_action(action_type, mailbox, mail_message_id, mail_unique_id, mail_message_delivery_time)
    output = {
        'action_type': action_type,
        'mailbox': mailbox,
        'batch_id': result.get('batch_id'),
        'traceId': result.get('traceId')
    }
    readable_output = tableToMarkdown(f'Action: {action_type} on mailbox: {mailbox} was initiated', output)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroCAS.EmailTakeAction',
        outputs_key_field='batch_id',
        outputs=output,
        raw_response=result
    )


def user_action_result_command(client, args):
    batch_id = args.get('batch_id')
    start = parse_date_to_isoformat(args.get('start'), 'start')
    end = parse_date_to_isoformat(args.get('end'), 'end')
    limit = args.get('limit')
    result = client.action_result_query(batch_id, start, end, limit, 'accounts')

    actions = result.get('actions')
    headers = ["action_id", "status", "action_type", "account_user_email", "action_executed_at", "error_message"]
    readable_output = tableToMarkdown('Action Result', actions, headers=headers)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroCAS.UserActionResult',
        outputs_key_field='batch_id',
        outputs=actions,
        raw_response=result
    )


def email_action_result_command(client, args):
    batch_id = args.get('batch_id')
    start = parse_date_to_isoformat(args.get('start'), 'start')
    end = parse_date_to_isoformat(args.get('end'), 'end')
    limit = args.get('limit')
    result = client.action_result_query(batch_id, start, end, limit, 'mails')

    actions = result.get('actions')
    headers = ["action_id", "status", "action_type", "account_user_email", "action_executed_at", "error_message"]
    readable_output = tableToMarkdown('Action Result', actions, headers=headers)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroCAS.EmailActionResult',
        outputs_key_field='batch_id',
        outputs=actions,
        raw_response=result
    )


def blocked_lists_get_command(client):
    result = client.blocked_lists_get()
    rules = result.get('rules')
    if not rules:
        return "Blocked List is empty"
    else:
        readable_output = tableToMarkdown('Blocked List', rules)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='TrendMicroCAS.BlockedList',
            outputs_key_field='BlockedList',
            outputs=rules,
            raw_response=result
        )


def blocked_lists_update_command(client, args):
    action_type = args.get('action_type')
    senders_list = argToList(args.get('senders'))
    urls_list = argToList(args.get('urls'))
    filehashes_list = argToList(args.get('filehashes'))

    result = client.blocked_lists_update(action_type, senders_list, urls_list, filehashes_list)
    rules = assign_params(senders=senders_list, urls=urls_list, filehashes=filehashes_list)
    readable_output = tableToMarkdown(result.get('message'), rules)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='TrendMicroCAS.BlockedList',
        outputs_key_field='BlockedList',
        outputs=rules,
        raw_response=result
    )


def fetch_incidents_command(client, params, is_test_module=False):
    list_services = params.get('service')
    list_event_type = params.get('event_type')
    first_fetch_time = parse_date_to_isoformat(params.get('first_fetch', '3 days'), 'first_fetch_time')
    max_results = int(params.get('max_fetch', 50))
    if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    last_run = demisto.getLastRun()  # getLastRun() gets the last run dict
    if not last_run:
        last_run = creates_empty_dictionary_of_last_run(list_services, list_event_type)
    next_run, incidents = fetch_incidents(
        client=client,
        max_results=max_results,
        last_run=last_run,  # getLastRun() gets the last run dict
        list_services=list_services,
        list_event_type=list_event_type,
        first_fetch_time=first_fetch_time,
        is_test_module=is_test_module
    )
    if is_test_module:
        return
    demisto.setLastRun(next_run)
    demisto.incidents(incidents)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    URLS = {
        'U.S.A': 'https://api.tmcas.trendmicro.com/v1/',
        'EU': 'https://api-eu.tmcas.trendmicro.com/v1/',
        'Japan': 'https://api.tmcas.trendmicro.co.jp/v1/',
        'Australia and New Zealand': 'https://api-au.tmcas.trendmicro.com/v1/',
        'UK': 'https://api.tmcas.trendmicro.co.uk/v1/',
        'Canada': 'https://api-ca.tmcas.trendmicro.com/v1/',
        'India': 'https://api-in.tmcas.trendmicro.com/v1/'
    }
    params = demisto.params()
    token = params.get('credentials_token', {}).get('password') or params.get('token')
    if not token:
        raise DemistoException('Token must be provided.')
    # get the service API url
    base_url = URLS.get(params.get("serviceURL"))
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Bearer {token}'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client, params)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents_command(client, params)
        elif demisto.command() == 'trendmicro-cas-email-sweep':
            return_results(email_sweep_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-cas-security-events-list':
            [return_results(result) for result in security_events_list_command(client, demisto.args())]
        elif demisto.command() == 'trendmicro-cas-user-take-action':
            return_results(user_take_action_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-cas-email-take-action':
            return_results(email_take_action_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-cas-user-action-result-query':
            return_results(user_action_result_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-cas-email-action-result-query':
            return_results(email_action_result_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-cas-blocked-lists-get':
            return_results(blocked_lists_get_command(client))
        elif demisto.command() == 'trendmicro-cas-blocked-lists-update':
            return_results(blocked_lists_update_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
