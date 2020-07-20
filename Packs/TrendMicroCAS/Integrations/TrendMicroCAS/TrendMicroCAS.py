import dateparser

import demistomock as demisto
from CommonServerPython import *

import json
import requests
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast
import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

MAX_INCIDENTS_TO_FETCH = 500

''' CLIENT CLASS '''


class Client(BaseClient):

    def security_events_list(self, service, event_type, start=None, end=None, limit=None) -> dict:
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

    def user_take_action(self, action_type: str, account_user_email: str) -> dict:
        account_list = argToList(account_user_email)
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

    def user_action_result_query(self, batch_id: str, start: str, end: str, limit: str) -> dict:
        params = assign_params(batch_id=batch_id, start=start, end=end, limit=limit)
        data = self._http_request(
            method='GET',
            url_suffix='mitigation/accounts',
            params=params
        )
        return data

    def email_action_result_query(self, batch_id: str, start: str, end: str, limit: str) -> dict:
        params = assign_params(batch_id=batch_id, start=start, end=end, limit=limit)
        data = self._http_request(
            method='GET',
            url_suffix='mitigation/mails',
            params=params

        )
        return data

    def blocked_lists_get(self):
        result = self._http_request(
            method='GET',
            url_suffix='remediation/mails'
        )
        return result

    def blocked_lists_update(self, action_type: str, senders_list: List[str], urls_list: List[str],
                             filehashes_list: List[str]) -> dict:
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

      :type arg: ``str``
      :param arg: The date to be parsed

      :type arg_name: ``str``
      :param arg_name: the name of the argument for error output

      :return: The parsed date in isoformat strings ('%Y-%m-%dT%H:%M:%SZ').
      :rtype: str
    """
    if arg is None:
        return None

    # we use dateparser to handle strings either in ISO8601 format, or
    # For example: format 2019-10-23T00:00:00 or "3 days", etc

    date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
    if not date:
        return_error(f'Error in the date - {arg_name}')

    date = f'{date.isoformat()}Z'
    return date


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    try:
        client.security_events_list(service='exchange', event_type='securityrisk')
    except DemistoException as e:
        if 'uthentication token not found' in str(e):
            return 'Authorization Error: make sure Token Key or URL are correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client, max_results: int, last_run, list_services: List[str], first_fetch: str,
                    list_event_type: List[str]) -> Tuple[Dict[str, dict], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch: ``str``
    :param first_fetch:
        If last_run is None (first time we are fetching), it contains
        the date in iso format on when to start fetching incidents

    :type list_services: ``str``
    :param list_services:
        liost services of the alerts to search for. Options are: 'exchange,sharepoint,onedrive,dropbox,box,googledrive,gmail,teams'


    :type list_event_type: ``str``
    :param list_event_type:
        list types of events to search for. Options are: securityrisk, virtualanalyze, ransomware, dlp

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, dict]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """
    next_run = {}
    incidents: List[Dict[str, Any]] = []
    end = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for service in list_services:
        next_run[service] = {}
        for event_type in list_event_type:
            last_fetch_time = last_run.get(service, {}).get(event_type, {}).get('last_fetch_time', first_fetch)
            last_fetch_ids = last_run.get(service, {}).get(event_type, {}).get('last_fetch_ids', [])
            result = client.security_events_list(
                service=service,
                event_type=event_type,
                start=last_fetch_time,
                end=end,
                limit=(max_results + len(last_fetch_ids)) - len(incidents)
            )
            new_latest_ids = []
            security_events = result.get('security_events')
            if not security_events:
                continue
            for event in security_events:
                if event.get('log_item_id') not in last_fetch_ids:
                    incident_name = event.get('log_item_id')
                    incident = {
                        'name': incident_name,
                        'occurred': event.get('message').get('detection_time'),
                        'rawJSON': json.dumps(event)
                    }
                    incidents.append(incident)
                    if event.get('message').get('detection_time') == result.get('last_log_item_generation_time'):
                        new_latest_ids.append(event.get('log_item_id'))
            latest_created_time = result.get('last_log_item_generation_time', '')
            if latest_created_time != last_fetch_time:
                next_run[service][event_type] = {'last_fetch_time': latest_created_time, 'last_fetch_ids': new_latest_ids}
            else:
                next_run[service][event_type] = {'last_fetch_time': last_fetch_time, 'last_fetch_ids': last_fetch_ids + new_latest_ids}
        if max_results <= len(incidents):
            break

    return next_run, incidents


def security_events_list_command(client, args):
    service = args.get('service')
    event_type = args.get('event_type')
    start = parse_date_to_isoformat(args.get('start'), 'start')
    end = parse_date_to_isoformat(args.get('end'), 'end')
    limit = args.get('limit')
    next_link = args.get('next_link')

    if start and not end:
        end = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if next_link:
        result = client.next_link(next_link)
    else:
        result = client.security_events_list(service, event_type, start, end, limit)

    security_events = result.get('security_events')
    if not security_events:
        return "no events"
    else:
        message_list = []
        for event in security_events:
            message = event.get('message')
            message['log_item_id'] = event.get('log_item_id')
            message_list.append(message)

        readable_output = tableToMarkdown(f'{event_type} events in {service}', message_list)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='TrendMicroCAS.Events',
            outputs_key_field='traceId',
            outputs=result,
            raw_response=result
        )


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
        return "not find emails"
    else:
        readable_output = tableToMarkdown('search results', value)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='TrendMicroCAS.EmailSweep',
            outputs_key_field='traceId',
            outputs=result,
            raw_response=result
        )


def user_take_action_command(client, args):
    action_type = args.get('action_type')
    account_user_email = args.get('account_user_email')
    result = client.user_take_action(action_type, account_user_email)
    output = {
        'action_type': action_type,
        'account_user_email': argToList(account_user_email),
        'batch_id': result.get('batch_id'),
        'traceId': result.get('traceId')
    }
    readable_output = tableToMarkdown(f'{action_type} started', output)
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
    readable_output = tableToMarkdown(f'{action_type} started', output)
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
    result = client.user_action_result_query(batch_id, start, end, limit)

    actions = result.get('actions')
    readable_output = tableToMarkdown('action result', actions)
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
    result = client.email_action_result_query(batch_id, start, end, limit)

    actions = result.get('actions')
    readable_output = tableToMarkdown('action result', actions)
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


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    URLS = {
        'U.S.A': 'api.tmcas.trendmicro.com',
        'EU': 'api-eu.tmcas.trendmicro.com',
        'Japan': 'api.tmcas.trendmicro.co.jp',
        'Australia and New Zealand': 'api-au.tmcas.trendmicro.com',
        'UK': 'api.tmcas.trendmicro.co.uk',
        'Canada': 'api-ca.tmcas.trendmicro.com'
    }

    token = demisto.params().get('token')
    # get the service API url
    base_url = f'https://{URLS[demisto.params().get("serviceURL")]}/v1/'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Bearer {token}'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            list_services = demisto.params().get('service')
            list_event_type = demisto.params().get('event_type')
            first_fetch = parse_date_to_isoformat(demisto.params().get('first_fetch', '3 days'), 'first_fetch')
            max_results = int(demisto.params().get('max_fetch', 50))
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            last_run = demisto.getLastRun()  # getLastRun() gets the last run dict
            if not last_run:
                last_run = {}
                for service in list_services:
                    last_run[service] = {}
                    for event_type in list_event_type:
                        last_run[service][event_type] = {}
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=last_run,  # getLastRun() gets the last run dict
                list_services=list_services,
                list_event_type=list_event_type,
                first_fetch=first_fetch
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'trendmicro-cas-email-sweep':
            return_results(email_sweep_command(client, demisto.args()))
        elif demisto.command() == 'trendmicro-cas-security-events-list':
            return_results(security_events_list_command(client, demisto.args()))
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
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
