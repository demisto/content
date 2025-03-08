from datetime import timedelta

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

VENDOR = 'Abnormal_Security'
PRODUCT = 'Email_Protection'


class Client(BaseClient):
    def list_threats(self, params):
        return self._http_request('GET', params=params, url_suffix='threats')

    def get_threat(self, threat_id, params):
        return self._http_request('GET', params=params, url_suffix=f'threats/{threat_id}')


def format_messages(messages: list):
    """change the messages into the desired form
        1. change the toAddresses value to a list.

    Args:
      messages(list): the messages list to check.

    Returns:
      list: the reorganised messages.

    """
    for message in messages:
        to_addresses = message.get('toAddresses')
        if isinstance(to_addresses, str):
            message['toAddresses'] = argToList(to_addresses)
    return messages


def get_events(client: Client, after: str, event_polling_lag: int):
    """Retrieves messages by time range & ordered by datetime

    Args:
      client (Client): Abnormal Security client.
      after (str): the start datetime to search messages

    Returns:
      list:  messages ordered by datetime.
      str: the last run to be set for the next run.

    """
    before = arg_to_datetime(arg='now', arg_name='before', required=True).strftime("%Y-%m-%dT%H:%M:%SZ")  # type: ignore
    before -= timedelta(minutes=event_polling_lag)
    threats_ids = get_list_threats(client, after, before)
    messages = []
    if threats_ids:
        for threat in reversed(threats_ids):
            messages += format_messages(get_messages_by_datetime(client, threat.get('threatId'), after, before))
        ordered_messages = sorted(messages, key=lambda d: d['receivedTime'])
        return ordered_messages, before
    return [], before


def get_messages_by_datetime(client: Client, threat_id: str, after: str, before: str):
    """get messages from a threat and return only the messages that are in the time range

    Args:
      client (Client): Abnormal Security client.
      threat_id (str): the threat to get messages.
      after (str): the datetime to search messages after that.
      before (str): the datetime to search messages before that.

    Returns:
      list:  messages filtered by the time range.
    """
    messages = []
    params = assign_params(pageSize=1000)
    res = client.get_threat(threat_id, params)
    for message in res.get('messages'):
        # messages are ordered from newest to oldest
        received_time = message.get('receivedTime')
        if before >= received_time >= after:
            messages.append(message)
        elif received_time < after:
            break
    return messages


def get_list_threats(client: Client, after: str, before: str):
    """get list of all threats ids in the time range

    Args:
      client (Client): Abnormal Security client.
      after (str): the datetime to search threats after that.
      before (str): the datetime to search threats before that.

    Returns:
      list:  list of threats ids.
    """
    threats = []
    is_next_page = True
    page_number = 1
    while is_next_page:
        params = assign_params(pageSize=1000, filter=f'receivedTime gte {after} lte {before}', pageNumber=page_number)
        res = client.list_threats(params)
        threats += res.get('threats')
        if res.get('nextPageNumber'):
            page_number = res.get('nextPageNumber')
        else:
            is_next_page = False
    return threats


def main():
    # Args is always stronger. Get last run even stronger
    params = demisto.params()

    token = params['token']['password']
    verify = params['verify']
    proxy = params['proxy']
    event_polling_lag = int(params.get('event_polling_lag', 0))
    after = arg_to_datetime(arg='1 minute').strftime("%Y-%m-%dT%H:%M:%SZ")  # type: ignore

    client = Client(
        base_url='https://api.abnormalplatform.com/v1',
        verify=verify,
        proxy=proxy,
        headers={"Authorization": f"Bearer {token}"},
        timeout=60
    )

    last_run = demisto.getLastRun().get('last_run')
    if last_run:
        after = last_run
    after -= timedelta(minutes=event_polling_lag)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:

        threats, last_run = get_events(client, after, event_polling_lag)
        if command == 'test-module':
            return_results('ok')

        elif command == 'fetch-events':
            send_events_to_xsiam(threats, VENDOR, PRODUCT)
            demisto.setLastRun({'last_run': last_run})

        elif command == 'abnormal-security-event-collector-get-events':
            command_results = CommandResults(
                readable_output=tableToMarkdown(f'{VENDOR} - {PRODUCT} events', threats),
                raw_response=threats,
            )
            return_results(command_results)
            if argToBoolean(demisto.args().get('should_push_events', False)):
                send_events_to_xsiam(threats, VENDOR, PRODUCT)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
