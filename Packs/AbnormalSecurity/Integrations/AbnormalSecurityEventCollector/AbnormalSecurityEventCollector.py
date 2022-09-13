from CommonServerPython import *
import demistomock as demisto

VENDOR = 'Abnormal Security'
PRODUCT = 'Email Protection'


class Client(BaseClient):
    def get_threats(self, params):
        return self._http_request('GET', params=params, url_suffix='threats')

    def get_threat(self, threat):
        return self._http_request('GET', url_suffix=f'threats/{threat}')


def get_threats(client: Client, after):
    before = get_timestamp_format('now')
    threats_ids = get_list_threats(client, after, before)
    messages = []
    if threats_ids:
        for threat in reversed(threats_ids):
            messages += get_messages_by_datetime(client, threat.get('threatId'), after, before)
        ordered_messages = sorted(messages, key=lambda d: d['receivedTime'])
        return ordered_messages, before
    return [], before


def get_messages_by_datetime(client: Client, threat_id, after, before):
    messages = []
    res = client.get_threat(threat_id)
    for message in res.get('messages'):
        received_time = message.get('receivedTime')
        if before >= received_time >= after:
            messages.append(message)
        elif received_time < after:
            break
    return messages


def get_timestamp_format(value):
    timestamp: Optional[datetime]
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)
    if timestamp is None:
        raise TypeError(f'after is not a valid time {value}')
    return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_list_threats(client, after, before):
    threats = []
    is_next_page = True
    page_number = 1
    while is_next_page:
        params = assign_params(pageSize=1000, filter=f'receivedTime gte {after} lte {before}', pageNumber=page_number)
        res = client.get_threats(params)
        threats += res.get('threats')
        if res.get('nextPageNumber'):
            page_number = res.get('nextPageNumber')
        else:
            is_next_page = False
    return threats


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    token = demisto_params['token']['password']
    should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))
    verify = demisto_params['verify']
    proxy = demisto_params['proxy']
    after = get_timestamp_format(demisto_params.get('after'))
    client = Client(base_url='https://api.abnormalplatform.com/v1',
                    verify=verify,
                    proxy=proxy,
                    headers={"Authorization": f"Bearer {token}"})

    command = demisto.command()
    try:
        threats, last_run = get_threats(client, after)
        if command == 'test-module':
            return_results('ok')

        elif command == 'fetch-events':
            demisto.setLastRun({'after': last_run})
            send_events_to_xsiam(threats, VENDOR, PRODUCT)

        elif command == 'AbnormalSecurityEventCollector-get-events':
            command_results = CommandResults(
                readable_output=tableToMarkdown(f'{VENDOR} - {PRODUCT} events', threats),
                raw_response=threats,
            )
            return_results(command_results)
            if should_push_events:
                send_events_to_xsiam(threats, VENDOR, PRODUCT)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
