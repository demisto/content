from DuoEventCollector import Client, GetEvents, LogType, Params

demisto_params = {'after': '1 month', 'host': 'api-a1fdb00d.duosecurity.com', 'integration_key': 'DI47EXXXXXXXWRYV2',
                  'limit': '5', 'proxy': False, 'retries': '5', 'secret_key': {'password': 'YK6mtSzXXXXXXXXXXX',
                                                                               'passwordChanged': False}}
demisto_params['params'] = Params(**demisto_params, mintime={})
client = Client(demisto_params)
get_events = GetEvents(client=client, request_order=[LogType.AUTHENTICATION, LogType.ADMINISTRATION, LogType.TELEPHONY])


def test_rotate_request_order():
    get_events.rotate_request_order()
    assert get_events.request_order == [LogType.ADMINISTRATION, LogType.TELEPHONY, LogType.AUTHENTICATION]
    get_events.rotate_request_order()
    get_events.rotate_request_order()
    assert get_events.request_order == [LogType.AUTHENTICATION, LogType.ADMINISTRATION, LogType.TELEPHONY]
