from DuoEventCollector import Client, GetEvents, LogType, Params
import pytest

demisto_params = {'after': '1 month', 'host': 'api-a1fdb00d.duosecurity.com', 'integration_key': 'DI47EXXXXXXXWRYV2',
                  'limit': '5', 'proxy': False, 'retries': '5', 'secret_key': {'password': 'YK6mtSzXXXXXXXXXXX',
                                                                               'passwordChanged': False}}
demisto_params['params'] = Params(**demisto_params, mintime={})
client = Client(demisto_params)
get_events = GetEvents(client=client, request_order=[LogType.AUTHENTICATION, LogType.ADMINISTRATION, LogType.TELEPHONY])
id1 = {'username': 'a', 'eventtype': 'a', 'timestamp': 'a'}
id2 = {'username': 'b', 'eventtype': 'b', 'timestamp': 'b'}
id3 = {'username': 'c', 'eventtype': 'c', 'timestamp': 'c'}


@pytest.mark.parametrize("events,ids,result", [
    ([id1, id2, id3], ['aaa'], [id2, id3]),
    ([id1, id2, id3], ['ddd'], [id1, id2, id3]),
    ([], ['aaa'], [])])
def test_remove_duplicates(events, ids, result):
    assert get_events.remove_duplicates(events, ids) == result

