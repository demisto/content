import demistomock as demisto
import requests

ITEM_WITH_MS = {
    'hour': '2019-05-03T03:02:54.123Z'
}
ITEM_WITHOUT_MS = {
    'hour': '2019-05-03T03:01:54Z'
}


class RequestMock:
    def __init__(self):
        self.status_code = 200

    def json(self):
        return ''


def init_integration(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {
            'identifier': 'a',
            'password': 'a'
        },
        'server': 'nexpose.com'
    })
    mocker.patch.object(requests, 'post', return_value=RequestMock())


def test_get_datetime_from_asset_history_item(mocker):
    init_integration(mocker)
    from Rapid7_Nexpose import get_datetime_from_asset_history_item

    assert(get_datetime_from_asset_history_item(ITEM_WITH_MS))
    assert(get_datetime_from_asset_history_item(ITEM_WITHOUT_MS))


def test_sort_with_and_without_ms(mocker):
    init_integration(mocker)
    from Rapid7_Nexpose import get_datetime_from_asset_history_item

    dt_arr = [ITEM_WITH_MS, ITEM_WITHOUT_MS]
    sorted_dt_arr = sorted(dt_arr, key=get_datetime_from_asset_history_item)
    assert(sorted_dt_arr[0].tm_hour == 2)
    assert(sorted_dt_arr[1].tm_hour == 1)
