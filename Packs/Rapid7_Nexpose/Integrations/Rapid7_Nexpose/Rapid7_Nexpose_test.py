import demistomock as demisto
import requests

ITEM_WITHOUT_MS = {
    'date': '2019-05-03T03:01:54Z'
}

ITEM_WITH_MS = {
    'date': '2019-05-03T03:02:54.123Z'
}

ITEM_WITH_SCANID = {
    'date': '2019-05-03T03:03:54.123Z',
    'scanId': '1'
}


class ResponseMock:
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
        'server': 'nexpose.com',
        'proxy': True
    })
    mocker.patch.object(requests, 'post', return_value=ResponseMock())


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
    assert(sorted_dt_arr[0] == ITEM_WITHOUT_MS)
    assert(sorted_dt_arr[1] == ITEM_WITH_MS)


def test_get_last_scan(mocker):
    init_integration(mocker)
    from Rapid7_Nexpose import get_last_scan

    # test empty history
    expected = '-'
    assert(get_last_scan({'history': None}) == expected)

    # test history with assorted items
    asset = {
        'history': [
            ITEM_WITH_MS,
            ITEM_WITHOUT_MS
        ]
    }
    expected = {
        'date': '2019-05-03T03:02:54.123Z',
        'id': '-'
    }

    # test history with assorted items + scanId
    asset = {
        'history': [
            ITEM_WITH_MS,
            ITEM_WITHOUT_MS,
            ITEM_WITH_SCANID
        ]
    }
    expected = {
        'date': '2019-05-03T03:03:54.123Z',
        'id': '1'
    }
    assert(get_last_scan(asset) == expected)
