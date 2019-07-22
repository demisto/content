import demistomock as demisto

DATE_WITHOUT_MS = '2019-05-03T03:01:54'
DATE_WITH_MS = '2019-05-03T03:02:54.123'


def init_integration(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'URL': 'mock.com'
    })


def test_fetch_incidents(mocker):
    init_integration(mocker)
    import Jask
    from Jask import fetch_incidents
    mocker.patch.object(Jask, 'req', return_value={
        'objects': [
            {
                'timestamp': DATE_WITHOUT_MS
            },
            {
                'timestamp': DATE_WITH_MS
            }
        ]
    })
    # asserts there are no exceptions
    assert(fetch_incidents() is None)
