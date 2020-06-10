import demistomock as demisto


PARAMS = {
    'server': 'server',
    'credentials': {},
    'proxy': True}

ARGS = {'ids': 'lastDateRange',
        'lastDateRange': '2 hours'}


def test_decode_ip(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    import ArcSightESMv2

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    res = ArcSightESMv2.decode_ip('52.213.8.10')
    assert res == '52.213.8.10'

    res = ArcSightESMv2.decode_ip(3232235845)
    assert res == '192.168.1.69'
