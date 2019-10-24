import demistomock as demisto


def test_main(mocker):
    from IPv4Whitelist import main

    mocker.patch.object(demisto, 'args', return_value={
        'value': '172.16.0.1,10.0.0.5,5.6.7.8,4.2.2.2',
        'cidr_ranges': '10.0.0.0/8,192.168.0.0/16,5.6.0.0/16'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 2
    assert results[0] == '10.0.0.5'
    assert results[1] == '5.6.7.8'

    # use an array instead of CSV
    mocker.patch.object(demisto, 'args', return_value={
        'value': ['172.16.0.1', '10.0.0.5', '5.6.7.8', '4.2.2.2'],
        'cidr_ranges': ['10.0.0.0/8', '192.168.0.0/16', '5.6.0.0/16']
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 2
    assert results[0] == '10.0.0.5'
    assert results[1] == '5.6.7.8'
