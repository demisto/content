import demistomock as demisto

EMAIL_ADDRESSES = 'test@test.com,filterme@nowhere.com,nobody@demistotest.com'
EMAIL_ADDRESSES_LIST = ['test@test.com', 'filterme@nowhere.com', 'nobody@demistotest.com']
DOMAIN_LIST = 'nowhere.com,somewhere.com'


def test_main(mocker):
    from EmailDomainBlacklist import main
    mocker.patch.object(demisto, 'args', return_value={
        'value': EMAIL_ADDRESSES,
        'domain_list': DOMAIN_LIST
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 2
    assert results[0] == 'test@test.com'
    assert results[1] == 'nobody@demistotest.com'

    # do it again, passing in a list this time
    mocker.patch.object(demisto, 'args', return_value={
        'value': EMAIL_ADDRESSES_LIST,
        'domain_list': DOMAIN_LIST
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 2
    assert results[0] == 'test@test.com'
    assert results[1] == 'nobody@demistotest.com'


def test_csv_string_to_list(mocker):
    from EmailDomainBlacklist import csv_string_to_list
    results = csv_string_to_list(EMAIL_ADDRESSES)
    assert len(results) == 3
    assert results[0] == 'test@test.com'
    assert results[1] == 'filterme@nowhere.com'
    assert results[2] == 'nobody@demistotest.com'

    # do it again, passing in a list this time
    results = csv_string_to_list(EMAIL_ADDRESSES_LIST)
    assert len(results) == 3
    assert results[0] == 'test@test.com'
    assert results[1] == 'filterme@nowhere.com'
    assert results[2] == 'nobody@demistotest.com'
