import demistomock as demisto


def test_main(mocker):
    from IsInCidrRanges import main

    value = '172.16.0.1'
    cidr_ranges = '10.0.0.0/8,192.168.0.0/16'
    mocker.patch.object(demisto, 'results')
    results = main(value, cidr_ranges)
    assert results is False

    value = '10.5.5.5'
    cidr_ranges = '10.0.0.0/8,192.168.0.0/16'
    results = main(value, cidr_ranges)
    assert results is True
