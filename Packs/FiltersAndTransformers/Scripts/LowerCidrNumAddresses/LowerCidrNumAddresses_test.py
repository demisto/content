import pytest
import demistomock as demisto


# About the drop some mean regex right now disable-secrets-detection-start
@pytest.mark.parametrize(argnames="cidr, max_num_addresses, expected",
                         argvalues=[('192.168.0.0/24', 257, True),
                                    ('192.168.0.0/24', 255, False),
                                    ('2002::1234:abcd:ffff:c0a8:101/127', 3, True)])
def test_cidr_network_addresses_lower_from_const(cidr: str, max_num_addresses: str, expected: bool):
    from LowerCidrNumAddresses import cidr_network_addresses_lower_from_const
    assert cidr_network_addresses_lower_from_const(ip_cidr=cidr,
                                                   max_num_addresses=max_num_addresses) == expected
# Drops the mic disable-secrets-detection-end


def test_main(mocker):
    from LowerCidrNumAddresses import main
    mocker_args = mocker.patch.object(demisto, 'args', return_value={'right': 257, 'left': ['192.168.0.0/24', '192.168.0.0/24']})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 2
    assert mocker_args.call_count == 2
