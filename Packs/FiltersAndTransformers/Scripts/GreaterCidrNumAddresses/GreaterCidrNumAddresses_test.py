import pytest
import demistomock as demisto


# About the drop some mean regex right now disable-secrets-detection-start
@pytest.mark.parametrize(argnames="cidr, min_num_addresses, expected",
                         argvalues=[('192.168.0.0/24', 257, False),
                                    ('192.168.0.0/24', 255, True),
                                    ('2002::1234:abcd:ffff:c0a8:101/127', 3, False)])
def test_cidr_network_addresses_greater_from_const(cidr: str, min_num_addresses: str, expected: bool):
    from GreaterCidrNumAddresses import cidr_network_addresses_greater_from_const
    assert cidr_network_addresses_greater_from_const(ip_cidr=cidr,
                                                     min_num_addresses=min_num_addresses) == expected
# Drops the mic disable-secrets-detection-end


@pytest.mark.parametrize(argnames="expected",
                         argvalues=[('192.168.0.0/24', 257, False)])
def test_main(mocker, expected):
    from GreaterCidrNumAddresses import main
    mocker = mocker.patch.object(demisto, 'args', return_value={'left': '192.168.0.0/24,192.168.0.0/24', 'right': 257})
    main()
    assert mocker.called == 1
