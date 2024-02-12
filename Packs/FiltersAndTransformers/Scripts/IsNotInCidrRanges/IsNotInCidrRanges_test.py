from pytest_mock import MockerFixture
from IsNotInCidrRanges import validate_cidr, process_ips


def test_validate_cidr(mocker: MockerFixture) -> None:
    """
    Given
        a CIDR string,
    When
        the validate_cidr function is called,
    Then
        it should return True if the string is a valid CIDR, and False otherwise.
    """
    mocker.patch('IsNotInCidrRanges.demisto.debug', return_value=None)
    assert validate_cidr('192.168.1.0/24') is True
    assert validate_cidr('192.168.1.500/24') is False


def test_process_ips_ip_in_cidr() -> None:
    """
    Given
        a valid IP and CIDR range
    When
        the process_ips function is called
    Then
        it should return False as the IP is in the CIDR range.
    """
    result = process_ips(['10.0.0.1'], ['10.0.0.0/8'])
    assert result is False


def test_process_ips_ip_not_in_cidr() -> None:
    """
    Given
        a valid IP and CIDR range,
    When
        the process_ips function is called,
    Then
        it should return True as the IP is not in the CIDR range.
    """
    result = process_ips(['172.16.0.1'], ['10.0.0.0/8'])
    assert result is True


def test_process_ips_invalid_ip(mocker: MockerFixture) -> None:
    """
    Given
        an invalid IP and a valid CIDR range,
    When
        the process_ips function is called,
    Then
        it should skip the invalid IP and not raise an exception.
    """
    mocker.patch('ipaddress.ip_address', side_effect=ValueError('Invalid IP'))
    result = process_ips(['invalid_ip'], ['10.0.0.0/8'])
    assert result is True
