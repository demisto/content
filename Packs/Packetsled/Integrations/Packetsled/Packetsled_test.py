from Packetsled import number_to_ip, ip_to_number


def test_number_to_ip():
    assert number_to_ip(168496141) == '10.11.12.13'


def test_ip_to_number():
    assert ip_to_number('10.11.12.13') == 168496141
