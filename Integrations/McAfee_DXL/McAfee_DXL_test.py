from McAfee_DXL import *
import pytest

data_test_push_ip = ['-.-.-.-', '1.1.1']


@pytest.mark.parametrize(argnames='input_ip', argvalues=data_test_push_ip)
def test_is_ip_valid(input_ip):
    assert not is_ip_valid(input_ip), f'argument ip {input_ip} is not a valid IP'
