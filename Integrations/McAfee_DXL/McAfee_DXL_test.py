from McAfee_DXL import *
import pytest

data_test_get_trust_level_key = ['0', '1', '15', '30', '50', '70', '85', '99', '100']
data_test_get_trust_level_key = [(k, k) for k in data_test_get_trust_level_key]
data_test_raise_get_trust_level_key = ['-', '', '-1']
data_test_push_ip = ['-.-.-.-', '1.1.1']


@pytest.mark.parametrize(argnames="input_key, output", argvalues=data_test_get_trust_level_key)
def test_get_trust_level_key(input_key, output):
    assert get_trust_level_key(EventSender.TRUST_LEVELS.get(input_key)) == output, \
        f"error in McAfee_DXL get_trust_level_key() key = {input_key}"


@pytest.mark.parametrize(argnames="input_key", argvalues=data_test_raise_get_trust_level_key)
def test_raise_get_trust_level_key(input_key):
    try:
        get_trust_level_key(input_key)
    except Exception as error:
        assert str(error) == f'Illegal argument trust_level {input_key}. Choose value from predefined values',\
            f'error in get_trust_level_key({input_key}).'
    else:
        raise Exception(f'error in get_trust_level_key({input_key}).')


@pytest.mark.parametrize(argnames='input_ip', argvalues=data_test_push_ip)
def test_is_ip_valid(input_ip):
    assert not is_ip_valid(input_ip), f'argument ip {input_ip} is not a valid IP'
