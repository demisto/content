import pytest
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import Lastline_v2


def hash_test_generator(hash_size) -> str:
    test_hash = ''
    for _ in range(hash_size):
        test_hash += '1'
    return hash_size


def test_hash_type_checker():
    assert hash_type_checker(hash_test_generator(Client.MD5_LEN)) == 'md5',\
        f'{INTEGRATION_NAME} Test.hash_type_checker() == md5'
    assert hash_type_checker(hash_test_generator(Client.SHA1_LEN)) == 'sha1',\
        f'{INTEGRATION_NAME} Test.hash_type_checker() == sha1'
    assert hash_type_checker(hash_test_generator(Client.SHA256_LEN)) == 'sha256',\
        f'{INTEGRATION_NAME} Test.hash_type_checker() == sha256'
    try:
        hash_type_checker(hash_test_generator(10))  # hard coded invalid size
    except DemistoException:
        pass
    else:
        assert False, f'{INTEGRATION_NAME} Test.hash_type_checker() invalid type error'


def test_exception_helper():
    json_obj = {"success": 0, "error_code": 115, "error": "Submission limit exceeded"}
    json_obj = json.loads(json_obj)
    try:
        exception_helper(json_obj)
    except DemistoException as error_msg:
        assert error_msg == DemistoException('error (115) Submission limit exceeded'),\
            f'{INTEGRATION_NAME} Test.exception_helper() failed'
    else:
        assert False, f'{INTEGRATION_NAME} Test.exception_helper() failed'
