# from CommonServerPython import *
from Lastline_v2 import *


def hash_test_generator(hash_size) -> str:
    test_hash = ''
    for _ in range(hash_size):
        test_hash += '1'
    return test_hash


def test_hash_type_checker():
    assert help_hash_type_checker(hash_test_generator(Client.MD5_LEN)) == 'md5',\
        f'{INTEGRATION_NAME} Test.help_hash_type_checker() == md5'
    assert help_hash_type_checker(hash_test_generator(Client.SHA1_LEN)) == 'sha1',\
        f'{INTEGRATION_NAME} Test.help_hash_type_checker() == sha1'
    assert help_hash_type_checker(hash_test_generator(Client.SHA256_LEN)) == 'sha256',\
        f'{INTEGRATION_NAME} Test.help_hash_type_checker() == sha256'
    try:
        help_hash_type_checker(hash_test_generator(10))  # hard coded invalid size
    except DemistoException:
        pass
    else:
        assert False, f'{INTEGRATION_NAME} Test.help_hash_type_checker() invalid type error'


def test_exception_helper():
    temp_dict = {"success": 0, "error_code": 115, "error": "Submission limit exceeded"}
    try:
        help_lastline_exception_handler(temp_dict)
    except DemistoException as error_msg:
        assert error_msg.args == DemistoException('error (115) Submission limit exceeded').args,\
            f'{INTEGRATION_NAME} Test.exception_helper() failed'
    else:
        assert False, f'{INTEGRATION_NAME} Test.exception_helper() failed'


def test_help_upload_and_status():
    help_upload_and_status(dict(), help_context_entry(f'{INTEGRATION_COMMAND_NAME}-check-status'))


def test_help_context_entry():
    assert help_context_entry('----') is None, f'{INTEGRATION_NAME} Test.help_hash_type_checker(\'----\') isn\'t None'
    assert help_context_entry('') is None, f'{INTEGRATION_NAME} Test.help_hash_type_checker(\'\') isn\'t None'
    assert help_context_entry(f'{INTEGRATION_COMMAND_NAME}-check-status') is not None,\
        f'{INTEGRATION_NAME} Test.help_hash_type_checker(\'{INTEGRATION_COMMAND_NAME}-check-status\') is None'


def test_help_get_report_context():
    help_get_report_context(dict())
