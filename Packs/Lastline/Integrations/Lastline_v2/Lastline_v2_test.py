import pytest
from Lastline_v2 import *

from CommonServerPython import DemistoException

data_test_hash_type_checker = [
    ('4e492e797ccfc808715c2278484517b1', 'md5'),
    ('e18e9ebfc7204712ee6f27903e1e7a4256fccba0', 'sha1'),
    ('7f3aa0fda6513c9fc6803fbebb0100e3a3d2ded503317d325eb2bccc097cf27b', 'sha256'),
    ('0123456789', f'{INTEGRATION_NAME} File command support md5/ sha1/ sha256 only.')
]
data_test_exception_handler = [
    (
        {"success": 0, "error_code": 115, "error": "Submission limit exceeded"},
        str(DemistoException('error (115) Submission limit exceeded'))
    ),
    (
        {},
        str(DemistoException('No response'))
    ),
    (
        {'test': 'nothing'},
        str(DemistoException('No response'))
    ),
    (
        {'success': None},
        str(DemistoException('No response'))
    ),
    (
        {},
        str(DemistoException('No response'))
    )
]
data_test_get_report_context = [
    None,
    './data_test/get_report_file.json',
    './data_test/get_report_url.json'
]


@pytest.mark.parametrize('test, result', data_test_hash_type_checker)
def test_hash_type_checker(test: str, result: str):
    try:
        assert hash_type_checker(test) == result, f'{INTEGRATION_NAME} Test.hash_type_checker() == {result}'
    except DemistoException as error:
        assert str(error) == result, f'{INTEGRATION_NAME} Test.hash_type_checker() invalid type error'


@pytest.mark.parametrize('test, result', data_test_exception_handler)
def test_exception_handler(test: Dict, result: str):
    try:
        lastline_exception_handler(test)
    except DemistoException as error_msg:
        assert str(error_msg) == result, f'{INTEGRATION_NAME} Test.exception_helper() failed'


def test_file_hash():
    # ./data_test/get_report_file.json hard coded hash md5
    output = '7ec67d7adb2ecfa05f54c852b646eeac'
    assert output == file_hash('./data_test/get_report_file.json'), f'{INTEGRATION_NAME} error in file_hash'


@pytest.mark.parametrize('path', data_test_get_report_context)
def test_get_report_context(path):
    if path is None:
        assert {} == get_report_context({}), f'{INTEGRATION_NAME} get_report_context filed'
    else:
        out_dict = {}
        with open(path) as json_obj:
            json_obj = json_obj.read()
            out_dict = json.loads(json_obj)
        get_report_context(out_dict)


def raise_exception():
    raise DemistoException('error Missing required field \'uuid\'.')


def test_credentials_not_part_of_params(mocker):
    """
        When:
            - testing connect to integration, using API key and API token only.

        Then:
            - validating that main finishes successfully without raising an error

        """
    mocker.patch.object(demisto, 'params', return_value={'url': 'testurl.com',
                                                         'api_key': 'apikey',
                                                         'api_token': 'apitoken'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(Client, 'get_report', side_effect=raise_exception)
    assert main() is None


def raise_exception_3006():
    raise DemistoException('error (3006) Missing required field \'uuid\'.')


def test_connect_with_credentials(mocker):
    """
    Given:
        - connect cedentials

    When:
        - testing connect to integration, using credentials: email and password.

    Then:
        - validating no error is raised.

    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'testurl.com',
                                                         'api_key': 'apikey',
                                                         'api_token': 'apitoken'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(Client, 'get_report', side_effect=raise_exception_3006)
    client = Client(base_url='test.com', api_params={}, credentials={'identifier': 'identifier',
                                                                     'password': 'password'})
    assert client.test_module_command() == ('ok', {}, {})
