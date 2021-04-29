import pytest
from pytest import CaptureFixture
import CommonServerPython
from cbapi.live_response_api import LiveResponseMemdump
import tkinter

from CarbonBlackLiveResponseCloud import *
import demistomock as demisto

CREDENTIALS = dict(
    url='https://test.test',
    ssl_verify=False,
    token='test_key/test_id',
    org_key='test_org_key'
)
api_client = CBCloudAPI(**CREDENTIALS)

commands_with_args = {
    command_test_module: {
        'api_client': api_client
    },
    put_file_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'destination_path': 'test_destination_path',
        'file_id': 'test_file_id'
    },
    get_file_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'source_path': 'test_source_path',
        'timeout': '900', 'delay': '900'
    },
    delete_file_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'source_path': 'test_source_path'
    },
    create_reg_key_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path'
    },
    set_reg_value_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path',
        'value_data': 'test_value_data',
        'value_type': 'test_value_type',
        'overwrite': False
    },
    delete_reg_key_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path',
    },
    delete_reg_value_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path',
    },
    list_directory_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'directory_path': 'test_directory_path'
    },
    list_reg_sub_keys_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path'
    },
    get_reg_values_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path'
    },

    list_processes_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
    },
    kill_process_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'pid': 'test_pid'
    },
    create_process_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'command_string': 'test_cmd_line_path',
        'wait_for_output': 'True',
        'wait_for_completion': True
    },
    memdump_command: {
        'api_client': api_client,
        'sensor_id': 'test_sensor_id',
        'target_path': 'test_target_path'
    }
}

TEST_REG_VALUES = [
    {'value_type': 'test_pbREG_SZ_1', 'value_name': 'test_val_1', 'value_data': 'test_value_1'},
    {'value_type': 'test_pbREG_SZ_2', 'value_name': 'test_val_2', 'value_data': 'test_value_2'}]

TEST_DIR_LIST = [
    {
        'size': 25600, 'attributes': ['TEST_ARCHIVE'],
        'create_time': 123, 'last_access_time': 123,
        'last_write_time': 123, 'filename': 'test.xls',
        'alternate_name': 'test_$9EE1B~1.XLS'}]

TEST_PROCESSES_RESULT = [
    dict(path='test_path_1', pid=1, command_line='test_command_line_1', username='test_user_1'),
    dict(path='test_path_2', pid=2, command_line='test_command_line_2', username='test_user_2')
]

HAPPY_PATH_ARGS = [
    ('put_file', put_file_command, 'File: test_file_id is successfully put to the remote destination '
                                   'test_destination_path',
     {}, None),

    ('delete_file', delete_file_command, 'The file: test_source_path was deleted successfully.',
     dict(filename='test_source_path'), None),

    ('create_registry_key', create_reg_key_command, 'Reg key: test_reg_path, was created successfully.', {}, None),

    ('set_registry_value', set_reg_value_command, 'Value was set to the reg key: test_reg_path successfully.', {},
     None),

    ('delete_registry_key', delete_reg_key_command, 'Registry key: test_reg_path was deleted successfully.', {}, None),

    ('delete_registry_value', delete_reg_value_command, 'Registry value: test_reg_path was deleted successfully.', {},
     None),

    ('kill_process', kill_process_command, 'The process: test_pid was killed successfully.', {},
     'The process: test_pid was killed successfully.')
]

WRONG_ARGS = [
    ('set_registry_value', set_reg_value_command, dict(overwrite='f')),
    ('create_process', create_process_command, dict(wait_for_completion='f')),
    ('create_process', create_process_command, dict(wait_for_output='f')),
    ('create_process', create_process_command, dict(wait_timeout='wrong_val')),
    ('get_file', get_file_command, dict(timeout='wrong_val')),
]

#

HAPPY_PATH_ARGS_FOR_COMMAND_RESULTS = [
    ('list_registry_keys_and_values', list_reg_sub_keys_command, 'sub_1', (), {'sub_keys': ['sub_1', 'sub_2']}),
    ('list_registry_values', get_reg_values_command, 'test_pbREG_SZ_1', (), TEST_REG_VALUES),
    ('list_processes', list_processes_command, 'test_path_1 | 1 | test_command_line_1', (), TEST_PROCESSES_RESULT),
    ('list_directory', list_directory_command, 'test.xls | File', (), TEST_DIR_LIST),
    ('create_process', create_process_command, 'test_process_output',
     dict(command_string='test_cmd_line_path', wait_timeout=30, wait_for_output=True, wait_for_completion=True),
     'test_process_output')
]


class MockedLRObject:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def lr_session(self):
        return self


def raise_unauthorized_exception(**kwargs):
    raise errors.UnauthorizedError('test_uri')


def mock_method_in_lr_session(mocker, method_name, mocked_results=None):
    """
        mocked the required method in CBCloudAPI and CbLRSessionBase


        :type mocker: ``Mock``
        :param mocker: the pytest mock object

        :type method_name: ``str``
        :param method_name: The name of the method in CbLRSessionBase to be mocked e.g put_file

        :type mocked_results: ``Any``
        :param mocked_results: The result to return in call to the mocked method

        :rtype: ``Mock``
        :return: the mocked object
    """
    mocked_lr_session = MockedLRObject()
    test_mocker = mocker.patch('cbc_sdk.CBCloudAPI.select', return_value=mocked_lr_session)

    def mock_method():
        lambda *args, **kwargs: None

    setattr(mocked_lr_session, method_name, mock_method)  # Just defined method in the object
    test_mocker = mocker.patch.object(mocked_lr_session, method_name, return_value=mocked_results)

    mocker.patch.object(demisto, 'getFilePath', return_value={
        "path": 'test_data/test.txt',
        "name": 'test'
    })
    return test_mocker


class TestCommands:

    @pytest.mark.parametrize(
        'api_method_to_be_mocked, tested_command, expected_result, expected_args, mocked_results', HAPPY_PATH_ARGS)
    def test_commands_happy_path(
            self, mocker,
            api_method_to_be_mocked, tested_command,
            expected_result, expected_args,
            mocked_results):
        """

        Given:
            - Args for command to send via Live Response API (from commands_with_args)

        When:
            - Run the command

        Then:
            - Returns the command output

        """
        mocked_obj = mock_method_in_lr_session(
            mocker=mocker,
            method_name=api_method_to_be_mocked, mocked_results=mocked_results)

        kwargs = commands_with_args[tested_command]
        res = tested_command(**kwargs)

        # assert result
        assert res == expected_result

        if expected_args:
            assert mocked_obj.call_args[1] == expected_args

    @pytest.mark.parametrize(
        'api_method_to_be_mocked, tested_command, wrong_args', WRONG_ARGS)
    def test_commands_wrong_args(self, mocker, api_method_to_be_mocked, tested_command,
                                 wrong_args):
        """

        Given:
            - Args for command to send via Live Response API (from commands_with_args)

        When:
            - Run the command

        Then:
            - Returns the command output

        """

        mocked_obj = mock_method_in_lr_session(mocker=mocker,
                                               method_name=api_method_to_be_mocked,
                                               mocked_results=None,
                                               )

        kwargs = commands_with_args[tested_command]
        kwargs.update(wrong_args)
        try:
            tested_command(**kwargs)
            assert False, 'ValueError exception should occurred'

        except ValueError:
            pass  # expected

    @pytest.mark.parametrize(
        'api_method_to_be_mocked, tested_command, expected_result, expected_args, mocked_results',
        HAPPY_PATH_ARGS_FOR_COMMAND_RESULTS)
    def test_readable_outputs(self, mocker, api_method_to_be_mocked,
                              tested_command, expected_result,
                              expected_args, mocked_results):
        # prepare
        mock_method_in_lr_session(
            mocker=mocker,
            method_name=api_method_to_be_mocked, mocked_results=mocked_results)

        # run
        kwargs = commands_with_args[tested_command]
        res = tested_command(**kwargs)

        # assert
        assert expected_result in res.readable_output

    def test_memdump_command(self, mocker):
        """
            Given:
                - Args for memdump command to send via Live Response API (from commands_with_args)

            When:
                - Run the memdump command

            Then:
                - Returns the command output

        """
        # prepare
        mocker.patch('cbapi.live_response_api.LiveResponseMemdump.wait')
        mocked_obj = mock_method_in_lr_session(
            mocker=mocker,
            method_name='start_memdump',
            mocked_results=LiveResponseMemdump(None, None, None))

        # run
        kwargs = commands_with_args[memdump_command]
        res = memdump_command(**kwargs)

        # assert
        assert 'Memory was successfully dumped to test_target_path.' == res

    def test_command_test_happy_path(self, mocker):
        """
            Given:
                - Args for test_command

            When:
                - Run the test_command

            Then:
                - Validate the results

        """
        # prepare
        kwargs = commands_with_args[command_test_module]
        api = kwargs['api_client']
        mocker.patch.object(api, 'api_json_request')

        # run
        res = command_test_module(**kwargs)

        # assert
        res == 'ok'

    def test_command_test_raise_exception(self, mocker, capfd):
        """
            Given:
                - Args for test_command

            When:
                - Run the test_command

            Then:
                - raise exceptions and validate them

        """
        # prepare
        kwargs = commands_with_args[command_test_module]
        api = kwargs['api_client']
        mocker.patch.object(api, 'api_json_request', side_effect=raise_unauthorized_exception)

        # run
        with capfd.disabled():  # allowed output in the stdout in the end of test
            try:
                res = command_test_module(**kwargs)

                # assert
                assert False, 'should fail with SystemExit as return_error should occurred'
            except SystemExit:
                return
