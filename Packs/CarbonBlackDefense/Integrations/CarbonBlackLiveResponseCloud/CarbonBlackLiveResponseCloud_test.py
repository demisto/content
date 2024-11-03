import functools

import pytest
from cbc_sdk.live_response_api import LiveResponseMemdump, LiveResponseSessionManager
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
        'device_id': 'test_device_id',
        'destination_path': 'test_destination_path',
        'file_id': 'test_file_id'
    },
    get_file_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'source_path': 'test_source_path',
        'timeout': '900', 'delay': '900'
    },
    delete_file_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'source_path': 'test_source_path'
    },
    create_reg_key_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'reg_path': 'test_reg_path'
    },
    set_reg_value_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'reg_path': 'test_reg_path',
        'value_data': 'test_value_data',
        'value_type': 'test_value_type',
        'overwrite': False
    },
    delete_reg_key_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'reg_path': 'test_reg_path',
    },
    delete_reg_value_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'reg_path': 'test_reg_path',
    },
    list_directory_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'directory_path': 'test_directory_path',
        'limit': 5
    },
    list_reg_sub_keys_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'reg_path': 'test_reg_path',
        'limit': '5'
    },
    get_reg_values_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'reg_path': 'test_reg_path',
        'limit': '5'
    },

    list_processes_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'limit': 5
    },
    kill_process_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'pid': '100'
    },
    create_process_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'command_string': 'test_cmd_line_path',
        'wait_for_output': 'True',
        'wait_for_completion': True
    },
    memdump_command: {
        'api_client': api_client,
        'device_id': 'test_device_id',
        'target_path': 'test_target_path'
    }
}

TEST_REG_VALUES = [
    dict(registry_type=f'test_pbREG_SZ_{i}',
         registry_name=f'test_val_{i}',
         registry_data=f'value_data_{i}')
    for i in range(10)]

TEST_DIR_LIST = [
    dict(size=25600, attributes=['TEST_ARCHIVE'],
         create_time=123, last_access_time=123,
         last_write_time='1970-01-02T03:46:40.000Z', filename=f'test_{i}.xls',
         alternate_name='test_$9EE1B~1.XLS')
    for i in range(10)]

TEST_PROCESSES = [
    dict(process_path=f'test_path_{i}', process_pid=i,
         process_cmdline=f'test_command_line_{i}',
         process_username=f'test_user_{i}')
    for i in range(10)]

SUB_KEY_LEN = 10
TEST_SUB_KEYS = {'sub_keys': [f'sub_{i}' for i in range(SUB_KEY_LEN)]}

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

    ('kill_process', kill_process_command, 'The process: 100 was killed successfully.', {},
     'The process: 100 was killed successfully.')
]

WRONG_ARGS = [
    ('set_registry_value', set_reg_value_command, dict(overwrite='f')),
    ('create_process', create_process_command, dict(wait_for_completion='f')),
    ('create_process', create_process_command, dict(wait_for_output='f')),
    ('create_process', create_process_command, dict(wait_timeout='wrong_val')),
    ('get_file', get_file_command, dict(timeout='wrong_val')),
    ('delete_registry_key', delete_reg_key_command, dict(force='wrong_val')),
    ('list_directory', list_directory_command, dict(limit='wrong_val')),
]

DIR_LIST_EXPECTED_OUTPUT = 'Name|Type|Date Modified|Size|\n|---|---|---|---|\n| test_0.xls | File | ' \
                           '1970-01-02T03:46:40.000Z | 25600'
#

HAPPY_PATH_ARGS_FOR_COMMAND_RESULTS = [
    ('list_registry_keys_and_values', list_reg_sub_keys_command, 'sub_1', (), TEST_SUB_KEYS),
    ('list_registry_values', get_reg_values_command, 'test_pbREG_SZ_1', (), TEST_REG_VALUES),
    ('list_processes', list_processes_command, 'test_path_1 | 1 | test_command_line_1', (), TEST_PROCESSES),
    ('list_directory', list_directory_command, DIR_LIST_EXPECTED_OUTPUT, (), TEST_DIR_LIST),
    ('create_process', create_process_command, 'פלט בעברית',
     dict(command_string='test_cmd_line_path', wait_timeout=30, wait_for_output=True, wait_for_completion=True),
     'פלט בעברית'.encode())
]


class MockedLRObject:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def lr_session(self):
        return self


MOCKED_LR_SESSION = MockedLRObject()


def raise_exception(exception_to_raise, *args):
    raise exception_to_raise


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

    test_mocker = mocker.patch('cbc_sdk.CBCloudAPI.select', return_value=MOCKED_LR_SESSION)

    def mock_method():
        lambda *args, **kwargs: None

    setattr(MOCKED_LR_SESSION, method_name, mock_method)  # Just defined method in the object
    test_mocker = mocker.patch.object(MOCKED_LR_SESSION, method_name, return_value=mocked_results)

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

        limit = arg_to_number(kwargs.get('limit'))
        if limit:
            assert len(res) <= limit

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

        mock_method_in_lr_session(mocker=mocker,
                                  method_name=api_method_to_be_mocked,
                                  mocked_results=[],
                                  )

        kwargs = commands_with_args[tested_command].copy()
        kwargs.update(wrong_args)
        with pytest.raises(ValueError):
            tested_command(**kwargs)

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

        limit = arg_to_number(kwargs.get('limit'))
        if limit:
            assert len(res.raw_response) <= limit

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
        mocker.patch('cbc_sdk.live_response_api.LiveResponseMemdump.wait')
        mock_method_in_lr_session(
            mocker=mocker,
            method_name='start_memdump',
            mocked_results=LiveResponseMemdump(None, None, None),
        )

        # run
        kwargs = commands_with_args[memdump_command]
        res = memdump_command(**kwargs)

        # assert
        assert res == 'Memory was successfully dumped to test_target_path.'

    @pytest.mark.parametrize('force, expected_call_count', [(False, 1), (True, 11)])
    def test_delete_reg_key_force(self, mocker, force, expected_call_count):
        """
            Given:
                - Reg key contain sub keys
            When:
                - run the delete reg key command with force arg true
            Then:
                - validate all sub keys was deleted
        """

        # prepare
        def mock_sub_keys(reg_key):
            return {'sub_keys': ['sub_key'] if reg_key.count('\\') < SUB_KEY_LEN else []}

        mock_method_in_lr_session(mocker=mocker, method_name='list_registry_keys_and_values')
        mocker.patch.object(MOCKED_LR_SESSION, 'list_registry_keys_and_values', side_effect=mock_sub_keys)
        mocked_method = mock_method_in_lr_session(mocker=mocker, method_name='delete_registry_key')

        # run
        kwargs = commands_with_args[delete_reg_key_command]
        kwargs['force'] = force
        delete_reg_key_command(**kwargs)

        assert mocked_method.call_count == expected_call_count

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
        mocker.patch.object(LiveResponseSessionManager, 'request_session')

        # run
        res = command_test_module(**kwargs)

        # assert
        res == 'ok'

    RAISE_EXCEPTION_PARAMS = [
        (errors.UnauthorizedError(''), AUTHORIZATION_ERROR_MSG),
        (errors.ConnectionError(''), CONNECTION_ERROR_MSG),
        (errors.ObjectNotFoundError('wrong org_id'), ORG_ID_ERROR_MSG)
    ]

    @pytest.mark.parametrize('exception_to_raise, expected_res', RAISE_EXCEPTION_PARAMS)
    def test_command_test_raise_exception(self, mocker, exception_to_raise, expected_res):
        """
            Given:
                - Args for test_command

            When:
                - Run the test_command

            Then:
                - raise exceptions and validate them

        """

        # prepare
        mocker.patch.object(LiveResponseSessionManager,
                            'request_session',
                            side_effect=functools.partial(raise_exception, exception_to_raise))

        # run
        kwargs = commands_with_args[command_test_module]
        with pytest.raises(DemistoException) as exc_info:
            command_test_module(**kwargs)

        # validate
        assert expected_res in exc_info.value.args[0]

    def test_not_implemented_command(self, mocker):
        """
            Given -
            When - Try to run not implemented command
            Then - Validate NotImplementedError was occurred
        """

        # prepare
        not_implemented_command = 'not_implemented'
        mocker.patch.object(demisto, 'command', return_value=not_implemented_command)
        mocker.patch.object(demisto, 'params', return_value={'custom_key': 'unit test',
                                                             'custom_id': 'unit test',
                                                             'org_key': 'unit test'})
        # run
        with pytest.raises(NotImplementedError) as exc_info:
            main()

        assert exc_info.value.args[0] == f'Command: {not_implemented_command} not implemented'
