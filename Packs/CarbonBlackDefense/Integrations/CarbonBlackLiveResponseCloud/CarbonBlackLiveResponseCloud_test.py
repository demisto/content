import pytest
from CarbonBlackLiveResponseCloud import *
import demistomock as demisto

CREDENTIALS = dict(
    url='https://test.test',
    ssl_verify=False,
    token='test_key/test_id',
    org_key='test_org_key'
)

commands_with_args = {
    put_file_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'destination_path': 'test_destination_path',
        'file_id': 'test_file_id'
    },
    get_file_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'source_path': 'test_source_path',
        'timeout': '900', 'delay': '900'
    },
    delete_file_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'source_path': 'test_source_path'
    },
    create_reg_key_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path'
    },
    set_reg_value_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path',
        'value_data': 'test_value_data',
        'value_type': 'test_value_type',
        'overwrite': False
    },
    delete_reg_key_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path',
    },
    delete_reg_value_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path',
    },
    list_directory_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'directory_path': 'test_directory_path'
    },
    list_reg_sub_keys_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path'
    },
    get_reg_values_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'reg_path': 'test_reg_path'
    },

    list_processes_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
    },
    kill_process_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'pid': 'test_pid'
    },
    create_process_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'command_string': 'test_cmd_line_path'
    },
    memdump_command: {
        'credentials': CREDENTIALS,
        'sensor_id': 'test_sensor_id',
        'target_path': 'test_target_path'
    }
}

TEST_REG_VALUES = [
    {'value_type': 'test_pbREG_SZ_1', 'value_name': 'test_val_1', 'value_data': 'test_value_1'},
    {'value_type': 'test_pbREG_SZ_2', 'value_name': 'test_val_2', 'value_data': 'test_value_2'}]

TEST_DIR_LIST = [
    {'size': 25600, 'attributes': ['TEST_ARCHIVE'], 'create_time': 123, 'last_access_time': 123, 'last_write_time': 123, 'filename': 'test.xls', 'alternate_name': 'test_$9EE1B~1.XLS'}]

TEST_PROCESSES_RESULT = [
    dict(path='test_path_1', pid=1, command_line='test_command_line_1', username='test_user_1'),
    dict(path='test_path_2', pid=2, command_line='test_command_line_2', username='test_user_2')
]

HAPPY_PATH_ARGS = [
    # 'api_method_to_be_mocked': str, tested_command: function, expected_results: Any, expected_args: tuple, mocked_results: Any
    ('put_file', put_file_command, 'File: test_file_id is now exist in the remote destination test_destination_path', (), None),
    ('delete_file', delete_file_command, 'The file: test_source_path was deleted', ('test_source_path',), None),
    ('create_registry_key', create_reg_key_command, 'Reg key: test_reg_path, was created', (), None),
    ('set_registry_value', set_reg_value_command, 'Value was set to the reg key: test_reg_path', (), None),
    ('delete_registry_key', delete_reg_key_command, 'Registry key: test_reg_path was deleted', (), None),
    ('delete_registry_value', delete_reg_value_command, 'Registry value: test_reg_path was deleted', (), None),
    ('kill_process', kill_process_command, 'The process: test_pid was killed', (), 'The process: test_pid was killed'),
    ('create_process', create_process_command, 'test_process_output', (), 'test_process_output'),
    # ('start_memdump', memdump_command, 'Memory was dumped to test_target_path', (), None)
    ]

HAPPY_PATH_ARGS_FOR_COMMAND_RESULTS = [
    ('list_registry_keys_and_values', list_reg_sub_keys_command, 'sub_1', (), {'sub_keys': ['sub_1', 'sub_2']}),
    ('list_registry_values', get_reg_values_command, 'test_pbREG_SZ_1', (), TEST_REG_VALUES),
    ('list_processes', list_processes_command, 'test_path_1 | 1 | test_command_line_1', (), TEST_PROCESSES_RESULT),
    ('list_directory', list_directory_command, 'test.xls | File', (), TEST_DIR_LIST)
]


class MockedLRObject:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def lr_session(self):
        return self


def mock_method_in_lr_session(mocker, method_name, mocked_results=None):
    mocked_lr_session = MockedLRObject()
    test_mocker = mocker.patch('cbc_sdk.CBCloudAPI.select', return_value=mocked_lr_session)

    mock_method = lambda *args, **kwargs: None
    setattr(mocked_lr_session, method_name, mock_method)  # Just add mocked method to the object
    test_mocker = mocker.patch.object(mocked_lr_session, method_name, return_value=mocked_results)

    mocker.patch.object(demisto, 'getFilePath', return_value={
        "path": 'test_data/test.txt',
        "name": 'test'
    })
    return test_mocker


class TestCommands:
    EXPECTED_ARGS_JSON_FILE_PATH = 'test_data/expected_args.json'
    expected_commands_args = None


    # todo ask eli for the fileResult mock

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
            assert mocked_obj.call_args[0] == expected_args

    @pytest.mark.parametrize(
        'api_method_to_be_mocked, tested_command, '
        'expected_result, expected_args, mocked_results', HAPPY_PATH_ARGS_FOR_COMMAND_RESULTS)
    def test_readable_outputs(self, mocker,
                     api_method_to_be_mocked, tested_command,
                     expected_result, expected_args,
                     mocked_results):
        # Prepare
        mock_method_in_lr_session(
            mocker=mocker,
            method_name=api_method_to_be_mocked, mocked_results=mocked_results)

        # run
        kwargs = commands_with_args[tested_command]
        res = tested_command(**kwargs)

        # assert
        assert expected_result in res.readable_output
