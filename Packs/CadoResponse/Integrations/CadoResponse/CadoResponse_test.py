''' Tests for the Cado Response API Integration for the Cortex XSOAR Platform '''


from typing import Any

from CommonServerPython import CommandResults, DemistoException

from pytest import raises


def test_module_command_success(requests_mock: Any) -> None:
    '''
    Successful test for the test-module command.
    '''

    from CadoResponse import Client, test_module

    mock_get_response: dict[str, str] = {
        'status': 'Running'
    }

    expected_mocked_command_result: str = 'ok'

    requests_mock.get('https://test.com/api/v2/system/status', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    mocked_command_result: str = test_module(client)

    assert mocked_command_result == expected_mocked_command_result


def test_module_command_fail(requests_mock: Any) -> None:
    '''
    Unsuccessful test for the test-module command.
    '''

    from CadoResponse import Client, test_module

    mock_get_response: dict[str, str] = {
        'status': 'Down'
    }

    expected_mocked_command_result: str = 'Cado Response is not running'

    requests_mock.get('https://test.com/api/v2/system/status', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    mocked_command_result: str = test_module(client)

    assert mocked_command_result == expected_mocked_command_result


def test_create_project_command_success(requests_mock: Any) -> None:
    '''
    Successful test for the cado-create-project command.
    '''

    from CadoResponse import Client, create_project_command

    mock_post_response: dict[str, int] = {
        'id': 1
    }

    expected_mocked_command_result: dict[str, Any] = mock_post_response

    requests_mock.post('https://test.com/api/v2/projects', json=mock_post_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, str] = {
        'project_name': 'testing-project',
        'project_description': 'This is a testing project'
    }

    mocked_command_result: CommandResults = create_project_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Project'
    assert mocked_command_result.outputs_key_field == 'id'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_get_project_list_command_success(requests_mock: Any) -> None:
    '''
    Successful test for the cado-get-project (list version) command.
    '''

    from CadoResponse import Client, list_project_command

    mock_get_response: list[dict[str, Any]] = [
        {
            'caseName': 'Project Name',
            'created': '2021-10-18T10:36:33.140305',
            'deleted': False,
            'description': 'Project Description',
            'id': 1,
            'status': 'Pending',
            'users': [
                {
                    'display_name': 'admin',
                    'id': 1,
                    'is_admin': True,
                    'login_type': 0,
                    'username': 'admin'
                }
            ]
        }
    ]

    expected_mocked_command_result: list[dict[str, Any]] = mock_get_response

    requests_mock.get('https://test.com/api/v2/projects', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'limit': 1
    }

    mocked_command_result: CommandResults = list_project_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Projects'
    assert mocked_command_result.outputs_key_field == 'id'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_get_project_single_command_success(requests_mock: Any) -> Any:
    '''
    Successful test for the cado-list-project (single project) command.
    '''

    from CadoResponse import Client, list_project_command

    mock_get_response: list[dict[str, Any]] = [
        {
            'caseName': 'Project Name',
            'created': '2021-10-18T10:36:33.140305',
            'deleted': False,
            'description': 'Project Description',
            'id': 1,
            'status': 'Pending',
            'users': [
                {
                    'display_name': 'admin',
                    'id': 1,
                    'is_admin': True,
                    'login_type': 0,
                    'username': 'admin'
                }
            ]
        }
    ]

    expected_mocked_command_result: list[dict[str, Any]] = mock_get_response

    requests_mock.get('https://test.com/api/v2/projects/1', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'project_id': 1
    }

    mocked_command_result: CommandResults = list_project_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Projects'
    assert mocked_command_result.outputs_key_field == 'id'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_get_project_no_id_command_success(requests_mock: Any) -> Any:
    '''
    Successful test for the cado-get-project (w/ no id) command.
    '''

    from CadoResponse import Client, list_project_command

    mock_get_response: list[dict[str, Any]] = [
        {
            'caseName': 'Project Name',
            'created': '2021-10-18T10:36:33.140305',
            'deleted': False,
            'description': 'Project Description',
            'id': 1,
            'status': 'Pending',
            'users': [
                {
                    'display_name': 'admin',
                    'id': 1,
                    'is_admin': True,
                    'login_type': 0,
                    'username': 'admin'
                }
            ]
        }
    ]

    expected_mocked_command_result: list[dict[str, Any]] = mock_get_response

    requests_mock.get('https://test.com/api/v2/projects', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict = {}
    mocked_command_result: CommandResults = list_project_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Projects'
    assert mocked_command_result.outputs_key_field == 'id'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_get_project_command_limit_success(requests_mock: Any) -> None:
    '''
    Successful test for the cado-get-project (w/ limit) command.
    '''

    from CadoResponse import Client, list_project_command

    mock_get_response: list[dict[str, Any]] = [
        {
            'caseName': 'Project Name',
            'created': '2021-10-18T10:36:33.140305',
            'deleted': False,
            'description': 'Project Description',
            'id': 1,
            'status': 'Pending',
            'users': [
                {
                    'display_name': 'admin',
                    'id': 1,
                    'is_admin': True,
                    'login_type': 0,
                    'username': 'admin'
                }
            ]
        },
        {
            'caseName': 'Project Name',
            'created': '2021-10-18T10:36:33.140305',
            'deleted': False,
            'description': 'Project Description',
            'id': 1,
            'status': 'Pending',
            'users': [
                {
                    'display_name': 'admin',
                    'id': 1,
                    'is_admin': True,
                    'login_type': 0,
                    'username': 'admin'
                }
            ]
        }
    ]

    expected_mocked_command_result: list[dict[str, Any]] = [
        {
            'caseName': 'Project Name',
            'created': '2021-10-18T10:36:33.140305',
            'deleted': False,
            'description': 'Project Description',
            'id': 1,
            'status': 'Pending',
            'users': [
                {
                    'display_name': 'admin',
                    'id': 1,
                    'is_admin': True,
                    'login_type': 0,
                    'username': 'admin'
                }
            ]
        }
    ]

    requests_mock.get('https://test.com/api/v2/projects', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'limit': 1
    }

    mocked_command_result: CommandResults = list_project_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Projects'
    assert mocked_command_result.outputs_key_field == 'id'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_get_pipeline_command_success(requests_mock: Any) -> None:
    from CadoResponse import Client, get_pipeline_command

    mock_get_response: dict[str, Any] = {
        'pipelines': [
            {
                'can_be_terminated': False,
                'created': '2021-10-20T13:04:21.198423',
                'evidence_id': 10,
                'evidence_name': 'import_test.dd',
                'name': '',
                'pipeline_id': 9,
                'pipeline_type': 'processing',
                'project_id': 1,
                'project_name': '1',
                'subtasks': [
                    {
                        'execution_duration': 0,
                        'finish_time': 1634735123.8961182,
                        'name': 'Shutdown: Stopping worker machine.',
                        'name_key': 'infrastructure.self_shutdown',
                        'notification_level': 'Info',
                        'progress_text': [],
                        'start_time': 1634735123.8948352,
                        'state': 'SUCCESS',
                        'task_id': '8b957153-fb64-47f0-8ad0-917e3411063e',
                        'total_stages': 'null'
                    }
                ],
                'summary': {
                    'cancelled': 0,
                    'failure': 0,
                    'pending': 0,
                    'running': 0,
                    'success': 15,
                    'total': 15
                },
                'terminated': True,
                'user_id': 1,
                'user_name': 'admin'
            }
        ]
    }

    expected_mocked_command_results: list[dict[str, Any]] = [
        {
            'can_be_terminated': False,
            'created': '2021-10-20T13:04:21.198423',
            'evidence_id': 10,
            'evidence_name': 'import_test.dd',
            'name': '',
            'pipeline_id': 9,
            'pipeline_type': 'processing',
            'project_id': 1,
            'project_name': '1',
            'subtasks': [
                {
                    'execution_duration': 0,
                    'finish_time': 1634735123.8961182,
                    'name': 'Shutdown: Stopping worker machine.',
                    'name_key': 'infrastructure.self_shutdown',
                    'notification_level': 'Info',
                    'progress_text': [],
                    'start_time': 1634735123.8948352,
                    'state': 'SUCCESS',
                    'task_id': '8b957153-fb64-47f0-8ad0-917e3411063e',
                    'total_stages': 'null'
                }
            ],
            'summary': {
                'cancelled': 0,
                'failure': 0,
                'pending': 0,
                'running': 0,
                'success': 15,
                'total': 15
            },
            'terminated': True,
            'user_id': 1,
            'user_name': 'admin'
        }
    ]

    requests_mock.get('https://test.com/api/v2/tasks/pipelines', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'project_id': 1
    }

    mocked_command_result: CommandResults = get_pipeline_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Pipelines'
    assert mocked_command_result.outputs_key_field == 'pipeline_id'
    assert mocked_command_result.outputs == expected_mocked_command_results


def test_get_single_pipeline_command_success(requests_mock: Any) -> None:
    from CadoResponse import Client, get_pipeline_command

    mock_get_response: dict[str, Any] = {
        'pipelines': [
            {
                'can_be_terminated': False,
                'created': '2021-10-20T13:04:21.198423',
                'evidence_id': 10,
                'evidence_name': 'import_test.dd',
                'name': '',
                'pipeline_id': 9,
                'pipeline_type': 'processing',
                'project_id': 1,
                'project_name': '1',
                'subtasks': [
                    {
                        'execution_duration': 0,
                        'finish_time': 1634735123.8961182,
                        'name': 'Shutdown: Stopping worker machine.',
                        'name_key': 'infrastructure.self_shutdown',
                        'notification_level': 'Info',
                        'progress_text': [],
                        'start_time': 1634735123.8948352,
                        'state': 'SUCCESS',
                        'task_id': '8b957153-fb64-47f0-8ad0-917e3411063e',
                        'total_stages': 'null'
                    }
                ],
                'summary': {
                    'cancelled': 0,
                    'failure': 0,
                    'pending': 0,
                    'running': 0,
                    'success': 15,
                    'total': 15
                },
                'terminated': True,
                'user_id': 1,
                'user_name': 'admin'
            }
        ]
    }

    expected_mocked_command_result: dict[str, Any] = mock_get_response

    requests_mock.get('https://test.com/api/v2/tasks/pipelines', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'project_id': 1,
        'pipeline_id': 1
    }

    mocked_command_result: CommandResults = get_pipeline_command(client, args)

    assert mocked_command_result.outputs_prefix == 'CadoResponse.Pipelines'
    assert mocked_command_result.outputs_key_field == 'pipeline_id'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_get_pipeline_command_limit_success(requests_mock: Any) -> None:
    from CadoResponse import Client, get_pipeline_command

    mock_get_response: dict[str, Any] = {
        'pipelines': [
            {
                'can_be_terminated': False,
                'created': '2021-10-20T13:04:21.198423',
                'evidence_id': 10,
                'evidence_name': 'import_test.dd',
                'name': '',
                'pipeline_id': 9,
                'pipeline_type': 'processing',
                'project_id': 1,
                'project_name': '1',
                'subtasks': [
                    {
                        'execution_duration': 0,
                        'finish_time': 1634735123.8961182,
                        'name': 'Shutdown: Stopping worker machine.',
                        'name_key': 'infrastructure.self_shutdown',
                        'notification_level': 'Info',
                        'progress_text': [],
                        'start_time': 1634735123.8948352,
                        'state': 'SUCCESS',
                        'task_id': '8b957153-fb64-47f0-8ad0-917e3411063e',
                        'total_stages': 'null'
                    }
                ],
                'summary': {
                    'cancelled': 0,
                    'failure': 0,
                    'pending': 0,
                    'running': 0,
                    'success': 15,
                    'total': 15
                },
                'terminated': True,
                'user_id': 1,
                'user_name': 'admin'
            },
            {
                'can_be_terminated': False,
                'created': '2021-10-20T13:04:21.198423',
                'evidence_id': 10,
                'evidence_name': 'import_test.dd',
                'name': '',
                'pipeline_id': 9,
                'pipeline_type': 'processing',
                'project_id': 1,
                'project_name': '1',
                'subtasks': [
                    {
                        'execution_duration': 0,
                        'finish_time': 1634735123.8961182,
                        'name': 'Shutdown: Stopping worker machine.',
                        'name_key': 'infrastructure.self_shutdown',
                        'notification_level': 'Info',
                        'progress_text': [],
                        'start_time': 1634735123.8948352,
                        'state': 'SUCCESS',
                        'task_id': '8b957153-fb64-47f0-8ad0-917e3411063e',
                        'total_stages': 'null'
                    }
                ],
                'summary': {
                    'cancelled': 0,
                    'failure': 0,
                    'pending': 0,
                    'running': 0,
                    'success': 15,
                    'total': 15
                },
                'terminated': True,
                'user_id': 1,
                'user_name': 'admin'
            }
        ]
    }

    expected_mocked_command_results: list[dict[str, Any]] = [
        {
            'can_be_terminated': False,
            'created': '2021-10-20T13:04:21.198423',
            'evidence_id': 10,
            'evidence_name': 'import_test.dd',
            'name': '',
            'pipeline_id': 9,
            'pipeline_type': 'processing',
            'project_id': 1,
            'project_name': '1',
            'subtasks': [
                {
                    'execution_duration': 0,
                    'finish_time': 1634735123.8961182,
                    'name': 'Shutdown: Stopping worker machine.',
                    'name_key': 'infrastructure.self_shutdown',
                    'notification_level': 'Info',
                    'progress_text': [],
                    'start_time': 1634735123.8948352,
                    'state': 'SUCCESS',
                    'task_id': '8b957153-fb64-47f0-8ad0-917e3411063e',
                    'total_stages': 'null'
                }
            ],
            'summary': {
                'cancelled': 0,
                'failure': 0,
                'pending': 0,
                'running': 0,
                'success': 15,
                'total': 15
            },
            'terminated': True,
            'user_id': 1,
            'user_name': 'admin'
        }
    ]

    requests_mock.get('https://test.com/api/v2/tasks/pipelines', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'project_id': 1,
        'limit': 1
    }

    mocked_command_results: CommandResults = get_pipeline_command(client, args)

    assert mocked_command_results.outputs_prefix == 'CadoResponse.Pipelines'
    assert mocked_command_results.outputs_key_field == 'pipeline_id'
    assert mocked_command_results.outputs == expected_mocked_command_results


def test_list_ec2_command_success(requests_mock: Any) -> None:
    from CadoResponse import Client, list_ec2_command

    mock_get_response: dict[str, Any] = {
        'instances': [
            {
                '_placement': 'us-west-2c',
                '_state': 'stopped',
                'evidence_id': 'null',
                'id': 'i-0408ccfaa00778f9c',
                'instance_name': 'DONOTDELETE-S509 SOF-ELK',
                'instance_type': 't2.2xlarge',
                'ip_address': 'null',
                'launch_time': 'Fri, 27 Aug 2021 16:17:40 GMT',
                'processing_type': 'null',
                'project_id': 'null',
                'region': {
                    'name': 'us-west-2'
                }
            }
        ]
    }

    expected_mocked_command_results: list[dict[str, Any]] = [
        {
            '_placement': 'us-west-2c',
            '_state': 'stopped',
            'evidence_id': 'null',
            'id': 'i-0408ccfaa00778f9c',
            'instance_name': 'DONOTDELETE-S509 SOF-ELK',
            'instance_type': 't2.2xlarge',
            'ip_address': 'null',
            'launch_time': 'Fri, 27 Aug 2021 16:17:40 GMT',
            'processing_type': 'null',
            'project_id': 'null',
            'region': {
                'name': 'us-west-2'
            }
        }
    ]

    requests_mock.get('https://test.com/api/v2/projects/1/imports/ec2', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int | str] = {
        'project_id': 1,
        'region': 'us-west-2'
    }

    mocked_command_results: CommandResults = list_ec2_command(client, args)

    assert mocked_command_results.outputs_prefix == 'CadoResponse.EC2Instances'
    assert mocked_command_results.outputs_key_field == 'id'
    assert mocked_command_results.outputs == expected_mocked_command_results


def test_list_s3_command_success(requests_mock: Any) -> None:
    from CadoResponse import Client, list_s3_command

    mock_get_response: dict[str, list[str]] = {
        'buckets': [
            'Bucket_name'
        ]
    }

    expected_mocked_command_result: dict[str, list[str]] = mock_get_response

    requests_mock.get('https://test.com/api/v2/projects/1/imports/s3', json=mock_get_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int] = {
        'project_id': 1,
        'limit': 1
    }

    mocked_command_results: CommandResults = list_s3_command(client, args)

    assert mocked_command_results.outputs_prefix == 'CadoResponse.S3Buckets'
    assert mocked_command_results.outputs == expected_mocked_command_result


def test_trigger_ec2_command_success(requests_mock: Any) -> None:
    from CadoResponse import Client, trigger_ec2_command

    mock_post_response: dict[str, Any] = {
        'created': '2021-11-01T13:12:57.046424',
        'evidence_id': 0,
        'name': 'Acquiring ...',
        'pipeline_id': 3,
        'pipeline_type': 'acquisition',
        'project_id': 2,
        'subtasks': [
            {
                'id': '11a63efc-0fbd-4271-9756-0e92545fe4e3',
            }
        ],
        'user_id': 1
    }

    expected_mocked_command_result: dict[str, Any] = mock_post_response

    requests_mock.post('https://test.com/api/v2/projects/1/imports/ec2', json=mock_post_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, Any] = {
        'project_id': 1,
        'instance_id': 'test',
        'region': 'us-east=1',
        'bucket': 'test-bucket',
        'compress': True,
        'include_disks': True,
        'include_hash': True,
        'include_logs': True,
        'include_screenshot': True
    }

    mocked_command_results: CommandResults = trigger_ec2_command(client, args)

    assert mocked_command_results.outputs_prefix == 'CadoResponse.EC2Acquistion'
    assert mocked_command_results.outputs_key_field == 'pipeline_id'
    assert mocked_command_results.outputs == expected_mocked_command_result


def test_trigger_s3_command_success(requests_mock: Any) -> None:
    from CadoResponse import Client, trigger_s3_command

    mock_post_response: dict[str, Any] = {
        'pipelines': [
            {
                'created': '2021-11-01T13:12:57.046424',
                'evidence_id': 0,
                'name': 'Acquiring ...',
                'pipeline_id': 3,
                'pipeline_type': 'acquisition',
                'project_id': 2,
                'subtasks': [
                    {
                        'id': '11a63efc-0fbd-4271-9756-0e92545fe4e3',
                    }
                ],
                'user_id': 1
            }
        ]
    }

    expected_mocked_command_results: list[dict[str, Any]] = [
        {
            'created': '2021-11-01T13:12:57.046424',
            'evidence_id': 0,
            'name': 'Acquiring ...',
            'pipeline_id': 3,
            'pipeline_type': 'acquisition',
            'project_id': 2,
            'subtasks': [
                {
                    'id': '11a63efc-0fbd-4271-9756-0e92545fe4e3',
                }
            ],
            'user_id': 1
        }
    ]

    requests_mock.post('https://test.com/api/v2/projects/1/imports/s3', json=mock_post_response)

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int | str] = {
        'project_id': 1,
        'file_name': 'test',
        'bucket': 'test-bucket'
    }

    mocked_command_results: CommandResults = trigger_s3_command(client, args)

    assert mocked_command_results.outputs_prefix == 'CadoResponse.S3Acquisition'
    assert mocked_command_results.outputs_key_field == 'pipeline_id'
    assert mocked_command_results.outputs == expected_mocked_command_results


def test_trigger_s3_command_raises_bucket() -> None:
    from CadoResponse import Client, trigger_s3_command

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int | str] = {
        'project_id': 1,
        'file_name': 'test',
    }

    with raises(DemistoException, match='bucket is a required parameter!'):
        trigger_s3_command(client, args)


def test_trigger_s3_command_raises_file() -> None:
    from CadoResponse import Client, trigger_s3_command

    client: Client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args: dict[str, int | str] = {
        'project_id': 1,
        'bucket': 'test',
    }

    with raises(DemistoException, match='file_name is a required parameter!'):
        trigger_s3_command(client, args)
