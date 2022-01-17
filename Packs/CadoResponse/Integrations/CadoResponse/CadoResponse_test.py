"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

from cgi import test
import io
import json
from typing import Any
from pytest import raises

from CommonServerPython import DemistoException


def util_load_json(path: str) -> Any:
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_module_command_success(requests_mock):
    from CadoResponse import Client, test_module
    mock_response = {
        'status': 'Running'
    }

    requests_mock.get('https://test.com/api/v2/system/status', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    response = test_module(client)

    assert response == 'ok'

def test_create_project_command_success(requests_mock):
    from CadoResponse import Client, create_project_command
    mock_response = {
        'id': 1
    }

    requests_mock.post('https://test.com/api/v2/projects', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_name': 'testing-project',
        'project_description': 'This is a testing project'
    }

    response = create_project_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.Project'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response

def test_list_project_command_success(requests_mock):
    from CadoResponse import Client, list_project_command

    mock_response = [
        {
            "caseName": "Project Name",
            "created": "2021-10-18T10:36:33.140305",
            "deleted": False,
            "description": "Project Description",
            "id": 1,
            "status": "Pending",
            "users": [
                {
                    "display_name": "admin",
                    "id": 1,
                    "is_admin": True,
                    "login_type": 0,
                    "username": "admin"
                }
            ]
        }
    ]

    requests_mock.get('https://test.com/api/v2/projects', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'limit': 1
    }

    response = list_project_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.Projects'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response

def test_list_project_command_limit_success(requests_mock):
    from CadoResponse import Client, list_project_command

    mock_response = [
        {
            "caseName": "Project Name",
            "created": "2021-10-18T10:36:33.140305",
            "deleted": False,
            "description": "Project Description",
            "id": 1,
            "status": "Pending",
            "users": [
                {
                    "display_name": "admin",
                    "id": 1,
                    "is_admin": True,
                    "login_type": 0,
                    "username": "admin"
                }
            ]
        },
        {
            "caseName": "Project Name",
            "created": "2021-10-18T10:36:33.140305",
            "deleted": False,
            "description": "Project Description",
            "id": 1,
            "status": "Pending",
            "users": [
                {
                    "display_name": "admin",
                    "id": 1,
                    "is_admin": True,
                    "login_type": 0,
                    "username": "admin"
                }
            ]
        }
    ]

    trunc_response = [
        {
            "caseName": "Project Name",
            "created": "2021-10-18T10:36:33.140305",
            "deleted": False,
            "description": "Project Description",
            "id": 1,
            "status": "Pending",
            "users": [
                {
                    "display_name": "admin",
                    "id": 1,
                    "is_admin": True,
                    "login_type": 0,
                    "username": "admin"
                }
            ]
        }
    ]

    requests_mock.get('https://test.com/api/v2/projects', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'limit': 1
    }

    response = list_project_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.Projects'
    assert response.outputs_key_field == 'id'
    assert response.outputs == trunc_response


def test_get_pipeline_command_success(requests_mock):
    from CadoResponse import Client, get_pipeline_command

    mock_response = {
        "pipelines": [
            {
                "can_be_terminated": False,
                "created": "2021-10-20T13:04:21.198423",
                "evidence_id": 10,
                "evidence_name": "import_test.dd",
                "name": "",
                "pipeline_id": 9,
                "pipeline_type": "processing",
                "project_id": 1,
                "project_name": "1",
                "subtasks": [
                    {
                        "execution_duration": 0,
                        "finish_time": 1634735123.8961182,
                        "name": "Shutdown: Stopping worker machine.",
                        "name_key": "infrastructure.self_shutdown",
                        "notification_level": "Info",
                        "progress_text": [],
                        "start_time": 1634735123.8948352,
                        "state": "SUCCESS",
                        "task_id": "8b957153-fb64-47f0-8ad0-917e3411063e",
                        "total_stages": "null"
                    }
                ],
                "summary": {
                    "cancelled": 0,
                    "failure": 0,
                    "pending": 0,
                    "running": 0,
                    "success": 15,
                    "total": 15
                },
                "terminated": True,
                "user_id": 1,
                "user_name": "admin"
            }
        ]
    }

    requests_mock.get('https://test.com/api/v2/tasks/pipelines', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        "project_id": 1
    }

    response = get_pipeline_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.Pipelines'
    assert response.outputs_key_field == 'pipeline_id'
    assert response.outputs == [
        {
            "can_be_terminated": False,
            "created": "2021-10-20T13:04:21.198423",
            "evidence_id": 10,
            "evidence_name": "import_test.dd",
            "name": "",
            "pipeline_id": 9,
            "pipeline_type": "processing",
            "project_id": 1,
            "project_name": "1",
            "subtasks": [
                {
                    "execution_duration": 0,
                    "finish_time": 1634735123.8961182,
                    "name": "Shutdown: Stopping worker machine.",
                    "name_key": "infrastructure.self_shutdown",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 1634735123.8948352,
                    "state": "SUCCESS",
                    "task_id": "8b957153-fb64-47f0-8ad0-917e3411063e",
                    "total_stages": "null"
                }
            ],
            "summary": {
                "cancelled": 0,
                "failure": 0,
                "pending": 0,
                "running": 0,
                "success": 15,
                "total": 15
            },
            "terminated": True,
            "user_id": 1,
            "user_name": "admin"
        }
    ]


def test_get_pipeline_command_limit_success(requests_mock):
    from CadoResponse import Client, get_pipeline_command

    mock_response = {
        "pipelines": [
            {
                "can_be_terminated": False,
                "created": "2021-10-20T13:04:21.198423",
                "evidence_id": 10,
                "evidence_name": "import_test.dd",
                "name": "",
                "pipeline_id": 9,
                "pipeline_type": "processing",
                "project_id": 1,
                "project_name": "1",
                "subtasks": [
                    {
                        "execution_duration": 0,
                        "finish_time": 1634735123.8961182,
                        "name": "Shutdown: Stopping worker machine.",
                        "name_key": "infrastructure.self_shutdown",
                        "notification_level": "Info",
                        "progress_text": [],
                        "start_time": 1634735123.8948352,
                        "state": "SUCCESS",
                        "task_id": "8b957153-fb64-47f0-8ad0-917e3411063e",
                        "total_stages": "null"
                    }
                ],
                "summary": {
                    "cancelled": 0,
                    "failure": 0,
                    "pending": 0,
                    "running": 0,
                    "success": 15,
                    "total": 15
                },
                "terminated": True,
                "user_id": 1,
                "user_name": "admin"
            },
            {
                "can_be_terminated": False,
                "created": "2021-10-20T13:04:21.198423",
                "evidence_id": 10,
                "evidence_name": "import_test.dd",
                "name": "",
                "pipeline_id": 9,
                "pipeline_type": "processing",
                "project_id": 1,
                "project_name": "1",
                "subtasks": [
                    {
                        "execution_duration": 0,
                        "finish_time": 1634735123.8961182,
                        "name": "Shutdown: Stopping worker machine.",
                        "name_key": "infrastructure.self_shutdown",
                        "notification_level": "Info",
                        "progress_text": [],
                        "start_time": 1634735123.8948352,
                        "state": "SUCCESS",
                        "task_id": "8b957153-fb64-47f0-8ad0-917e3411063e",
                        "total_stages": "null"
                    }
                ],
                "summary": {
                    "cancelled": 0,
                    "failure": 0,
                    "pending": 0,
                    "running": 0,
                    "success": 15,
                    "total": 15
                },
                "terminated": True,
                "user_id": 1,
                "user_name": "admin"
            }
        ]
    }

    requests_mock.get('https://test.com/api/v2/tasks/pipelines', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        "project_id": 1,
        "limit": 1
    }

    response = get_pipeline_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.Pipelines'
    assert response.outputs_key_field == 'pipeline_id'
    assert response.outputs == [
        {
            "can_be_terminated": False,
            "created": "2021-10-20T13:04:21.198423",
            "evidence_id": 10,
            "evidence_name": "import_test.dd",
            "name": "",
            "pipeline_id": 9,
            "pipeline_type": "processing",
            "project_id": 1,
            "project_name": "1",
            "subtasks": [
                {
                    "execution_duration": 0,
                    "finish_time": 1634735123.8961182,
                    "name": "Shutdown: Stopping worker machine.",
                    "name_key": "infrastructure.self_shutdown",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 1634735123.8948352,
                    "state": "SUCCESS",
                    "task_id": "8b957153-fb64-47f0-8ad0-917e3411063e",
                    "total_stages": "null"
                }
            ],
            "summary": {
                "cancelled": 0,
                "failure": 0,
                "pending": 0,
                "running": 0,
                "success": 15,
                "total": 15
            },
            "terminated": True,
            "user_id": 1,
            "user_name": "admin"
        }
    ]


def test_list_ec2_command_success(requests_mock):
    from CadoResponse import Client, list_ec2_command

    mock_response = {
        "instances": [
            {
                "_placement": "us-west-2c",
                "_state": "stopped",
                "evidence_id": "null",
                "id": "i-0408ccfaa00778f9c",
                "instance_name": "DONOTDELETE-S509 SOF-ELK",
                "instance_type": "t2.2xlarge",
                "ip_address": "null",
                "launch_time": "Fri, 27 Aug 2021 16:17:40 GMT",
                "processing_type": "null",
                "project_id": "null",
                "region": {
                    "name": "us-west-2"
                }
            }
        ]
    }

    requests_mock.get('https://test.com/api/v2/projects/1/imports/ec2', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_id': 1,
        "region": "us-west-2"
    }

    response = list_ec2_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.EC2Instances'
    assert response.outputs_key_field == 'id'
    assert response.outputs == [
        {
            "_placement": "us-west-2c",
            "_state": "stopped",
            "evidence_id": "null",
            "id": "i-0408ccfaa00778f9c",
            "instance_name": "DONOTDELETE-S509 SOF-ELK",
            "instance_type": "t2.2xlarge",
            "ip_address": "null",
            "launch_time": "Fri, 27 Aug 2021 16:17:40 GMT",
            "processing_type": "null",
            "project_id": "null",
            "region": {
                "name": "us-west-2"
            }
        }
    ]


def test_list_s3_command_success(requests_mock):
    from CadoResponse import Client, list_s3_command

    mock_response = {
        "buckets": [
            "Bucket_name"
        ]
    }

    requests_mock.get('https://test.com/api/v2/projects/1/imports/s3', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_id': 1,
        "limit": 1
    }

    response = list_s3_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.S3Buckets'
    assert response.outputs == mock_response


def test_trigger_ec2_command_success(requests_mock):
    from CadoResponse import Client, trigger_ec2_command

    mock_response = {
        "created": "2021-11-01T13:12:57.046424",
        "evidence_id": 0,
        "name": "Acquiring ...",
        "pipeline_id": 3,
        "pipeline_type": "acquisition",
        "project_id": 2,
        "subtasks": [
            {
                "id": "11a63efc-0fbd-4271-9756-0e92545fe4e3",
            }
        ],
        "user_id": 1
    }

    requests_mock.post('https://test.com/api/v2/projects/1/imports/ec2', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_id': 1,
        "instance_id": "test",
        "region": "us-east=1",
        "bucket": "test-bucket",
        "compress": True,
        "include_disks": True,
        "include_hash": True,
        "include_logs": True,
        "include_screenshot": True
    }

    response = trigger_ec2_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.EC2Acquistion'
    assert response.outputs_key_field == 'pipeline_id'
    assert response.outputs == mock_response


def test_trigger_s3_command_success(requests_mock):
    from CadoResponse import Client, trigger_s3_command

    mock_response = {
        "pipelines": [
            {
                "created": "2021-11-01T13:12:57.046424",
                "evidence_id": 0,
                "name": "Acquiring ...",
                "pipeline_id": 3,
                "pipeline_type": "acquisition",
                "project_id": 2,
                "subtasks": [
                    {
                        "id": "11a63efc-0fbd-4271-9756-0e92545fe4e3",
                    }
                ],
                "user_id": 1
            }
        ]
    }

    requests_mock.post('https://test.com/api/v2/projects/1/imports/s3', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_id': 1,
        "file_name": "test",
        "bucket": "test-bucket"
    }

    response = trigger_s3_command(client, args)

    assert response.outputs_prefix == 'CadoResponse.S3Acquisition'
    assert response.outputs_key_field == 'pipeline_id'
    assert response.outputs == [
        {
            "created": "2021-11-01T13:12:57.046424",
            "evidence_id": 0,
            "name": "Acquiring ...",
            "pipeline_id": 3,
            "pipeline_type": "acquisition",
            "project_id": 2,
            "subtasks": [
                {
                    "id": "11a63efc-0fbd-4271-9756-0e92545fe4e3",
                }
            ],
            "user_id": 1
        }
    ]

def test_trigger_s3_command_raises_bucket():
    from CadoResponse import Client, trigger_s3_command

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_id': 1,
        "file_name": "test",
    }

    with raises(DemistoException, match='bucket is a required parameter!'):
        trigger_s3_command(client, args)

def test_trigger_s3_command_raises_file():
    from CadoResponse import Client, trigger_s3_command

    client = Client(
        base_url='https://test.com/api/v2/',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'project_id': 1,
        "bucket": "test",
    }

    with raises(DemistoException, match='file_name is a required parameter!'):
        trigger_s3_command(client, args)
