import json
from datetime import datetime
from AWSApiModule import *
from AWSEKS import datetime_to_str, validate_args, list_clusters_command
from test_data.test_response import UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_datetime_to_str():
    """
        Given:
            - A data object with a datetime object.
        When:
            - running a command with a datetime object in the response.
        Then:
            - update the datetime object to the string representation of the date.
    """
    data = {
        'createdAt': datetime(2020, 1, 1, 12, 0, 0)
    }
    datetime_to_str(data, 'createdAt')
    assert data['createdAt'] == '2020-01-01T12:00:00Z'


def test_datetime_to_str_invalid():
    """
        Given:
            - A data object without a datetime object.
        When:
            - running a command without a datetime object in the response.
        Then:
            - assert that the datetime object doesn't exist in the data object.
    """
    data = {}
    datetime_to_str(data, 'createdAt')
    assert 'createdAt' not in data


def test_datetime_to_str_none():
    """
        Given:
            - A data object with a createdAt key and a None value.
        When:
            - running a command with a createdAt key in the response.
        Then:
            - assert that the datetime object wasn't updated, and equal to None.
    """
    data = {'createdAt': None}
    datetime_to_str(data, 'createdAt')
    assert not data['createdAt']


def test_validate_args_one_arg():
    """
        Given:
            - A logging argument.
        When:
            - running update_cluster_config_command.
        Then:
            - assert that the returned value is ok.
    """
    resources_vpc_config = {}
    logging_arg = {
        "clusterLogging": [
            {
                "types": ["api", "authenticator", "audit"],
                "enabled": True
            }
        ]
    }
    authentication_mode = ""
    result = validate_args(resources_vpc_config, logging_arg, authentication_mode)
    assert result == "ok"


def test_validate_args_no_args():
    """
        Given:
            - Empty arguments.
        When:
            - running update_cluster_config_command.
        Then:
            - assert that a ValueError is raised.
    """
    resources_vpc_config = {}
    logging_arg = {}
    authentication_mode = ""
    try:
        validate_args(resources_vpc_config, logging_arg, authentication_mode)
    except ValueError as e:
        assert str(e) == "Please provide exactly one of the following arguments: resources_vpc_config, logging or " \
                         "authentication_mode."


def test_validate_args_multiple_args():
    """
        Given:
            - All arguments (resources_vpc_config, logging_arg, authentication_mode).
        When:
            - running update_cluster_config_command.
        Then:
            - assert that a ValueError is raised.
    """
    resources_vpc_config = {
        'subnetIds': [
            'string',
        ],
        'securityGroupIds': [
            'string',
        ],
        'endpointPublicAccess': True,
        'endpointPrivateAccess': True,
        'publicAccessCidrs': [
            'string',
        ]
    }
    logging_arg = {
        "clusterLogging": [
            {
                "types": ["api", "authenticator", "audit"],
                "enabled": True
            }
        ]
    }
    authentication_mode = "API"
    try:
        validate_args(resources_vpc_config, logging_arg, authentication_mode)
    except ValueError as e:
        assert str(e) == "Please provide exactly one of the following arguments: resources_vpc_config, logging or " \
                         "authentication_mode."


class Boto3Client:
    def list_clusters(self):
        pass

    def update_cluster_config(self, clusterName, resourcesVpcConfig=None, logging=None, authenticationMode=None):
        pass


def test_list_clusters_command(mocker):
    """
        Given:
            - An empty args.
        When:
            - running list_clusters_command.
        Then:
            - assert that the readable output is correct.
    """
    response = {
        'clusters': [
            'cluster_name_1',
        ],
        'nextToken': None
    }
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_clusters", return_value=response)

    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    result = list_clusters_command(client, {})
    assert result.readable_output == '### The list of clusters\n|ClustersNames|\n|---|\n| cluster_name_1 |\n'


def test_list_clusters_command_with_next_token(mocker):
    """
        Given:
            - A limit.
        When:
            - running list_clusters_command.
        Then:
            - assert that the readable output is correct (containing the cluster name and next token).
    """
    response = {
        'clusters': [
            'cluster_name_1',
        ],
        'nextToken': 'NextToken'
    }
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_clusters", return_value=response)

    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    result = list_clusters_command(client, {'limit': '1'})
    assert result.readable_output == ('### The list of clusters\n|ClustersNames|NextToken|\n|---|---|\n'
                                      '| cluster_name_1 | NextToken |\n')


def test_list_clusters_command_with_pagination(mocker):
    """
        Given:
            - A large limit.
        When:
            - running list_clusters_command.
        Then:
            - assert that the readable output is correct (containing all the clusters names, after the pagination).
    """
    response1 = util_load_json("test_data/list_clusters.json").get('response_with_next_toke')
    response2 = util_load_json("test_data/list_clusters.json").get('response_without_next_token')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_clusters", side_effect=[response1, response2])

    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    result = list_clusters_command(client, {'limit': '200'})
    assert result.readable_output == ('### The list of clusters\n|ClustersNames|\n|---|\n| '
                                      'cluster_name_1,<br>cluster_name_100,<br>cluster_name_101 |\n')


def test_update_cluster_config_command(mocker):
    """
        Given:
            - A cluster name and a logging configuration.
        When:
            - running update_cluster_config_command.
        Then:
            - assert that the readable output and outputs are correct.
    """
    from AWSEKS import update_cluster_config_command
    expected_output = util_load_json("test_data/update_cluster_config.json").get('logging_expected_output')
    expected_readable_output = util_load_json("test_data/update_cluster_config.json").get('logging_expected_readable_output')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "update_cluster_config", return_value=UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    args = {
        "cluster_name": "cluster_name",
        "logging": "{'clusterLogging': [{'types': ['api', 'authenticator', 'audit'], 'enabled': true}]}"
    }
    result = update_cluster_config_command(client, args)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output
