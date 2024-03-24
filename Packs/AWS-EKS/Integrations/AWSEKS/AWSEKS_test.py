import json
from datetime import datetime

import pytest

from AWSApiModule import *
from AWSEKS import datetime_to_str, validate_args, list_clusters_command
from test_data.test_response import (UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE, DESCRIBE_CLUSTER_RESPONSE,
                                     UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE, CREATE_ACCESS_ENTRY_RESPONSE,
                                     ASSOCIATE_ACCESS_POLICY_RESPONSE, UPDATE_ACCESS_ENTRY_RESPONSE)


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

    def describe_cluster(self, clusterName):
        pass

    def create_access_entry(self, clusterName, principalArn, kubernetesGroups, tags, clientRequestToken, type):
        pass

    def associate_access_policy(self, clusterName, principalArn, policyArn, accessScope):
        pass

    def update_access_entry(self, clusterName, principalArn, kubernetesGroups, clientRequestToken, username):
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
    assert result.outputs == {'ClustersNames': ['cluster_name_1'], 'NextToken': None}


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
    assert result.readable_output == '### The list of clusters\n|ClustersNames|\n|---|\n| cluster_name_1 |\n'
    assert result.outputs == {'ClustersNames': ['cluster_name_1'], 'NextToken': 'NextToken'}


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
    assert result.readable_output == ('### The list of clusters\n|ClustersNames|\n|---|\n| cluster_name_1 |\n| cluster_name_100 '
                                      '|\n| cluster_name_101 |\n')
    assert result.outputs == {'ClustersNames': ['cluster_name_1', 'cluster_name_100', 'cluster_name_101'],
                              'NextToken': None}


def test_update_cluster_config_logging_command(mocker):
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


def test_update_cluster_config_authentication_mode_command(mocker):
    """
        Given:
            - A cluster name and an authentication mode.
        When:
            - running update_cluster_config_command.
        Then:
            - assert that update_cluster_config was called with the correct args.
    """
    from AWSEKS import update_cluster_config_command
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    http_request = mocker.patch.object(Boto3Client, "update_cluster_config",
                                       return_value=UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    args = {
        "cluster_name": "cluster_name",
        "authentication_mode": "API_AND_CONFIG_MAP"
    }
    access_config = {
        'authenticationMode': 'API_AND_CONFIG_MAP'
    }
    update_cluster_config_command(client, args)
    http_request.assert_called_with(name='cluster_name',
                                    accessConfig=access_config)


def test_describe_cluster_command(mocker):
    """
        Given:
            - A cluster name.
        When:
            - running describe_cluster_command.
        Then:
            - assert that the readable output and outputs are correct.
    """
    from AWSEKS import describe_cluster_command
    expected_readable_output = util_load_json("test_data/describe_cluster.json").get('expected_readable_output')
    expected_output = util_load_json("test_data/describe_cluster.json").get('expected_outputs')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "describe_cluster", return_value=DESCRIBE_CLUSTER_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    args = {
        "cluster_name": "cluster_name",
    }
    result = describe_cluster_command(client, args)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output


def test_create_access_entry_command(mocker):
    """
        Given:
            - A cluster name and a principal ARN.
        When:
            - running create_access_entry_command.
        Then:
            - assert that the readable output and outputs are correct.
    """
    from AWSEKS import create_access_entry_command
    expected_readable_output = util_load_json("test_data/create_access_entry.json").get('expected_readable_output')
    expected_output = util_load_json("test_data/create_access_entry.json").get('expected_outputs')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "create_access_entry", return_value=CREATE_ACCESS_ENTRY_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    args = {
        "cluster_name": "cluster_name",
        "principal_arn": "principal_arn"
    }
    result = create_access_entry_command(client, args)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output


def test_associate_access_policy_command(mocker):
    """
        Given:
            - A cluster name, a principal ARN, a policy ARN, and a type.
        When:
            - running associate_access_policy_command.
        Then:
            - assert that the readable output and outputs are correct.
    """
    from AWSEKS import associate_access_policy_command
    expected_readable_output = util_load_json("test_data/associate_access_policy.json").get('expected_readable_output')
    expected_output = util_load_json("test_data/associate_access_policy.json").get('expected_outputs')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "associate_access_policy", return_value=ASSOCIATE_ACCESS_POLICY_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    args = {
        "cluster_name": "clusterName",
        "principal_arn": "principalArn",
        "policy_arn": "policyArn",
        "type": "cluster"
    }
    result = associate_access_policy_command(client, args)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output


ARGS_CLUSTER = {
    "cluster_name": "cluster_name",
    "policy_arn": "policy_arn",
    "principal_arn": "principal_arn",
    "type": 'cluster'
}
ARGS_NAMESPACES = {
    "cluster_name": "cluster_name",
    "policy_arn": "policy_arn",
    "principal_arn": "principal_arn",
    "type": "namespace",
    "namespaces": "namespace_1"
}
ACCESS_SCOPE_CLUSTER = {
    'type': 'cluster',
    'namespaces': []
}
ACCESS_SCOPE_NAMESPACES = {
    'type': 'namespace',
    'namespaces': ["namespace_1"]
}


@pytest.mark.parametrize('args, access_scope', [
    (ARGS_CLUSTER, ACCESS_SCOPE_CLUSTER),
    (ARGS_NAMESPACES, ACCESS_SCOPE_NAMESPACES)
])
def test_associate_access_policy_command_type_cluster(mocker, args, access_scope):
    """
        Given:
            - A cluster name, a principal ARN, a policy ARN, and a type.
            - Case A: the type is cluster.
            - Case B: the type is namespace.
        When:
            - running associate_access_policy_command.
        Then:
            - assert that associate_access_policy_command was called with the correct args.
    """
    from AWSEKS import associate_access_policy_command
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    http_request = mocker.patch.object(Boto3Client, "associate_access_policy",
                                       return_value=UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    associate_access_policy_command(client, args)
    http_request.assert_called_with(clusterName=args['cluster_name'],
                                    principalArn=args["principal_arn"],
                                    policyArn=args["policy_arn"],
                                    accessScope=access_scope)


def test_update_access_entry_command(mocker):
    """
        Given:
            - A cluster name and a principal ARN.
        When:
            - running create_access_entry_command.
        Then:
            - assert that the readable output and outputs are correct.
    """
    from AWSEKS import update_access_entry_command
    expected_readable_output = util_load_json("test_data/update_access_entry.json").get('expected_readable_output')
    expected_output = util_load_json("test_data/update_access_entry.json").get('expected_outputs')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "update_access_entry", return_value=UPDATE_ACCESS_ENTRY_RESPONSE)
    client = AWSClient("aws_default_region", None, None, None,
                       None, "aws_access_key_id", "aws_secret_access_key", "verify_certificate", None, 5)
    args = {
        "cluster_name": "cluster_name",
        "principal_arn": "principal_arn"
    }
    result = update_access_entry_command(client, args)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output
