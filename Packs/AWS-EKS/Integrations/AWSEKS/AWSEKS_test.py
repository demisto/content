import importlib
import json
import demistomock as demisto  # noqa: F401

import pytest

from AWSEKS import validate_args, list_clusters_command, CommandResults
from test_data.test_response import (UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE, DESCRIBE_CLUSTER_RESPONSE,
                                     UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE, CREATE_ACCESS_ENTRY_RESPONSE,
                                     ASSOCIATE_ACCESS_POLICY_RESPONSE, UPDATE_ACCESS_ENTRY_RESPONSE)

AWSEKS = importlib.import_module("AWSEKS")


@pytest.fixture(autouse=True)
def mock_build_client(mocker, request):
    if request.node.name != "test_build_client":
        mocker.patch.object(AWSEKS, 'build_client', lambda _: Boto3Client)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_build_client(mocker):
    params = {'accounts_to_access': '1,2', "defaultRegion": "Region"}
    mocker.patch.object(AWSEKS, 'config_aws_session', return_value="aws_client")
    mocker.patch.object(demisto, 'params', return_value=params)

    aws_client = AWSEKS.build_client({})

    assert aws_client == "aws_client"


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
    authentication_mode = False
    try:
        validate_args(resources_vpc_config, logging_arg, authentication_mode)
    except Exception as e:
        pytest.fail(f"Unexpected Error {str(e)}")


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
    authentication_mode = False
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
    authentication_mode = True
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
    mocker.patch.object(Boto3Client, "list_clusters", return_value=response)
    result = list_clusters_command({})
    assert isinstance(result, CommandResults)
    assert result.readable_output == '### The list of clusters\n|Clusters Names|\n|---|\n| cluster_name_1 |\n'
    assert result.outputs == {'ClustersNames': ['cluster_name_1'], 'NextToken': None}

    result = list_clusters_command({})


def test_list_clusters_command_no_clusters(mocker):
    """
        Given:
            - An empty args.
        When:
            - running list_clusters_command.
        Then:
            - assert that the readable output is correct.
    """
    response = {
        'clusters': [],
        'nextToken': None
    }
    mocker.patch.object(Boto3Client, "list_clusters", return_value=response)
    result = list_clusters_command({})
    assert isinstance(result, CommandResults)
    assert result.readable_output == 'No clusters found.'
    assert result.outputs == {'ClustersNames': [], 'NextToken': None}


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
    mocker.patch.object(Boto3Client, "list_clusters", return_value=response)

    result = list_clusters_command({'limit': '1'})
    assert isinstance(result, CommandResults)
    assert result.readable_output == '### The list of clusters\n|Clusters Names|\n|---|\n| cluster_name_1 |\n'
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
    mocker.patch.object(Boto3Client, "list_clusters", side_effect=[response1, response2])

    result = list_clusters_command({'limit': '200'})
    assert isinstance(result, CommandResults)
    assert result.readable_output == ('### The list of clusters\n|Clusters Names|\n|---|\n| cluster_name_1 |\n| cluster_name_100 '
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
    mocker.patch.object(Boto3Client, "update_cluster_config", return_value=UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE)
    args = {
        "cluster_name": "cluster_name",
        "logging": "{'clusterLogging': [{'types': ['api', 'authenticator', 'audit'], 'enabled': true}]}"
    }

    result = update_cluster_config_command(args)
    assert isinstance(result, CommandResults)
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
    http_request = mocker.patch.object(Boto3Client, "update_cluster_config",
                                       return_value=UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE)
    args = {
        "cluster_name": "cluster_name",
        "authentication_mode": "true"
    }
    access_config = {
        'authenticationMode': 'API_AND_CONFIG_MAP'
    }
    update_cluster_config_command(args)
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
    mocker.patch.object(Boto3Client, "describe_cluster", return_value=DESCRIBE_CLUSTER_RESPONSE)
    args = {
        "cluster_name": "cluster_name",
    }
    result = describe_cluster_command(args)
    assert isinstance(result, CommandResults)
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
    mocker.patch.object(Boto3Client, "create_access_entry", return_value=CREATE_ACCESS_ENTRY_RESPONSE)
    args = {
        "cluster_name": "cluster_name",
        "principal_arn": "principal_arn"
    }
    result = create_access_entry_command(args)
    assert isinstance(result, CommandResults)
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
    mocker.patch.object(Boto3Client, "associate_access_policy", return_value=ASSOCIATE_ACCESS_POLICY_RESPONSE)
    args = {
        "cluster_name": "clusterName",
        "principal_arn": "principalArn",
        "policy_arn": "policyArn",
        "type": "cluster"
    }
    result = associate_access_policy_command(args)
    assert isinstance(result, CommandResults)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output


def test_associate_access_policy_command_namespaces():
    """
        Given:
            - A cluster name, a principal ARN, a policy ARN, and a type = namespaces.
        When:
            - running associate_access_policy_command.
        Then:
            - assert that an exception was raised.
    """
    from AWSEKS import associate_access_policy_command
    args = {
        "cluster_name": "clusterName",
        "principal_arn": "principalArn",
        "policy_arn": "policyArn",
        "type": "namespace"
    }
    try:
        associate_access_policy_command(args)
    except Exception as e:
        assert str(e) == "When the type_arg='namespace', you must enter a namespace."


def test_associate_access_policy_command_namespaces_assert_called_with(mocker):
    """
        Given:
            - A cluster name, a principal ARN, a policy ARN, and a type.
        When:
            - running associate_access_policy_command.
        Then:
            - assert that the http request was sent with the correct arguments.
    """
    from AWSEKS import associate_access_policy_command
    http_request = mocker.patch.object(Boto3Client, "associate_access_policy", return_value=ASSOCIATE_ACCESS_POLICY_RESPONSE)
    args = {
        "cluster_name": "clusterName",
        "principal_arn": "principalArn",
        "policy_arn": "policyArn",
        "type": "namespace",
        "namespaces": "namespace1"
    }
    access_scope = {
        "type": "namespace",
        "namespaces": ["namespace1"]
    }
    associate_access_policy_command(args)
    http_request.assert_called_with(clusterName=args.get('cluster_name'),
                                    principalArn=args.get("principal_arn"),
                                    policyArn=args.get("policy_arn"),
                                    accessScope=access_scope)


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
    http_request = mocker.patch.object(Boto3Client, "associate_access_policy",
                                       return_value=UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE)
    associate_access_policy_command(args)
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
    mocker.patch.object(Boto3Client, "update_access_entry", return_value=UPDATE_ACCESS_ENTRY_RESPONSE)
    args = {
        "cluster_name": "cluster_name",
        "principal_arn": "principal_arn"
    }
    result = update_access_entry_command(args)
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_output
