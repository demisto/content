from datetime import datetime

UPDATE_CLUSTER_CONFIG_LOGGING_RESPONSE = {
    "update": {
        "createdAt": datetime(2024, 1, 1),
        "error": [],
        "id": "11111111-1111-1111-1111-111111111111",
        "params": [
            {
                "type": "ClusterLogging",
                "value": "{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\"],\"enabled\":true}]}"
            }
        ],
        "status": "InProgress",
        "type": "LoggingUpdate"
    }
}

UPDATE_CLUSTER_CONFIG_ACCESS_CONFIG_RESPONSE = {
    "update": {
        "createdAt": datetime(2024, 1, 1),
        "error": [],
        "id": "11111111-1111-1111-1111-111111111111",
        "params": [
            {
                "type": "AuthenticationMode",
                "value": "{\"authenticationMode\": \"API_AND_CONFIG_MAP\"}"
            }
        ],
        "status": "InProgress",
        "type": "AccessConfigUpdate"
    }
}

DESCRIBE_CLUSTER_RESPONSE = {
    'cluster': {
        'name': 'cluster_name',
        'arn': 'arn',
        'createdAt': datetime(2024, 1, 1),
        'version': '1.29',
        'endpoint': 'endpoint',
        'roleArn': 'roleArn',
        'resourcesVpcConfig': {
            'subnetIds': [
                'subnetId',
            ],
            'securityGroupIds': [
                'securityGroupId',
            ],
            'clusterSecurityGroupId': 'clusterSecurityGroupId',
            'vpcId': 'string',
            'endpointPublicAccess': True,
            'endpointPrivateAccess': True,
            'publicAccessCidrs': [
                'publicAccessCidr',
            ]
        },
        'kubernetesNetworkConfig': {
            'serviceIpv4Cidr': 'serviceIpv4Cidr',
            'ipFamily': 'ipv4'
        },
        'logging': {
            'clusterLogging': [
                {
                    'types': [
                        'controllerManager', 'scheduler',
                    ],
                    'enabled': True
                },
            ]
        },
        'identity': {
            'oidc': {
                'issuer': 'issuer'
            }
        },
        'status': 'ACTIVE',
        'certificateAuthority': {
            'data': 'data'
        },
        'clientRequestToken': 'clientRequestToken',
        'platformVersion': 'ek.3',
        'tags': {},
        'encryptionConfig': [
            {
                'resources': [
                    'resources',
                ],
                'provider': {
                    'keyArn': 'keyArn'
                }
            },
        ],
        'connectorConfig': {
            'activationId': 'activationId',
            'activationCode': 'activationCode',
            'activationExpiry': datetime(2024, 1, 1),
            'provider': 'provider',
            'roleArn': 'roleArn'
        },
        'id': 'id',
        'health': {
            'issues': []
        },
        'outpostConfig': {
            'outpostArns': [
                'outpostArns',
            ],
            'controlPlaneInstanceType': 'controlPlaneInstanceType',
            'controlPlanePlacement': {
                'groupName': 'groupName'
            }
        },
        'accessConfig': {
            'bootstrapClusterCreatorAdminPermissions': True,
            'authenticationMode': 'API'
        }
    }
}

CREATE_ACCESS_ENTRY_RESPONSE = {
    'accessEntry': {
        'clusterName': 'cluster_name',
        'principalArn': 'principal_arn',
        'kubernetesGroups': [
            'kubernetesGroup',
        ],
        'accessEntryArn': 'accessEntryArn',
        'createdAt': datetime(2024, 1, 1),
        'modifiedAt': datetime(2024, 1, 1),
        'tags': {},
        'username': 'username',
        'type': 'STANDARD'
    }
}

ASSOCIATE_ACCESS_POLICY_RESPONSE = {
    'clusterName': 'clusterName',
    'principalArn': 'principalArn',
    'associatedAccessPolicy': {
        'policyArn': 'policyArn',
        'accessScope': {
            'type': 'cluster'
        },
        'associatedAt': datetime(2024, 1, 1),
        'modifiedAt': datetime(2024, 1, 1)
    }
}

UPDATE_ACCESS_ENTRY_RESPONSE = {
    'accessEntry': {
        'clusterName': 'cluster_name',
        'principalArn': 'principal_arn',
        'kubernetesGroups': [
            'kubernetesGroup',
        ],
        'accessEntryArn': 'accessEntryArn',
        'createdAt': datetime(2024, 1, 1),
        'modifiedAt': datetime(2024, 1, 1),
        'tags': {},
        'username': 'username',
        'type': 'STANDARD'
    }
}
