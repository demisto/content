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
