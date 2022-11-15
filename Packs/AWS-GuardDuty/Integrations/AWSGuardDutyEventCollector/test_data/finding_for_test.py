import datetime
from dateutil.tz import tzlocal

FINDING = {
    "AccountId": "account_id",
    "Arn": "so_on",
    "CreatedAt": "2022-08-16T07:22:39.893Z",
    "Description": "Finding description.",
    "Id": "some_id",
    "Partition": "aws",
    "Region": "some_region",
    "Resource": {
        "AccessKeyDetails": {
            "AccessKeyId": "GeneratedFindingAccessKeyId",
            "PrincipalId": "GeneratedFindingPrincipalId",
            "UserName": "GeneratedFindingUserName",
            "UserType": "IAMUser"
        },
        "InstanceDetails": {
            "AvailabilityZone": "GeneratedFindingInstaceAvailabilityZone",
            "IamInstanceProfile": {
                "Arn": "some_arn",
                "Id": "GeneratedFindingInstanceProfileId"
            },
            "ImageDescription": "GeneratedFindingInstaceImageDescription",
            "ImageId": "some_image",
            "InstanceId": "some_instance",
            "InstanceState": "running",
            "InstanceType": "some_type",
            "LaunchTime": "2016-08-02T02:05:06.000Z",
            "NetworkInterfaces": [
                {
                    "Ipv6Addresses": [],
                    "NetworkInterfaceId": "some_network_interface",
                    "PrivateDnsName": "GeneratedFindingPrivateDnsName",
                    "PrivateIpAddress": "10.0.0.1",
                    "PrivateIpAddresses": [
                        {
                            "PrivateDnsName": "GeneratedFindingPrivateName",
                            "PrivateIpAddress": "10.0.0.1"
                        }
                    ],
                    "PublicDnsName": "GeneratedFindingPublicDNSName",
                    "PublicIp": "10.0.0.1",
                    "SecurityGroups": [
                        {
                            "GroupId": "GeneratedFindingSecurityId",
                            "GroupName": "GeneratedFindingSecurityGroupName"
                        }
                    ],
                    "SubnetId": "GeneratedFindingSubnetId",
                    "VpcId": "GeneratedFindingVPCId"
                }
            ],
            "OutpostArn": "arn_outputs",
            "ProductCodes": [
                {}
            ],
            "Tags": [
                {
                    "Key": "GeneratedFindingInstaceTag1",
                    "Value": "GeneratedFindingInstaceValue1"
                },
                {
                    "Key": "GeneratedFindingInstaceTag2",
                    "Value": "GeneratedFindingInstaceTagValue2"
                },
                {
                    "Key": "GeneratedFindingInstaceTag3",
                    "Value": "GeneratedFindingInstaceTagValue3"
                },
                {
                    "Key": "GeneratedFindingInstaceTag4",
                    "Value": "GeneratedFindingInstaceTagValue4"
                },
                {
                    "Key": "GeneratedFindingInstaceTag5",
                    "Value": "GeneratedFindingInstaceTagValue5"
                },
                {
                    "Key": "GeneratedFindingInstaceTag6",
                    "Value": "GeneratedFindingInstaceTagValue6"
                },
                {
                    "Key": "GeneratedFindingInstaceTag7",
                    "Value": "GeneratedFindingInstaceTagValue7"
                },
                {
                    "Key": "GeneratedFindingInstaceTag8",
                    "Value": "GeneratedFindingInstaceTagValue8"
                },
                {
                    "Key": "GeneratedFindingInstaceTag9",
                    "Value": "GeneratedFindingInstaceTagValue9"
                }
            ]
        },
        "ResourceType": "S3Bucket",
        "S3BucketDetails": [
            {
                "Arn": "arn_bucket",
                "CreatedAt": datetime.datetime(2021, 12, 8, 23, 23, 50, tzinfo=tzlocal()),
                "Name": "GeneratedFindingS3Bucket",
                "Owner": {
                    "Id": "CanonicalId of Owner"
                },
                "PublicAccess": {
                    "EffectivePermission": "NOT_PUBLIC",
                    "PermissionConfiguration": {
                        "AccountLevelPermissions": {
                            "BlockPublicAccess": {
                                "BlockPublicAcls": False,
                                "BlockPublicPolicy": False,
                                "IgnorePublicAcls": False,
                                "RestrictPublicBuckets": False
                            }
                        },
                        "BucketLevelPermissions": {
                            "AccessControlList": {
                                "AllowsPublicReadAccess": False,
                                "AllowsPublicWriteAccess": False
                            },
                            "BlockPublicAccess": {
                                "BlockPublicAcls": False,
                                "BlockPublicPolicy": False,
                                "IgnorePublicAcls": False,
                                "RestrictPublicBuckets": False
                            },
                            "BucketPolicy": {
                                "AllowsPublicReadAccess": False,
                                "AllowsPublicWriteAccess": False
                            }
                        }
                    }
                },
                "Tags": [],
                "Type": "Destination"
            }
        ]
    },
    "SchemaVersion": "2.0",
    "Service": {
        "Action": {
            "ActionType": "AWS_API_CALL",
            "AwsApiCallAction": {
                "Api": "GeneratedFindingAPIName",
                "CallerType": "Remote IP",
                "ErrorCode": "AccessDenied",
                "RemoteIpDetails": {
                    "City": {
                        "CityName": "GeneratedFindingCityName"
                    },
                    "Country": {
                        "CountryName": "GeneratedFindingCountryName"
                    },
                    "GeoLocation": {
                        "Lat": 0,
                        "Lon": 0
                    },
                    "IpAddressV4": "10.0.0.1",
                    "Organization": {
                        "Asn": "-1",
                        "AsnOrg": "GeneratedFindingASNOrg",
                        "Isp": "GeneratedFindingISP",
                        "Org": "GeneratedFindingOrg"
                    }
                },
                "ServiceName": "GeneratedFindingAPIServiceName"
            }
        },
        "Archived": False,
        "Count": 1,
        "DetectorId": "some_detector_id",
        "EventFirstSeen": "2022-08-16T07:22:39.000Z",
        "EventLastSeen": "2022-08-16T07:22:39.000Z",
        "ResourceRole": "TARGET",
        "ServiceName": "guardduty"
    },
    "Severity": 8,
    "Title": "Some title.",
    "Type": "some_type",
    "UpdatedAt": "2022-08-16T07:22:39.893Z"
}

FINDING_OUTPUT = {
    "AccountId": "account_id",
    "Arn": "so_on",
    "CreatedAt": "2022-08-16T07:22:39.893Z",
    "Description": "Finding description.",
    "Id": "some_id",
    "Partition": "aws",
    "Region": "some_region",
    "Resource": {
        "AccessKeyDetails": {
            "AccessKeyId": "GeneratedFindingAccessKeyId",
            "PrincipalId": "GeneratedFindingPrincipalId",
            "UserName": "GeneratedFindingUserName",
            "UserType": "IAMUser"
        },
        "InstanceDetails": {
            "AvailabilityZone": "GeneratedFindingInstaceAvailabilityZone",
            "IamInstanceProfile": {
                "Arn": "some_arn",
                "Id": "GeneratedFindingInstanceProfileId"
            },
            "ImageDescription": "GeneratedFindingInstaceImageDescription",
            "ImageId": "some_image",
            "InstanceId": "some_instance",
            "InstanceState": "running",
            "InstanceType": "some_type",
            "LaunchTime": "2016-08-02T02:05:06.000Z",
            "NetworkInterfaces": [
                {
                    "Ipv6Addresses": [],
                    "NetworkInterfaceId": "some_network_interface",
                    "PrivateDnsName": "GeneratedFindingPrivateDnsName",
                    "PrivateIpAddress": "10.0.0.1",
                    "PrivateIpAddresses": [
                        {
                            "PrivateDnsName": "GeneratedFindingPrivateName",
                            "PrivateIpAddress": "10.0.0.1"
                        }
                    ],
                    "PublicDnsName": "GeneratedFindingPublicDNSName",
                    "PublicIp": "10.0.0.1",
                    "SecurityGroups": [
                        {
                            "GroupId": "GeneratedFindingSecurityId",
                            "GroupName": "GeneratedFindingSecurityGroupName"
                        }
                    ],
                    "SubnetId": "GeneratedFindingSubnetId",
                    "VpcId": "GeneratedFindingVPCId"
                }
            ],
            "OutpostArn": "arn_outputs",
            "ProductCodes": [
                {}
            ],
            "Tags": [
                {
                    "Key": "GeneratedFindingInstaceTag1",
                    "Value": "GeneratedFindingInstaceValue1"
                },
                {
                    "Key": "GeneratedFindingInstaceTag2",
                    "Value": "GeneratedFindingInstaceTagValue2"
                },
                {
                    "Key": "GeneratedFindingInstaceTag3",
                    "Value": "GeneratedFindingInstaceTagValue3"
                },
                {
                    "Key": "GeneratedFindingInstaceTag4",
                    "Value": "GeneratedFindingInstaceTagValue4"
                },
                {
                    "Key": "GeneratedFindingInstaceTag5",
                    "Value": "GeneratedFindingInstaceTagValue5"
                },
                {
                    "Key": "GeneratedFindingInstaceTag6",
                    "Value": "GeneratedFindingInstaceTagValue6"
                },
                {
                    "Key": "GeneratedFindingInstaceTag7",
                    "Value": "GeneratedFindingInstaceTagValue7"
                },
                {
                    "Key": "GeneratedFindingInstaceTag8",
                    "Value": "GeneratedFindingInstaceTagValue8"
                },
                {
                    "Key": "GeneratedFindingInstaceTag9",
                    "Value": "GeneratedFindingInstaceTagValue9"
                }
            ]
        },
        "ResourceType": "S3Bucket",
        "S3BucketDetails": [
            {
                "Arn": "arn_bucket",
                "CreatedAt": "2021-12-08T23:23:50.000000",
                "Name": "GeneratedFindingS3Bucket",
                "Owner": {
                    "Id": "CanonicalId of Owner"
                },
                "PublicAccess": {
                    "EffectivePermission": "NOT_PUBLIC",
                    "PermissionConfiguration": {
                        "AccountLevelPermissions": {
                            "BlockPublicAccess": {
                                "BlockPublicAcls": False,
                                "BlockPublicPolicy": False,
                                "IgnorePublicAcls": False,
                                "RestrictPublicBuckets": False
                            }
                        },
                        "BucketLevelPermissions": {
                            "AccessControlList": {
                                "AllowsPublicReadAccess": False,
                                "AllowsPublicWriteAccess": False
                            },
                            "BlockPublicAccess": {
                                "BlockPublicAcls": False,
                                "BlockPublicPolicy": False,
                                "IgnorePublicAcls": False,
                                "RestrictPublicBuckets": False
                            },
                            "BucketPolicy": {
                                "AllowsPublicReadAccess": False,
                                "AllowsPublicWriteAccess": False
                            }
                        }
                    }
                },
                "Tags": [],
                "Type": "Destination"
            }
        ]
    },
    "SchemaVersion": "2.0",
    "Service": {
        "Action": {
            "ActionType": "AWS_API_CALL",
            "AwsApiCallAction": {
                "Api": "GeneratedFindingAPIName",
                "CallerType": "Remote IP",
                "ErrorCode": "AccessDenied",
                "RemoteIpDetails": {
                    "City": {
                        "CityName": "GeneratedFindingCityName"
                    },
                    "Country": {
                        "CountryName": "GeneratedFindingCountryName"
                    },
                    "GeoLocation": {
                        "Lat": 0,
                        "Lon": 0
                    },
                    "IpAddressV4": "10.0.0.1",
                    "Organization": {
                        "Asn": "-1",
                        "AsnOrg": "GeneratedFindingASNOrg",
                        "Isp": "GeneratedFindingISP",
                        "Org": "GeneratedFindingOrg"
                    }
                },
                "ServiceName": "GeneratedFindingAPIServiceName"
            }
        },
        "Archived": False,
        "Count": 1,
        "DetectorId": "some_detector_id",
        "EventFirstSeen": "2022-08-16T07:22:39.000Z",
        "EventLastSeen": "2022-08-16T07:22:39.000Z",
        "ResourceRole": "TARGET",
        "ServiceName": "guardduty"
    },
    "Severity": 8,
    "Title": "Some title.",
    "Type": "some_type",
    "UpdatedAt": "2022-08-16T07:22:39.893Z"
}

MOST_GENERAL_FINDING = {
    'AccountId': 'string',
    'Arn': 'string',
    'Confidence': 123.0,
    'CreatedAt': 'string',
    'Description': 'string',
    'Id': 'string',
    'Partition': 'string',
    'Region': 'string',
    'Resource': {
        'AccessKeyDetails': {
            'AccessKeyId': 'string',
            'PrincipalId': 'string',
            'UserName': 'string',
            'UserType': 'string'
        },
        'S3BucketDetails': [
            {
                'Arn': 'string',
                'Name': 'string',
                'Type': 'string',
                'CreatedAt': datetime.datetime(2015, 1, 1),
                'Owner': {
                    'Id': 'string'
                },
                'Tags': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    },
                ],
                'DefaultServerSideEncryption': {
                    'EncryptionType': 'string',
                    'KmsMasterKeyArn': 'string'
                },
                'PublicAccess': {
                    'PermissionConfiguration': {
                        'BucketLevelPermissions': {
                            'AccessControlList': {
                                'AllowsPublicReadAccess': True,
                                'AllowsPublicWriteAccess': True
                            },
                            'BucketPolicy': {
                                'AllowsPublicReadAccess': True,
                                'AllowsPublicWriteAccess': True
                            },
                            'BlockPublicAccess': {
                                'IgnorePublicAcls': True,
                                'RestrictPublicBuckets': True,
                                'BlockPublicAcls': True,
                                'BlockPublicPolicy': True
                            }
                        },
                        'AccountLevelPermissions': {
                            'BlockPublicAccess': {
                                'IgnorePublicAcls': True,
                                'RestrictPublicBuckets': True,
                                'BlockPublicAcls': True,
                                'BlockPublicPolicy': True
                            }
                        }
                    },
                    'EffectivePermission': 'string'
                }
            },
        ],
        'InstanceDetails': {
            'AvailabilityZone': 'string',
            'IamInstanceProfile': {
                'Arn': 'string',
                'Id': 'string'
            },
            'ImageDescription': 'string',
            'ImageId': 'string',
            'InstanceId': 'string',
            'InstanceState': 'string',
            'InstanceType': 'string',
            'OutpostArn': 'string',
            'LaunchTime': 'string',
            'NetworkInterfaces': [
                {
                    'Ipv6Addresses': [
                        'string',
                    ],
                    'NetworkInterfaceId': 'string',
                    'PrivateDnsName': 'string',
                    'PrivateIpAddress': 'string',
                    'PrivateIpAddresses': [
                        {
                            'PrivateDnsName': 'string',
                            'PrivateIpAddress': 'string'
                        },
                    ],
                    'PublicDnsName': 'string',
                    'PublicIp': 'string',
                    'SecurityGroups': [
                        {
                            'GroupId': 'string',
                            'GroupName': 'string'
                        },
                    ],
                    'SubnetId': 'string',
                    'VpcId': 'string'
                },
            ],
            'Platform': 'string',
            'ProductCodes': [
                {
                    'Code': 'string',
                    'ProductType': 'string'
                },
            ],
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ]
        },
        'EksClusterDetails': {
            'Name': 'string',
            'Arn': 'string',
            'VpcId': 'string',
            'Status': 'string',
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ],
            'CreatedAt': datetime.datetime(2015, 1, 1)
        },
        'KubernetesDetails': {
            'KubernetesUserDetails': {
                'Username': 'string',
                'Uid': 'string',
                'Groups': [
                    'string',
                ]
            },
            'KubernetesWorkloadDetails': {
                'Name': 'string',
                'Type': 'string',
                'Uid': 'string',
                'Namespace': 'string',
                'HostNetwork': True,
                'Containers': [
                    {
                        'ContainerRuntime': 'string',
                        'Id': 'string',
                        'Name': 'string',
                        'Image': 'string',
                        'ImagePrefix': 'string',
                        'VolumeMounts': [
                            {
                                'Name': 'string',
                                'MountPath': 'string'
                            },
                        ],
                        'SecurityContext': {
                            'Privileged': True
                        }
                    },
                ],
                'Volumes': [
                    {
                        'Name': 'string',
                        'HostPath': {
                            'Path': 'string'
                        }
                    },
                ]
            }
        },
        'ResourceType': 'string',
        'EbsVolumeDetails': {
            'ScannedVolumeDetails': [
                {
                    'VolumeArn': 'string',
                    'VolumeType': 'string',
                    'DeviceName': 'string',
                    'VolumeSizeInGB': 123,
                    'EncryptionType': 'string',
                    'SnapshotArn': 'string',
                    'KmsKeyArn': 'string'
                },
            ],
            'SkippedVolumeDetails': [
                {
                    'VolumeArn': 'string',
                    'VolumeType': 'string',
                    'DeviceName': 'string',
                    'VolumeSizeInGB': 123,
                    'EncryptionType': 'string',
                    'SnapshotArn': 'string',
                    'KmsKeyArn': 'string'
                },
            ]
        },
        'EcsClusterDetails': {
            'Name': 'string',
            'Arn': 'string',
            'Status': 'string',
            'ActiveServicesCount': 123,
            'RegisteredContainerInstancesCount': 123,
            'RunningTasksCount': 123,
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ],
            'TaskDetails': {
                'Arn': 'string',
                'DefinitionArn': 'string',
                'Version': 'string',
                'TaskCreatedAt': datetime.datetime(2015, 1, 1),
                'StartedAt': datetime.datetime(2015, 1, 1),
                'StartedBy': 'string',
                'Tags': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    },
                ],
                'Volumes': [
                    {
                        'Name': 'string',
                        'HostPath': {
                            'Path': 'string'
                        }
                    },
                ],
                'Containers': [
                    {
                        'ContainerRuntime': 'string',
                        'Id': 'string',
                        'Name': 'string',
                        'Image': 'string',
                        'ImagePrefix': 'string',
                        'VolumeMounts': [
                            {
                                'Name': 'string',
                                'MountPath': 'string'
                            },
                        ],
                        'SecurityContext': {
                            'Privileged': True
                        }
                    },
                ],
                'Group': 'string'
            }
        },
        'ContainerDetails': {
            'ContainerRuntime': 'string',
            'Id': 'string',
            'Name': 'string',
            'Image': 'string',
            'ImagePrefix': 'string',
            'VolumeMounts': [
                {
                    'Name': 'string',
                    'MountPath': 'string'
                },
            ],
            'SecurityContext': {
                'Privileged': True
            }
        }
    },
    'SchemaVersion': 'string',
    'Service': {
        'Action': {
            'ActionType': 'string',
            'AwsApiCallAction': {
                'Api': 'string',
                'CallerType': 'string',
                'DomainDetails': {
                    'Domain': 'string'
                },
                'ErrorCode': 'string',
                'UserAgent': 'string',
                'RemoteIpDetails': {
                    'City': {
                        'CityName': 'string'
                    },
                    'Country': {
                        'CountryCode': 'string',
                        'CountryName': 'string'
                    },
                    'GeoLocation': {
                        'Lat': 123.0,
                        'Lon': 123.0
                    },
                    'IpAddressV4': 'string',
                    'Organization': {
                        'Asn': 'string',
                        'AsnOrg': 'string',
                        'Isp': 'string',
                        'Org': 'string'
                    }
                },
                'ServiceName': 'string',
                'RemoteAccountDetails': {
                    'AccountId': 'string',
                    'Affiliated': True
                },
                'AffectedResources': {
                    'string': 'string'
                }
            },
            'DnsRequestAction': {
                'Domain': 'string',
                'Protocol': 'string',
                'Blocked': True
            },
            'NetworkConnectionAction': {
                'Blocked': True,
                'ConnectionDirection': 'string',
                'LocalPortDetails': {
                    'Port': 123,
                    'PortName': 'string'
                },
                'Protocol': 'string',
                'LocalIpDetails': {
                    'IpAddressV4': 'string'
                },
                'RemoteIpDetails': {
                    'City': {
                        'CityName': 'string'
                    },
                    'Country': {
                        'CountryCode': 'string',
                        'CountryName': 'string'
                    },
                    'GeoLocation': {
                        'Lat': 123.0,
                        'Lon': 123.0
                    },
                    'IpAddressV4': 'string',
                    'Organization': {
                        'Asn': 'string',
                        'AsnOrg': 'string',
                        'Isp': 'string',
                        'Org': 'string'
                    }
                },
                'RemotePortDetails': {
                    'Port': 123,
                    'PortName': 'string'
                }
            },
            'PortProbeAction': {
                'Blocked': True,
                'PortProbeDetails': [
                    {
                        'LocalPortDetails': {
                            'Port': 123,
                            'PortName': 'string'
                        },
                        'LocalIpDetails': {
                            'IpAddressV4': 'string'
                        },
                        'RemoteIpDetails': {
                            'City': {
                                'CityName': 'string'
                            },
                            'Country': {
                                'CountryCode': 'string',
                                'CountryName': 'string'
                            },
                            'GeoLocation': {
                                'Lat': 123.0,
                                'Lon': 123.0
                            },
                            'IpAddressV4': 'string',
                            'Organization': {
                                'Asn': 'string',
                                'AsnOrg': 'string',
                                'Isp': 'string',
                                'Org': 'string'
                            }
                        }
                    },
                ]
            },
            'KubernetesApiCallAction': {
                'RequestUri': 'string',
                'Verb': 'string',
                'SourceIps': [
                    'string',
                ],
                'UserAgent': 'string',
                'RemoteIpDetails': {
                    'City': {
                        'CityName': 'string'
                    },
                    'Country': {
                        'CountryCode': 'string',
                        'CountryName': 'string'
                    },
                    'GeoLocation': {
                        'Lat': 123.0,
                        'Lon': 123.0
                    },
                    'IpAddressV4': 'string',
                    'Organization': {
                        'Asn': 'string',
                        'AsnOrg': 'string',
                        'Isp': 'string',
                        'Org': 'string'
                    }
                },
                'StatusCode': 123,
                'Parameters': 'string'
            }
        },
        'Evidence': {
            'ThreatIntelligenceDetails': [
                {
                    'ThreatListName': 'string',
                    'ThreatNames': [
                        'string',
                    ]
                },
            ]
        },
        'Archived': True,
        'Count': 123,
        'DetectorId': 'string',
        'EventFirstSeen': 'string',
        'EventLastSeen': 'string',
        'ResourceRole': 'string',
        'ServiceName': 'string',
        'UserFeedback': 'string',
        'AdditionalInfo': {
            'Value': 'string',
            'Type': 'string'
        },
        'FeatureName': 'string',
        'EbsVolumeScanDetails': {
            'ScanId': 'string',
            'ScanStartedAt': datetime.datetime(2015, 1, 1),
            'ScanCompletedAt': datetime.datetime(2015, 1, 1),
            'TriggerFindingId': 'string',
            'Sources': [
                'string',
            ],
            'ScanDetections': {
                'ScannedItemCount': {
                    'TotalGb': 123,
                    'Files': 123,
                    'Volumes': 123
                },
                'ThreatsDetectedItemCount': {
                    'Files': 123
                },
                'HighestSeverityThreatDetails': {
                    'Severity': 'string',
                    'ThreatName': 'string',
                    'Count': 123
                },
                'ThreatDetectedByName': {
                    'ItemCount': 123,
                    'UniqueThreatNameCount': 123,
                    'Shortened': True,
                    'ThreatNames': [
                        {
                            'Name': 'string',
                            'Severity': 'string',
                            'ItemCount': 123,
                            'FilePaths': [
                                {
                                    'FilePath': 'string',
                                    'VolumeArn': 'string',
                                    'Hash': 'string',
                                    'FileName': 'string'
                                },
                            ]
                        },
                    ]
                }
            }
        }
    },
    'Severity': 123.0,
    'Title': 'string',
    'Type': 'string',
    'UpdatedAt': 'string'
}

MOST_GENERAL_FINDING_STR = {
    'AccountId': 'string',
    'Arn': 'string',
    'Confidence': 123.0,
    'CreatedAt': 'string',
    'Description': 'string',
    'Id': 'string',
    'Partition': 'string',
    'Region': 'string',
    'Resource': {
        'AccessKeyDetails': {
            'AccessKeyId': 'string',
            'PrincipalId': 'string',
            'UserName': 'string',
            'UserType': 'string'
        },
        'S3BucketDetails': [
            {
                'Arn': 'string',
                'Name': 'string',
                'Type': 'string',
                'CreatedAt': '2015-01-01T00:00:00.000000',
                'Owner': {
                    'Id': 'string'
                },
                'Tags': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    },
                ],
                'DefaultServerSideEncryption': {
                    'EncryptionType': 'string',
                    'KmsMasterKeyArn': 'string'
                },
                'PublicAccess': {
                    'PermissionConfiguration': {
                        'BucketLevelPermissions': {
                            'AccessControlList': {
                                'AllowsPublicReadAccess': True,
                                'AllowsPublicWriteAccess': True
                            },
                            'BucketPolicy': {
                                'AllowsPublicReadAccess': True,
                                'AllowsPublicWriteAccess': True
                            },
                            'BlockPublicAccess': {
                                'IgnorePublicAcls': True,
                                'RestrictPublicBuckets': True,
                                'BlockPublicAcls': True,
                                'BlockPublicPolicy': True
                            }
                        },
                        'AccountLevelPermissions': {
                            'BlockPublicAccess': {
                                'IgnorePublicAcls': True,
                                'RestrictPublicBuckets': True,
                                'BlockPublicAcls': True,
                                'BlockPublicPolicy': True
                            }
                        }
                    },
                    'EffectivePermission': 'string'
                }
            },
        ],
        'InstanceDetails': {
            'AvailabilityZone': 'string',
            'IamInstanceProfile': {
                'Arn': 'string',
                'Id': 'string'
            },
            'ImageDescription': 'string',
            'ImageId': 'string',
            'InstanceId': 'string',
            'InstanceState': 'string',
            'InstanceType': 'string',
            'OutpostArn': 'string',
            'LaunchTime': 'string',
            'NetworkInterfaces': [
                {
                    'Ipv6Addresses': [
                        'string',
                    ],
                    'NetworkInterfaceId': 'string',
                    'PrivateDnsName': 'string',
                    'PrivateIpAddress': 'string',
                    'PrivateIpAddresses': [
                        {
                            'PrivateDnsName': 'string',
                            'PrivateIpAddress': 'string'
                        },
                    ],
                    'PublicDnsName': 'string',
                    'PublicIp': 'string',
                    'SecurityGroups': [
                        {
                            'GroupId': 'string',
                            'GroupName': 'string'
                        },
                    ],
                    'SubnetId': 'string',
                    'VpcId': 'string'
                },
            ],
            'Platform': 'string',
            'ProductCodes': [
                {
                    'Code': 'string',
                    'ProductType': 'string'
                },
            ],
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ]
        },
        'EksClusterDetails': {
            'Name': 'string',
            'Arn': 'string',
            'VpcId': 'string',
            'Status': 'string',
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ],
            'CreatedAt': '2015-01-01T00:00:00.000000'
        },
        'KubernetesDetails': {
            'KubernetesUserDetails': {
                'Username': 'string',
                'Uid': 'string',
                'Groups': [
                    'string',
                ]
            },
            'KubernetesWorkloadDetails': {
                'Name': 'string',
                'Type': 'string',
                'Uid': 'string',
                'Namespace': 'string',
                'HostNetwork': True,
                'Containers': [
                    {
                        'ContainerRuntime': 'string',
                        'Id': 'string',
                        'Name': 'string',
                        'Image': 'string',
                        'ImagePrefix': 'string',
                        'VolumeMounts': [
                            {
                                'Name': 'string',
                                'MountPath': 'string'
                            },
                        ],
                        'SecurityContext': {
                            'Privileged': True
                        }
                    },
                ],
                'Volumes': [
                    {
                        'Name': 'string',
                        'HostPath': {
                            'Path': 'string'
                        }
                    },
                ]
            }
        },
        'ResourceType': 'string',
        'EbsVolumeDetails': {
            'ScannedVolumeDetails': [
                {
                    'VolumeArn': 'string',
                    'VolumeType': 'string',
                    'DeviceName': 'string',
                    'VolumeSizeInGB': 123,
                    'EncryptionType': 'string',
                    'SnapshotArn': 'string',
                    'KmsKeyArn': 'string'
                },
            ],
            'SkippedVolumeDetails': [
                {
                    'VolumeArn': 'string',
                    'VolumeType': 'string',
                    'DeviceName': 'string',
                    'VolumeSizeInGB': 123,
                    'EncryptionType': 'string',
                    'SnapshotArn': 'string',
                    'KmsKeyArn': 'string'
                },
            ]
        },
        'EcsClusterDetails': {
            'Name': 'string',
            'Arn': 'string',
            'Status': 'string',
            'ActiveServicesCount': 123,
            'RegisteredContainerInstancesCount': 123,
            'RunningTasksCount': 123,
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ],
            'TaskDetails': {
                'Arn': 'string',
                'DefinitionArn': 'string',
                'Version': 'string',
                'TaskCreatedAt': '2015-01-01T00:00:00.000000',
                'StartedAt': '2015-01-01T00:00:00.000000',
                'StartedBy': 'string',
                'Tags': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    },
                ],
                'Volumes': [
                    {
                        'Name': 'string',
                        'HostPath': {
                            'Path': 'string'
                        }
                    },
                ],
                'Containers': [
                    {
                        'ContainerRuntime': 'string',
                        'Id': 'string',
                        'Name': 'string',
                        'Image': 'string',
                        'ImagePrefix': 'string',
                        'VolumeMounts': [
                            {
                                'Name': 'string',
                                'MountPath': 'string'
                            },
                        ],
                        'SecurityContext': {
                            'Privileged': True
                        }
                    },
                ],
                'Group': 'string'
            }
        },
        'ContainerDetails': {
            'ContainerRuntime': 'string',
            'Id': 'string',
            'Name': 'string',
            'Image': 'string',
            'ImagePrefix': 'string',
            'VolumeMounts': [
                {
                    'Name': 'string',
                    'MountPath': 'string'
                },
            ],
            'SecurityContext': {
                'Privileged': True
            }
        }
    },
    'SchemaVersion': 'string',
    'Service': {
        'Action': {
            'ActionType': 'string',
            'AwsApiCallAction': {
                'Api': 'string',
                'CallerType': 'string',
                'DomainDetails': {
                    'Domain': 'string'
                },
                'ErrorCode': 'string',
                'UserAgent': 'string',
                'RemoteIpDetails': {
                    'City': {
                        'CityName': 'string'
                    },
                    'Country': {
                        'CountryCode': 'string',
                        'CountryName': 'string'
                    },
                    'GeoLocation': {
                        'Lat': 123.0,
                        'Lon': 123.0
                    },
                    'IpAddressV4': 'string',
                    'Organization': {
                        'Asn': 'string',
                        'AsnOrg': 'string',
                        'Isp': 'string',
                        'Org': 'string'
                    }
                },
                'ServiceName': 'string',
                'RemoteAccountDetails': {
                    'AccountId': 'string',
                    'Affiliated': True
                },
                'AffectedResources': {
                    'string': 'string'
                }
            },
            'DnsRequestAction': {
                'Domain': 'string',
                'Protocol': 'string',
                'Blocked': True
            },
            'NetworkConnectionAction': {
                'Blocked': True,
                'ConnectionDirection': 'string',
                'LocalPortDetails': {
                    'Port': 123,
                    'PortName': 'string'
                },
                'Protocol': 'string',
                'LocalIpDetails': {
                    'IpAddressV4': 'string'
                },
                'RemoteIpDetails': {
                    'City': {
                        'CityName': 'string'
                    },
                    'Country': {
                        'CountryCode': 'string',
                        'CountryName': 'string'
                    },
                    'GeoLocation': {
                        'Lat': 123.0,
                        'Lon': 123.0
                    },
                    'IpAddressV4': 'string',
                    'Organization': {
                        'Asn': 'string',
                        'AsnOrg': 'string',
                        'Isp': 'string',
                        'Org': 'string'
                    }
                },
                'RemotePortDetails': {
                    'Port': 123,
                    'PortName': 'string'
                }
            },
            'PortProbeAction': {
                'Blocked': True,
                'PortProbeDetails': [
                    {
                        'LocalPortDetails': {
                            'Port': 123,
                            'PortName': 'string'
                        },
                        'LocalIpDetails': {
                            'IpAddressV4': 'string'
                        },
                        'RemoteIpDetails': {
                            'City': {
                                'CityName': 'string'
                            },
                            'Country': {
                                'CountryCode': 'string',
                                'CountryName': 'string'
                            },
                            'GeoLocation': {
                                'Lat': 123.0,
                                'Lon': 123.0
                            },
                            'IpAddressV4': 'string',
                            'Organization': {
                                'Asn': 'string',
                                'AsnOrg': 'string',
                                'Isp': 'string',
                                'Org': 'string'
                            }
                        }
                    },
                ]
            },
            'KubernetesApiCallAction': {
                'RequestUri': 'string',
                'Verb': 'string',
                'SourceIps': [
                    'string',
                ],
                'UserAgent': 'string',
                'RemoteIpDetails': {
                    'City': {
                        'CityName': 'string'
                    },
                    'Country': {
                        'CountryCode': 'string',
                        'CountryName': 'string'
                    },
                    'GeoLocation': {
                        'Lat': 123.0,
                        'Lon': 123.0
                    },
                    'IpAddressV4': 'string',
                    'Organization': {
                        'Asn': 'string',
                        'AsnOrg': 'string',
                        'Isp': 'string',
                        'Org': 'string'
                    }
                },
                'StatusCode': 123,
                'Parameters': 'string'
            }
        },
        'Evidence': {
            'ThreatIntelligenceDetails': [
                {
                    'ThreatListName': 'string',
                    'ThreatNames': [
                        'string',
                    ]
                },
            ]
        },
        'Archived': True,
        'Count': 123,
        'DetectorId': 'string',
        'EventFirstSeen': 'string',
        'EventLastSeen': 'string',
        'ResourceRole': 'string',
        'ServiceName': 'string',
        'UserFeedback': 'string',
        'AdditionalInfo': {
            'Value': 'string',
            'Type': 'string'
        },
        'FeatureName': 'string',
        'EbsVolumeScanDetails': {
            'ScanId': 'string',
            'ScanStartedAt': '2015-01-01T00:00:00.000000',
            'ScanCompletedAt': '2015-01-01T00:00:00.000000',
            'TriggerFindingId': 'string',
            'Sources': [
                'string',
            ],
            'ScanDetections': {
                'ScannedItemCount': {
                    'TotalGb': 123,
                    'Files': 123,
                    'Volumes': 123
                },
                'ThreatsDetectedItemCount': {
                    'Files': 123
                },
                'HighestSeverityThreatDetails': {
                    'Severity': 'string',
                    'ThreatName': 'string',
                    'Count': 123
                },
                'ThreatDetectedByName': {
                    'ItemCount': 123,
                    'UniqueThreatNameCount': 123,
                    'Shortened': True,
                    'ThreatNames': [
                        {
                            'Name': 'string',
                            'Severity': 'string',
                            'ItemCount': 123,
                            'FilePaths': [
                                {
                                    'FilePath': 'string',
                                    'VolumeArn': 'string',
                                    'Hash': 'string',
                                    'FileName': 'string'
                                },
                            ]
                        },
                    ]
                }
            }
        }
    },
    'Severity': 123.0,
    'Title': 'string',
    'Type': 'string',
    'UpdatedAt': 'string'
}
