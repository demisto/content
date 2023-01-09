from datetime import datetime

FINDING = {
            'AccountId': 'string',
            'Arn': 'string',
            'Confidence': 123.0,
            'CreatedAt': '2022-11-08T14:24:52.908Z',
            'Description': 'desc',
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
                        'CreatedAt': datetime(2015, 1, 1),
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
                    'CreatedAt': datetime(2015, 1, 1)
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
                        'TaskCreatedAt': datetime(2015, 1, 1),
                        'StartedAt': datetime(2015, 1, 1),
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
                    'ScanStartedAt': datetime(2015, 1, 1),
                    'ScanCompletedAt': datetime(2015, 1, 1),
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
            'Title': 'title',
            'Type': 'string',
            'UpdatedAt': '2022-11-08T14:24:52.908Z'
        }

GET_MEMBERS_RESPONSE = {
    'Members': [
        {},
        {
            'AccountId': 1,
            'DetectorId': 1,
            'MasterId': 1,
        }
    ]
}

LIST_MEMBERS_RESPONSE = {
    'Members': [
        {
            'AccountId': 'string',
            'DetectorId': 'string',
            'MasterId': 'string',
            'Email': 'string',
            'RelationshipStatus': 'string',
            'InvitedAt': 'string',
            'UpdatedAt': 'string',
            'AdministratorId': 'string'
        },
    ],
    'NextToken': 'string'
}


THREAT_INTEL_SET_RESPONSE = {
    'Name': 'string',
    'Format': 'TXT',
    'Location': 'string',
    'Status': 'INACTIVE',
    'Tags': {
        'string': 'string'
    }
}

IP_SET_RESPONSE = {
    'Name': 'string',
    'Format': 'TXT',
    'Location': 'string',
    'Status': 'INACTIVE',
    'Tags': {
        'string': 'string'
    }
}

DETECTOR_RESPONSE = {
    'CreatedAt': 'string',
    'FindingPublishingFrequency': 'FIFTEEN_MINUTES',
    'ServiceRole': 'string',
    'Status': 'ENABLED',
    'UpdatedAt': 'string',
    'DataSources': {
        'CloudTrail': {
            'Status': 'ENABLED'
        },
        'DNSLogs': {
            'Status': 'ENABLED'
        },
        'FlowLogs': {
            'Status': 'ENABLED'
        },
        'S3Logs': {
            'Status': 'ENABLED'
        },
        'Kubernetes': {
            'AuditLogs': {
                'Status': 'ENABLED'
            }
        },
        'MalwareProtection': {
            'ScanEc2InstanceWithFindings': {
                'EbsVolumes': {
                    'Status': 'ENABLED'
                }
            },
            'ServiceRole': 'string'
        }
    },
    'Tags': {
        'string': 'string'
    }
}


RESPONSE_METADATA = {
    'ResponseMetadata': {'RequestId': 'string',
                         'HTTPStatusCode': 200,
                         'HTTPHeaders':
                             {'date': 'Wed, 07 Sep 2022 13:08:42 GMT',
                              'content-type': 'application/json',
                              'content-length': '0',
                              'connection': 'keep-alive',
                              'x-amzn-requestid': 'string',
                              'access-control-allow-origin': '*',
                              'access-control-allow-headers': 'string',
                              'x-amz-apigw-id': 'string',
                              'access-control-expose-headers': 'string',
                              'x-amzn-trace-id': 'string',
                              'access-control-max-age': 'string'},
                         'RetryAttempts': 0}
}