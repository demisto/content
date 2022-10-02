from datetime import datetime

FINDING = {
        'AccountId': 'string',
        'Arn': 'string',
        'Confidence': 123.0,
        'CreatedAt': 'string',
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
            'ResourceType': 'string'
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
                    'ServiceName': 'string'
                },
                'DnsRequestAction': {
                    'Domain': 'string'
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
            'UserFeedback': 'string'
        },
        'Severity': 123.0,
        'Title': 'title',
        'Type': 'string',
        'UpdatedAt': 'string'
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