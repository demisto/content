from datetime import datetime

from AWSGuardDuty import get_members, parse_incident_from_finding

RESPONSE = {
    'Members': [
        {},
        {
            'AccountId': 1,
            'DetectorId': 1,
            'MasterId': 1,
        }
    ]
}


class Client:
    @staticmethod
    def get_members(DetectorId, AccountIds):
        return RESPONSE


def test_get_members():
    """
    Given
    - get-members command

    When
    - running get-members, that returns empty map

    Then
    - Ensure that empty map is not returned to the context
    """
    client = Client
    members_res = get_members(client, {})
    assert members_res['Contents'] == [{'AccountId': 1, 'DetectorId': 1, 'MasterId': 1}]


def test_parse_incident_from_finding():
    """
    Given:
    - Amazon GuardDuty finding with datetime object nested in it

    When:
    - Parsing finding to incident

    Then:
    - Ensure finding is parsed as expected
    """
    title = 'title'
    desc = 'desc'
    finding = {
        'AccountId': 'string',
        'Arn': 'string',
        'Confidence': 123.0,
        'CreatedAt': 'string',
        'Description': desc,
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
        'Title': title,
        'Type': 'string',
        'UpdatedAt': 'string'
    }
    incident = parse_incident_from_finding(finding)
    assert incident['name'] == title
    assert incident['details'] == desc
    assert incident['severity'] == 0
    assert '2015-01-01' in incident['rawJSON']
