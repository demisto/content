from AwsEC2GetPublicSGRules import get_ec2_sg_public_rules

IPPERM = [{"IpProtocol": "-1", "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "PrefixListIds": [],
           "UserIdGroupPairs": []}, {"FromPort": 10, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                     "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "PrefixListIds": [], "ToPort": 22,
                                     "UserIdGroupPairs": []},
          {"FromPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
           "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "PrefixListIds": [], "ToPort": 23, "UserIdGroupPairs": []},
          {"FromPort": 55, "IpProtocol": "tcp", "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
           "PrefixListIds": [], "ToPort": 55, "UserIdGroupPairs": []}]

IPPERM2 = {"FromPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
           "PrefixListIds": [], "ToPort": 22, "UserIdGroupPairs": []}


def test_get_ec2_sg_public_rules():
    expected1 = [{"groupId": "sg-12345", "ipProtocol": "tcp", "region": "us-east-1", "fromPort": 10, "toPort": 22,
                  "cidrIp": "0.0.0.0/0"},
                 {"groupId": "sg-12345", "ipProtocol": "tcp", "region": "us-east-1", "fromPort": 22, "toPort": 23,
                  "cidrIp": "0.0.0.0/0"}]

    expected2 = [{"cidrIp": "::/0", "groupId": "sg-12345", "ipProtocol": "-1", "region": "us-east-1"},
                 {"cidrIp": "0.0.0.0/0", "fromPort": 10, "groupId": "sg-12345", "ipProtocol": "tcp",
                  "region": "us-east-1", "toPort": 22},
                 {"cidrIp": "::/0", "fromPort": 10, "groupId": "sg-12345", "ipProtocol": "tcp", "region": "us-east-1",
                  "toPort": 22}, {"cidrIp": "0.0.0.0/0", "fromPort": 22, "groupId": "sg-12345", "ipProtocol": "tcp",
                                  "region": "us-east-1", "toPort": 23},
                 {"cidrIp": "::/0", "fromPort": 22, "groupId": "sg-12345", "ipProtocol": "tcp", "region": "us-east-1",
                  "toPort": 23}]

    expected3 = []

    expected4 = [{"cidrIp": "::/0", "groupId": "sg-12345", "ipProtocol": "-1", "region": "us-east-1"}]

    expected5 = [{"groupId": "sg-12345", "ipProtocol": "tcp", "region": "us-east-1", "fromPort": 22, "toPort": 22,
                 "cidrIp": "0.0.0.0/0"}]

    result1 = get_ec2_sg_public_rules(group_id='sg-12345', ip_permissions=IPPERM, checked_protocol='tcp',
                                      checked_from_port=22, checked_to_port=22, region='us-east-1', include_ipv6='no'
                                      )

    result2 = get_ec2_sg_public_rules(group_id='sg-12345', ip_permissions=IPPERM, checked_protocol='tcp',
                                      checked_from_port=22, checked_to_port=22, region='us-east-1', include_ipv6='yes'
                                      )

    result3 = get_ec2_sg_public_rules(group_id='sg-12345', ip_permissions=IPPERM, checked_protocol='udp',
                                      checked_from_port=55, checked_to_port=60, region='us-east-1', include_ipv6='no'
                                      )

    result4 = get_ec2_sg_public_rules(group_id='sg-12345', ip_permissions=IPPERM, checked_protocol='udp',
                                      checked_from_port=55, checked_to_port=60, region='us-east-1', include_ipv6='yes'
                                      )

    result5 = get_ec2_sg_public_rules(group_id='sg-12345', ip_permissions=IPPERM2, checked_protocol='tcp',
                                      checked_from_port=22, checked_to_port=22, region='us-east-1', include_ipv6='yes'
                                      )

    assert expected1 == result1
    assert expected2 == result2
    assert expected3 == result3
    assert expected4 == result4
    assert expected5 == result5
