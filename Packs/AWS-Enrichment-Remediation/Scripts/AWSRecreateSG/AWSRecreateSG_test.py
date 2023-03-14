import demistomock as demisto  # noqa: F401


def test_split_rule(mocker):
    """Tests get_asm_args helper function.

        Given:
            - Mocked arguments
        When:
            - Sending args to split_rule helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from AWSRecreateSG import split_rule
    rule = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
            "PrefixListIds": [], "UserIdGroupPairs": []}
    args = {"rule": rule, "port": 22, "protocol": "tcp"}
    result = split_rule(**args)
    assert result[0] == {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': 21}

#TODO
def instance_info(mocker):
    """Tests get_asm_args helper function.
        
        Given:
            - Mocked arguments
        When:
            - Sending args to split_rule helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from AWSRecreateSG import instance_info
    example_output= [{"NetworkInterfaces":[{"Association":{"IpOwnerId":"717007404259","PublicDnsName":"","PublicIp":"52.22.120.51"},"Attachment":{"AttachTime":"2022-08-10T11:59:30","AttachmentId":"eni-attach-0feb71c931c2b2cfc","DeleteOnTermination":true,"DeviceIndex":0,"NetworkCardIndex":0,"Status":"attached"},"Description":"","Groups":[{"GroupId":"sg-0c63e43b0b6a2fd9e","GroupName":"1852-bad"}],"InterfaceType":"interface","Ipv6Addresses":[],"MacAddress":"12:aa:43:f9:e4:55","NetworkInterfaceId":"eni-0db6b9d77a7032858","OwnerId":"717007404259","PrivateIpAddress":"10.0.101.59","PrivateIpAddresses":[{"Association":{"IpOwnerId":"717007404259","PublicDnsName":"","PublicIp":"52.22.120.51"},"Primary":true,"PrivateIpAddress":"10.0.101.59"}]}]}]
    mocker.patch.object(demisto, "executeCommand", return_value=date_result)
    args = {"instance_id": "fake-instance-id", "public_ip": "1.1.1.1"}
    result = instance_info(**args)
    assert result[0] == {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': 21}
