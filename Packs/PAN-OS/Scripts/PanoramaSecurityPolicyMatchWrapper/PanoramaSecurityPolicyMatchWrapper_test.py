SECURITY_POLICY_MATCH = [
    'The query for source: 2.2.2.2, destination: 8.8.8.8 did not match a Security policy.',
    'The query for source: 3.3.3.3, destination: 8.8.8.8 did not match a Security policy.',
    {
        'Action': 'allow',
        'Category': 'any',
        'Destination': 'any',
        'DeviceSerial': '1234567890',
        'From': 'any',
        'Name': 'block rule',
        'Source': '1.1.1.1',
        'To': 'any'
    }
]
SECURITY_POLICY_MATCH2 = ['The query for source: 1.1.1.1, destination: 8.8.8.8 did not match a Security policy.']


def test_wrapper_command(mocker):
    """
    Given:
        - args for wrapper_command
    When:
        - running PanoramaSecurityPolicyMatchWrapper command
    Then:
        - Validate the output returned as expected
    """
    from PanoramaSecurityPolicyMatchWrapper import wrapper_command

    args = {
        'destination': '8.8.8.8',
        'source': '1.1.1.1, 2.2.2.2, 3.3.3.3',
        'protocol': '4'
    }
    mocker.patch('PanoramaSecurityPolicyMatchWrapper.wrapper_panorama_security_policy_match',
                 return_value=SECURITY_POLICY_MATCH)
    response = wrapper_command(args)

    assert response.outputs == [
        {'Action': 'allow', 'Category': 'any', 'Destination': 'any', 'DeviceSerial': '1234567890', 'From': 'any',
         'Name': 'block rule', 'Source': '1.1.1.1', 'To': 'any'}]


def test_wrapper_panorama_security_policy_match(mocker):
    """
    Given:
        - args for wrapper_panorama_security_policy_match
    When:
        - calling wrapper_panorama_security_policy_match command
    Then:
        - Validate the output returned as expected
    """
    from PanoramaSecurityPolicyMatchWrapper import wrapper_panorama_security_policy_match

    args = {
        'protocol': '4'
    }
    mocker.patch('PanoramaSecurityPolicyMatchWrapper.panorama_security_policy_match',
                 return_value=SECURITY_POLICY_MATCH2)
    response = wrapper_panorama_security_policy_match(['8.8.8.8'], ['1.1.1.1'], ['700'], args)

    assert response == SECURITY_POLICY_MATCH2
