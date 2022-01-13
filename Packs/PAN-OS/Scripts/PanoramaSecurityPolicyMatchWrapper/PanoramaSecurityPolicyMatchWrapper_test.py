

def test_wrapper_command(mocker):

    from PanoramaSecurityPolicyMatchWrapper import wrapper_command

    args = {
        'destination': '8.8.8.8, 3.3.3.3',
        'source': '1.1.1.1, 2.2.2.2',
        'protocol': '4'
    }
    mocker.patch('PanoramaSecurityPolicyMatchWrapper.wrapper_panorama_security_policy_match', return_value='')
    responses = wrapper_command(args)

    for res in responses:
        assert res == 'The query for source: 1.1.1.1, destination: 8.8.8.8 did not match a Security policy.'
