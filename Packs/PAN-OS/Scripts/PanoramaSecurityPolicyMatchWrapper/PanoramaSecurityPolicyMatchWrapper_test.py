

def test_wrapper_command(mocker):

    from PanoramaSecurityPolicyMatchWrapper import wrapper_command

    args = {
        'destinations': '8.8.8.8, 3.3.3.3',
        'sources': '1.1.1.1, 2.2.2.2',
        'protocol': '4'
    }
    mocker.patch('PanoramaSecurityPolicyMatchWrapper.panorama_security_policy_match', return_value='The query did not match a Security policy')
    responses = wrapper_command(args)

    for res in responses:
        assert res == 'The query for source: 1.1.1.1, destination: 8.8.8.8 did not match a Security policy.'
