"""
Tests module for Xpanse Feed integration.
"""


def test_map_indicator_type():
    """Tests map_indicator_type helper function.

        Given:
            - Indicator type input
        When:
            - Getting output from map_indicator_type helper function
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from FeedXpanse import map_indicator_type
    # Test know types
    assert map_indicator_type('UNASSOCIATED_RESPONSIVE_IP') == 'IP'
    assert map_indicator_type('DOMAIN') == 'Domain'
    assert map_indicator_type('CERTIFICATE') == 'X509 Certificate'
    assert map_indicator_type('CIDR') == 'CIDR'
    # test_map_unknown_type
    assert map_indicator_type('UNKNOWN_TYPE') == 'None'
    # test_map_empty_string
    assert map_indicator_type('') == 'None'
    # test_map_none_input
    assert map_indicator_type('domain') == 'None'