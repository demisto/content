DOMAIN_TABLE = [['Client Type', 'Domain(s)'],
                ['domain1', '*.d1.com'],
                ['domain2', '*.d2.com'],
                ['Long message without domain name']]


def test_grab_domains():
    """
    Given:
        - Raw list of tuples that contains domain name and domain url, returned by api call:
        first array is the title, 2 seconds arrays are data, last array is message.
    When:
        - Filtered list contains domain's urls only
    Then:
        - Return domains list without errors
    """
    from CiscoWebExFeed import grab_domains
    expected_result = ['*.d1.com', '*.d2.com']
    assert grab_domains(DOMAIN_TABLE) == expected_result
