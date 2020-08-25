def test_malware_readable_data():
    """
    Given:
        A dict with only "name" key
    When:
        calling malware_readable_data method on it
    Then:
        Ensure execution does not raise exception on it
    """
    from FireEyeETP import malware_readable_data
    try:
        malware_readable_data({'name': 'some-name'})
    except KeyError:
        assert False, 'malware_readable_data method should not fail on dict with name key only'
