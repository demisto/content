import demistomock as demisto  # noqa: F401


def test_test_range_func(mocker):
    """Tests test_range helper function.

        Given:
            - Mocked arguments
        When:
            - Sending args to lookup helper function.
        Then:
            - Checks the output of the helpedfunction with the expected output.
    """
    from GCPOffendingFirewallRule import test_range

    assert test_range('20-25', '22')
    assert not test_range('20-21', '22')


# def test_test_match_func(mocker):
#     """Tests test_match helper function.

#         Given:
#             - Mocked arguments
#         When:
#             - Sending args to lookup helper function.
#         Then:
#             - Checks the output of the helpedfunction with the expected output.
#     """
#     from GCPOffendingFirewallRule import test_match

#     assert test_match('20-25', '22')
#     assert not test_match('20-21', '22')
