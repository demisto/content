import pytest

from github_workflow_scripts.jira_integration_scripts import link_pr_to_jira_issue

PR_WITH_ONLY_FIXES_WITH_SPACE = """This pr is dummy
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3473 somthing
something else to say"""
PR_WITH_ONLY_FIXES_WITH_NEWLINE = """This pr is dummy
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3473
something else to say"""
PR_WITH_ONLY_FIXES_WITHOUT_END_OF_STR = """This pr is dummy
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3473"""

PR_WITH_ONLY_RELATES_WITH_SPACE = """This pr is dummy
relates: https://jira-hq.paloaltonetworks.local/browse/CIAC-3472 somthing
something else to say"""
PR_WITH_ONLY_RELATES_WITH_NEWLINE = """This pr is dummy
relates: https://jira-hq.paloaltonetworks.local/browse/CIAC-3472
something else to say"""
PR_WITH_ONLY_RELATES_WITHOUT_END_OF_STR = """This pr is dummy
relates:https://jira-hq.paloaltonetworks.local/browse/CIAC-3472"""

PR_WITH_BOTH_BY_NEWLINE = """This pr is dummy
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3473
relates: https://jira-dc.paloaltonetworks.com/browse/CIAC-3475

something else to say"""
PR_WITH_MULTIPLE_FIXES_BY_NEWLINE = """This pr is dummy
fixes:https://jira-hq.paloaltonetworks.local/browse/CIAC-3473
fixes: https://jira-dc.paloaltonetworks.com/browse/CIAC-3475

something else to say"""

PR_TEST_CASE = [
    # Pr is not merged, so just need to detect all the issues.
    (PR_WITH_ONLY_FIXES_WITH_SPACE, False, ['CIAC-3473'], ['fixes']),
    (PR_WITH_ONLY_FIXES_WITH_NEWLINE, False, ['CIAC-3473'], ['fixes']),
    (PR_WITH_ONLY_FIXES_WITHOUT_END_OF_STR, False, ['CIAC-3473'], ['fixes']),
    (PR_WITH_MULTIPLE_FIXES_BY_NEWLINE, False, ['CIAC-3473', 'CIAC-3475'], ['fixes', 'fixes']),

    # Pr is merged, so need to detect the issues fixed by it.
    (PR_WITH_ONLY_FIXES_WITH_SPACE, True, ['CIAC-3473'], ['fixes']),
    (PR_WITH_ONLY_FIXES_WITH_NEWLINE, True, ['CIAC-3473'], ['fixes']),
    (PR_WITH_ONLY_FIXES_WITHOUT_END_OF_STR, True, ['CIAC-3473'], ['fixes']),
    (PR_WITH_MULTIPLE_FIXES_BY_NEWLINE, True, ['CIAC-3473', 'CIAC-3475'], ['fixes', 'fixes']),

    # PR is not merge, so just need to detect all the issues.
    (PR_WITH_ONLY_RELATES_WITH_SPACE, False, ['CIAC-3472'], ['relates']),
    (PR_WITH_ONLY_RELATES_WITH_NEWLINE, False, ['CIAC-3472'], ['relates']),
    (PR_WITH_ONLY_RELATES_WITHOUT_END_OF_STR, False, ['CIAC-3472'], ['relates']),
    (PR_WITH_BOTH_BY_NEWLINE, False, ['CIAC-3473', 'CIAC-3475'], ['fixes', 'relates']),

    # PR is merged, related issues should not be detected.
    (PR_WITH_ONLY_RELATES_WITH_SPACE, True, [], []),
    (PR_WITH_ONLY_RELATES_WITH_NEWLINE, True, [], []),
    (PR_WITH_ONLY_RELATES_WITHOUT_END_OF_STR, True, [], []),
    (PR_WITH_BOTH_BY_NEWLINE, True, ['CIAC-3473'], ['fixes'])
]


@pytest.mark.parametrize('pr_body, is_merged, expected_ids, expected_actions', PR_TEST_CASE)
def test_find_fixed_issue_in_body(pr_body, is_merged, expected_ids, expected_actions):
    """
    Given: A PR representing text containing a few links.
    When: Searching all relevant links for closing/ for connecting
    Then: validates relevant links were fetch for closing, and relevant links were fetch when only connected.
    """
    res = link_pr_to_jira_issue.find_fixed_issue_in_body(pr_body, is_merged)
    res_ids = [x.get('id') for x in res]
    assert res_ids == expected_ids

    res_actions = [x.get('action') for x in res]
    assert res_actions == expected_actions


TRIGGER_TEST_CASE = [
    (
        True,
        [  # case one link with fixes:
            {'action': 'fixes', 'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3473', 'id': 'CIAC-3473'}
        ]
    ),
    (
        False,
        [  # case multiple links only related:
            {'action': 'fixes', 'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3473', 'id': 'CIAC-3473'},
            {'action': 'relates', 'link': 'https://jira-dc.paloaltonetworks.com/browse/CIAC-3475', 'id': 'CIAC-3475'}
        ]
    )
]


@pytest.mark.parametrize('is_merged, expected', TRIGGER_TEST_CASE)
def test_trigger_generic_webhook(requests_mock, is_merged, expected):
    """
    Given: the links in a PR
    When: Running github action on PR
    Then: make sure the request to server is created correctly.
    """
    class OptionMock:
        def __init__(self, link, num, title, body, merged):
            self.pr_link = link
            self.pr_title = title
            self.pr_body = body
            self.is_merged = merged
            self.pr_num = num
            self.username = 'test_user'
            self.password = 'test_password'
            self.url = 'http://test.com'

    post_mock = requests_mock.post(
        f'http://test.com/instance/execute/{link_pr_to_jira_issue.GENERIC_WEBHOOK_NAME}', status_code=200, json=[{"id": "1"}])
    option_mock = OptionMock('pr_link_example', '1', 'dummy pr', PR_WITH_BOTH_BY_NEWLINE, is_merged)
    link_pr_to_jira_issue.trigger_generic_webhook(option_mock)
    res = post_mock.last_request.json()
    assert res.get('name') == f'{link_pr_to_jira_issue.GENERIC_WEBHOOK_NAME} - #1'
    assert 'raw_json' in res
    assert 'closeIssue' in res.get('raw_json')
    assert res.get('raw_json').get('JiraIssues') == expected
    assert res.get('raw_json').get('closeIssue') == str(is_merged).lower()
