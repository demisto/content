import pytest

from Utils.github_workflow_scripts.jira_integration_scripts import link_pr_to_jira_issue

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
relates: https://jira-hq.paloaltonetworks.local/browse/CIAC-3475

something else to say"""
PR_WITH_MULTIPLE_FIXES_BY_NEWLINE = """This pr is dummy
fixes:https://jira-hq.paloaltonetworks.local/browse/CIAC-3473
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3475

something else to say"""

PR_TEST_CASE = [
    # Pr is not merged, so just need to detect all the issues.
    (PR_WITH_ONLY_FIXES_WITH_SPACE, False, ['CIAC-3473']),
    (PR_WITH_ONLY_FIXES_WITH_NEWLINE, False, ['CIAC-3473']),
    (PR_WITH_ONLY_FIXES_WITHOUT_END_OF_STR, False, ['CIAC-3473']),
    (PR_WITH_MULTIPLE_FIXES_BY_NEWLINE, False, ['CIAC-3473', 'CIAC-3475']),

    # Pr is merged, so need to detect the issues fixed by it.
    (PR_WITH_ONLY_FIXES_WITH_SPACE, True, ['CIAC-3473']),
    (PR_WITH_ONLY_FIXES_WITH_NEWLINE, True, ['CIAC-3473']),
    (PR_WITH_ONLY_FIXES_WITHOUT_END_OF_STR, True, ['CIAC-3473']),
    (PR_WITH_MULTIPLE_FIXES_BY_NEWLINE, True, ['CIAC-3473', 'CIAC-3475']),

    # PR is not merge, so just need to detect all the issues.
    (PR_WITH_ONLY_RELATES_WITH_SPACE, False, ['CIAC-3472']),
    (PR_WITH_ONLY_RELATES_WITH_NEWLINE, False, ['CIAC-3472']),
    (PR_WITH_ONLY_RELATES_WITHOUT_END_OF_STR, False, ['CIAC-3472']),
    (PR_WITH_BOTH_BY_NEWLINE, False, ['CIAC-3473', 'CIAC-3475']),
]


@pytest.mark.parametrize('pr_body, is_merged, expected', PR_TEST_CASE)
def test_find_fixed_issue_in_body(pr_body, is_merged, expected):
    """
    Given: A PR representing text containing a few links.
    When: Searching all relevant links for closing/ for connecting
    Then: Validates relevant links were fetched for closing, and relevant links were fetched when only connected.
    """
    res = link_pr_to_jira_issue.find_fixed_issue_in_body(pr_body)
    res_keys = [x.get('key') for x in res]
    assert res_keys == expected


TRIGGER_TEST_CASE = [
    (
        PR_WITH_BOTH_BY_NEWLINE,
        [
            {
                'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3473',
                'key': 'CIAC-3473',
                'should_close': True,
            },
            {
                'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3475',
                'key': 'CIAC-3475',
                'should_close': False,
            }
        ]
    ),
]


@pytest.mark.parametrize('pr_body, expected', TRIGGER_TEST_CASE)
def test_trigger_generic_webhook(requests_mock, pr_body, expected):
    """
    Given: The links in a PR
    When: Running GitHub action on PR
    Then: Make sure the request to server is created correctly.
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

    post_mock = requests_mock.post('http://test.com', status_code=200, json=[{"id": "1"}])
    option_mock = OptionMock('pr_link_example', '1', 'dummy pr', pr_body, True)
    link_pr_to_jira_issue.trigger_generic_webhook(option_mock)
    res = post_mock.last_request.json()
    assert res.get('name') == link_pr_to_jira_issue.GENERIC_WEBHOOK_NAME
    assert 'raw_json' in res
    assert 'closeIssue' in res.get('raw_json')
    assert res.get('raw_json').get('JiraIssues') == expected
