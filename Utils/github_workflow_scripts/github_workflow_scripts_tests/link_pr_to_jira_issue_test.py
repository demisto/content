import pytest
import requests

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
relates: https://jira-hq.paloaltonetworks.local/browse/CIAC-3472"""

PR_WITH_BOTH_BY_NEWLINE = """This pr is dummy
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3473
relates: https://jira-hq.paloaltonetworks.local/browse/CIAC-3475

something else to say"""
PR_WITH_MULTIPLE_FIXES_BY_NEWLINE = """This pr is dummy
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3473
fixes: https://jira-hq.paloaltonetworks.local/browse/CIAC-3475

something else to say"""

PR_TEST_CASE=[
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

    # PR is merged, related issues should not be detected.
    (PR_WITH_ONLY_RELATES_WITH_SPACE, True, []),
    (PR_WITH_ONLY_RELATES_WITH_NEWLINE, True, []),
    (PR_WITH_ONLY_RELATES_WITHOUT_END_OF_STR, True, []),
    (PR_WITH_BOTH_BY_NEWLINE, True,  ['CIAC-3473'])
]


@pytest.mark.parametrize('pr_body, is_merged, expected', PR_TEST_CASE)
def test_find_fixed_issue_in_body(pr_body, is_merged, expected):
    res = link_pr_to_jira_issue.find_fixed_issue_in_body(pr_body, is_merged)
    res_ids = [x.get('id') for x  in res]
    assert res_ids == expected


TRIGGER_TEST_CASE = [
    (True, [{'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3473', 'id': 'CIAC-3473'}]),
    (False, [{'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3473', 'id': 'CIAC-3473'},
             {'link': 'https://jira-hq.paloaltonetworks.local/browse/CIAC-3475', 'id': 'CIAC-3475'}])
]

@pytest.mark.parametrize('is_merged, expected', TRIGGER_TEST_CASE)
def test_trigger_generic_webhook(mocker, requests_mock, is_merged, expected):
    class OptionMock:
        def __init__(self, link, num, title, body, merged):
            self.pr_link = link
            self.pr_title = title
            self.pr_body = body
            self.is_merged = merged
            self.pr_num = num
            self.username = 'test_user'
            self.password = 'test_password'

    # post_mock = mocker.patch.object(requests, 'post', return_value=requests_mock )
    post_mock = requests_mock.post(link_pr_to_jira_issue.JIRA_GITHUB_INTEGRATION_INSTANCE_URL, status_code=200)
    option_mock = OptionMock('pr_link_example','1', 'dummy pr', PR_WITH_BOTH_BY_NEWLINE, is_merged)
    link_pr_to_jira_issue.trigger_generic_webhook(option_mock)
    res = post_mock.last_request.json()
    assert res.get('name') == link_pr_to_jira_issue.GENERIC_WEBHOOK_NAME
    assert 'raw_json' in res
    assert 'closeIssue' in res.get('raw_json')
    assert res.get('raw_json').get('JiraIssues') == expected
    assert res.get('raw_json').get('closeIssue') == is_merged
