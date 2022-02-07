import os
import re

import requests
from gitlab_slack_notifier import get_artifact_data


def create_pr_comment():
    comment = ''
    comment += get_failing_ut()
    comment += get_failing_validations()
    comment += get_failing_tests()
    comment += f"here is a link to the full report: "
    return comment


FAILED_UT_COMMENT = 'This is the link to the failed unit tests'
JID = os.environ.get("CI_JOB_ID")
FAILED_UT_LINK = f'https://xsoar.docs.pan.run/-/content/-/jobs/{JID}/artifacts/failed_unit_tests.txt'
example_run_tests_file = "Users/yucohen/Downloads/Run_Tests (1).log"
ARTIFACTS_FOLDER = ''


def get_failing_ut():
    failed_ut = get_artifact_data(ARTIFACTS_FOLDER, "failed_unit_tests.txt")
    if failed_ut:
        failed_ut_list = failed_ut.split('\n')
        write_data_to_summary_file()
        return f'you have {len(failed_ut_list)} failed unit test on this push.\n'
    return 'no failing unit tests on this one. nice job!\n'


def get_failing_validations():
    # TODO check the file name
    failed_validations = get_artifact_data(ARTIFACTS_FOLDER, "failed_validations.txt")
    if failed_validations:
        failed_validations_list = failed_validations.split('\n')
        write_data_to_summary_file()
        return f'you have {len(failed_validations_list)} failed validations on this push.\n'
    return 'no failing validations on this one. nice job!\n'


def get_failing_tests():
    # TODO check the file name
    failed_tests = get_artifact_data(ARTIFACTS_FOLDER, "failed_tests.txt")
    if failed_tests:
        failed_tests_list = failed_tests.split('\n')
        for failed_test in failed_tests_list:
            test_data = get_test_data(failed_test)
        write_data_to_summary_file()
        return f'you have {len(failed_tests_list)} failed tests on this push.\n'
    return 'no failing tests on this one. nice job!\n'


def write_data_to_summary_file():
    pass


def get_test_data(failed_test_name: str) -> str:
    # TODO check the file name
    log_data = get_artifact_data(ARTIFACTS_FOLDER, "xsoar/logs/Run_Tests.log")
    index_to_trim = failed_test_name.find("(Mock Disabled)")
    if index_to_trim > -1:
        failed_test_name = failed_test_name[:index_to_trim - 1]
    test_log_pattern = f"------ Test playbook: {failed_test_name}.*start ------"
    re.search(test_log_pattern, log_data)

    '''
    [2022-02-06 12:46:05] - [Thread-1] - [INFO] - ------ Test playbook: "ConvertFile-Test" with no integrations start ------ (Mock: Disabled)
INFO:demisto-sdk:External Playbook Configuration not provided, skipping re-configuration.
[2022-02-06 12:46:05] - [Thread-1] - [INFO] - ssh tunnel command:
ssh -i ~/.ssh/oregon-ci.pem -4 -o StrictHostKeyChecking=no -f -N "content-build@content-build-lb.demisto.works" -L "4447:10.0.24.230:443"
[2022-02-06 12:46:25] - [Thread-1] - [INFO] - Investigation URL: https://localhost:4447/#/WorkPlan/7
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] - "ConvertFile-Test" failed with error/s
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] - Playbook "ConvertFile-Test" has failed:
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] - - Task ID: 8
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] -   Command: !ReadPDFFileV2 entryID="10@7" maxImages="0"
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] -   Body:
Could not load pdf file in EntryID 10@7
Error: 'http://www.w3.org/1999/xhtml'
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] - - Task ID: 8
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] -   Command: !ReadPDFFileV2 entryID="10@7" maxImages="0"
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] -   Body:
The script failed read PDF file due to an error: 'http://www.w3.org/1999/xhtml'
[2022-02-06 12:46:46] - [Thread-1] - [ERROR] - Test failed: playbook: "ConvertFile-Test" with no integrations
[2022-02-06 12:46:47] - [Thread-1] - [INFO] - ------ Test playbook: "ConvertFile-Test" with no integrations end ------'''
















def add_pr_comment():
    token = os.environ['CONTENT_GITHUB_TOKEN']
    branch_name = os.environ['CI_COMMIT_BRANCH']
    sha1 = os.environ['CI_COMMIT_SHA']

    query = '?q={}+repo:demisto/content+org:demisto+is:pr+is:open+head:{}+is:open'.format(sha1, branch_name)
    url = 'https://api.github.com/search/issues'
    headers = {'Authorization': 'Bearer ' + token}
    try:
        response = requests.get(url + query, headers=headers)
        res_dict = response.json()

        if res_dict and res_dict.get('total_count', 0) == 1:
            issue_url = res_dict['items'][0].get('comments_url') if res_dict.get('items', []) else None
            if issue_url:
                response = requests.get(issue_url, headers=headers)
                issue_comments = response.json()
                for existing_comment in issue_comments:
                    # Check if a comment about report coverage already exists. If there is delete it first and then post
                    # a new comment:
                    if FAILED_UT_COMMENT in existing_comment.get('body'):
                        comment_url = existing_comment.get('url')
                        requests.delete(comment_url, headers=headers)
                requests.post(issue_url, json={'body': f'{FAILED_UT_COMMENT}:\n {FAILED_UT_LINK}'},
                              headers=headers)
        else:
            print(f'Add pull request comment failed: There is more then one open pull request for branch {branch_name}.')
    except Exception as e:
        print(f'Add pull request comment failed with error {e}')


if __name__ == "__main__":
    add_pr_comment()
