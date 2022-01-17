import json
import os
from queue import Queue
from unittest import mock
import responses


class MockTestResults:
    playbook_skipped_integration = {'demo integration'}
    failed_playbooks = False

    @staticmethod
    def print_test_summary(is_ami, logging_module):
        return

    @staticmethod
    def create_result_files():
        return


class MockBuildContext:
    instances_ips = {}
    unmockable_tests_to_run = Queue()
    mockable_tests_to_run = Queue()
    build_name = 'mock'
    is_nightly = False
    tests_data_keeper = MockTestResults
    isAMI = False


MOCK_ENV_VARIABLES = {
    'CONTENT_GITHUB_TOKEN': '123456',
    'CI_COMMIT_BRANCH': 'mock_branch',
    'CI_COMMIT_SHA': '1234567890abcdef',
    'UT_JOB_ID': '123456'
}


COVERAGE_REPORT_COMMENT = 'Link to the coverage report of the integration:'

# https://github.com/getsentry/responses
@responses.activate
def test_add_pr_comment(mocker):
    expected_results = 'Link to the coverage report of the integration:\n ' \
                'https://xsoar.docs.pan.run/-/content/-/jobs/123456/artifacts/artifacts/coverage_report/html/index.html'
    results = []

    def mock_handle_github_response(response):
        return response.json()

    def mock_post_response(request):
        body = json.loads(request.body)
        headers = {'request-id': '123456789'}
        results.append(body)
        return 200, headers, json.dumps(body)

    with mock.patch.dict(os.environ, MOCK_ENV_VARIABLES, clear=True):
        mocker.patch('Tests.scripts.utils.add_pr_comment._handle_github_response',
                     side_effect=mock_handle_github_response)
        url = 'https://api.github.com/search/issues'
        query = '?q=1234567890abcdef+repo:demisto/content+org:demisto+is:pr+is:open+head:mock_branch+is:open'

        responses.add(responses.GET, url + query,
                      json={'total_count': 1, 'items': [{'comments_url': 'https://api.github.com/search/issues/1'}]})
        responses.add(responses.GET, 'https://api.github.com/search/issues/1', json={
            'body': COVERAGE_REPORT_COMMENT, 'url': 'https://github.com/comment_123456'}
        )
        responses.add(responses.DELETE, 'https://github.com/comment_123456')
        responses.add_callback(responses.POST, 'https://api.github.com/search/issues/1',
                               callback=mock_post_response, content_type='application/json')

        from Tests.scripts.add_pr_comment import _add_pr_comment
        _add_pr_comment()

    assert expected_results == results[0].get('body')
