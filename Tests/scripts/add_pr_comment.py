import os
import sys
import requests
COVERAGE_REPORT_COMMENT = 'Link to the coverage report of the integration'


def _handle_github_response(response) -> dict:
    res_dict = response.json()
    if not response.ok:
        print(f'Add pull request comment failed: {res_dict.get("message")}')
    return res_dict


def _add_pr_comment(comment):
    token = os.environ['CONTENT_GITHUB_TOKEN']
    branch_name = os.environ['CI_COMMIT_BRANCH']
    sha1 = os.environ['CI_COMMIT_SHA']

    query = '?q={}+repo:demisto/content+org:demisto+is:pr+is:open+head:{}+is:open'.format(sha1, branch_name)
    url = 'https://api.github.com/search/issues'
    headers = {'Authorization': 'Bearer ' + token}
    try:
        response = requests.get(url + query, headers=headers, verify=False)
        res = _handle_github_response(response)

        if res and res.get('total_count', 0) == 1:
            issue_url = res['items'][0].get('comments_url') if res.get('items', []) else None
            if issue_url:
                response = requests.get(issue_url, headers=headers, verify=False)
                issue_comments = _handle_github_response(response)
                for existing_comment in issue_comments:
                    # Check if a comment about report coverage already exists. If there is delete it first and then post
                    # a new comment:
                    if COVERAGE_REPORT_COMMENT in existing_comment.get('body'):
                        comment_url = existing_comment.get('url')
                        requests.delete(comment_url, headers=headers, verify=False)
                coverage_report_res = requests.post(issue_url, json={'body': comment},
                                                    headers=headers, verify=False)
                _handle_github_response(coverage_report_res)
        else:
            print('Add pull request comment failed: There is more then one open pull request for branch {branch_name}.')
    except Exception:
        print('Add pull request comment failed')


coverage_link = f'https://xsoar.docs.pan.run/-/content/-/jobs/{os.environ.get("CI_JOB_ID")}' \
                f'/artifacts/artifacts/coverage_report/html/index.html'
coverage_report_comment = f'{COVERAGE_REPORT_COMMENT}:\n {coverage_link}'
_add_pr_comment(coverage_report_comment)

