import os
import requests


COVERAGE_REPORT_COMMENT = 'Link to the unit tests coverage report'
JOB_ID = os.environ.get("CI_JOB_ID")
COVERAGE_LINK = f'https://xsoar.docs.pan.run/-/content/-/jobs/{JOB_ID}/artifacts/artifacts/coverage_report/html/' \
                f'index.html'


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

        print(res_dict)

        if res_dict and res_dict.get('total_count', 0) == 1:
            issue_url = res_dict['items'][0].get('comments_url') if res_dict.get('items', []) else None
            if issue_url:
                response = requests.get(issue_url, headers=headers)
                issue_comments = response.json()
                for existing_comment in issue_comments:
                    # Check if a comment about report coverage already exists. If there is delete it first and then post
                    # a new comment:
                    if COVERAGE_REPORT_COMMENT in existing_comment.get('body'):
                        comment_url = existing_comment.get('url')
                        requests.delete(comment_url, headers=headers)
                requests.post(issue_url, json={'body': f'{COVERAGE_REPORT_COMMENT}:\n {COVERAGE_LINK}'},
                              headers=headers)
        else:
            print(f'Failed adding coverage report comment for pull request: There is more than one open pull request '
                  f'for branch {branch_name}.')
    except Exception as e:
        print(f'Failed adding coverage report comment for pull request: {e}')


if __name__ == "__main__":
    add_pr_comment()