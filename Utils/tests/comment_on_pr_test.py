from Utils.comment_on_pr import get_pr_comments_url


github_comment_response_1 = [
    {
        "url": "https://api.github.com/repos/demisto/content/pulls/comments/477124055",
        "body": "shtak"
    },
    {
        "url": "https://api.github.com/repos/demisto/content/pulls/comments/477138466",
        "body": "eyy",
    }
]

github_comment_response_2 = [
    {
        "url": "https://api.github.com/repos/demisto/content/pulls/comments/477124056",
        "body": "Instance is ready. blablabla."
    },
    {
        "url": "https://api.github.com/repos/demisto/content/pulls/comments/477138467",
        "body": "eyyy",
    }
]

github_comment_response_3: list = []


def test_get_pr_comments_url_existing(requests_mock):
    """
       Scenario: Get the comments URL for a pull request

       Given
       - A pull request
       - An existing comment with an instance link on the pull requests

       When
       - Getting the pull request comments URL in order to add a comment

       Then
       - Ensure the comments URL is the existing comment
    """
    pr_number = '1'
    requests_mock.get('https://api.github.com/repos/demisto/content/pulls/1',
                      json={'comments_url': 'https://api.github.com/repos/demisto/content/issues/1/comments'},
                      status_code=200)
    requests_mock.get(
        'https://api.github.com/repos/demisto/content/issues/1/comments',
        [{'json': github_comment_response_1, 'status_code': 200},
         {'json': github_comment_response_2, 'status_code': 200},
         {'json': github_comment_response_3, 'status_code': 200}]
    )

    comments_url = get_pr_comments_url(pr_number)

    assert comments_url == 'https://api.github.com/repos/demisto/content/pulls/comments/477124056'


def test_get_pr_comments_url_new(requests_mock):
    """
       Scenario: Get the comments URL for a pull request

       Given
       - A pull request
       - No existing comment with an instance link on the pull requests

       When
       - Getting the pull request comments URL in order to add a comment

       Then
       - Ensure the comments URL is a new comment
    """
    pr_number = '1'
    requests_mock.get('https://api.github.com/repos/demisto/content/pulls/1',
                      json={'comments_url': 'https://api.github.com/repos/demisto/content/issues/1/comments'},
                      status_code=200)
    requests_mock.get(
        'https://api.github.com/repos/demisto/content/issues/1/comments',
        [{'json': github_comment_response_1, 'status_code': 200},
         {'json': github_comment_response_3, 'status_code': 200}]
    )

    comments_url = get_pr_comments_url(pr_number)

    assert comments_url == 'https://api.github.com/repos/demisto/content/issues/1/comments'
