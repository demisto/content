from Utils.update_contribution_pack_in_base_branch import get_pr_files

github_response_1 = [
    {
        "sha": "1",
        "filename": "hmm",
        "status": "modified",
        "additions": 1,
        "deletions": 0,
        "changes": 1,
        "blob_url": "https://github.com/demisto/content/blob/1/Packs/Slack/Integrations/Slack/README.md",
        "raw_url": "https://github.com/demisto/content/raw/1/Packs/Slack/Integrations/Slack/README.md",
        "contents_url": "https://api.github.com/repos/demisto/content",
        "patch": "@@ -1,4 +1,5 @@\n <p>\n+  shtak\n   Send messages and notifications to your Slack Team.\n"
    },
    {
        "sha": "2",
        "filename": "what",
        "status": "modified",
        "additions": 2,
        "deletions": 2,
        "changes": 4,
        "blob_url": "https://github.com/demisto/content/blob/1/Packs/Slack/pack_metadata.json",
        "raw_url": "https://github.com/demisto/content/raw/1/Packs/Slack/pack_metadata.json",
        "contents_url": "https://api.github.com/repos/demisto/content/contents",
        "patch": "@@ -13,7 +13,7 @@\n     \"tags\": [],\n     \"useCases\": []"
    }
]

github_response_2 = [
    {
        "sha": "3",
        "filename": "nope",
        "status": "modified",
        "additions": 1,
        "deletions": 0,
        "changes": 1,
        "blob_url": "https://github.com/demisto/content/blob/1/Packs/Slack/Integrations/Slack/README.md",
        "raw_url": "https://github.com/demisto/content/raw/1/Packs/Slack/Integrations/Slack/README.md",
        "contents_url": "https://api.github.com/repos/demisto/content",
        "patch": "@@ -1,4 +1,5 @@\n <p>\n+  shtak\n   Send messages and notifications to your Slack Team.\n"
    },
    {
        "sha": "4",
        "filename": "Packs/Slack/pack_metadata.json",
        "status": "modified",
        "additions": 2,
        "deletions": 2,
        "changes": 4,
        "blob_url": "https://github.com/demisto/content/blob/1/Packs/Slack/pack_metadata.json",
        "raw_url": "https://github.com/demisto/content/raw/1/Packs/Slack/pack_metadata.json",
        "contents_url": "https://api.github.com/repos/demisto/content/contents",
        "patch": "@@ -13,7 +13,7 @@\n     \"tags\": [],\n     \"useCases\": []"
    }
]

github_response_3 = [
    {
        "sha": "1",
        "filename": "hmm",
        "status": "modified",
        "additions": 1,
        "deletions": 0,
        "changes": 1,
        "blob_url": "https://github.com/demisto/content/blob/1/Packs/Slack1/Integrations/Slack/README.md",
        "raw_url": "https://github.com/demisto/content/raw/1/Packs/Slack1/Integrations/Slack/README.md",
        "contents_url": "https://api.github.com/repos/demisto/content",
        "patch": "@@ -1,4 +1,5 @@\n <p>\n+  shtak\n   Send messages and notifications to your Slack Team.\n"
    },
    {
        "sha": "2",
        "filename": "Packs/AnotherPackName/pack_metadata.json",
        "status": "modified",
        "additions": 2,
        "deletions": 2,
        "changes": 4,
        "blob_url": "https://github.com/demisto/content/blob/1/Packs/Slack1/pack_metadata.json",
        "raw_url": "https://github.com/demisto/content/raw/1/Packs/Slack1/pack_metadata.json",
        "contents_url": "https://api.github.com/repos/demisto/content/contents",
        "patch": "@@ -13,7 +13,7 @@\n     \"tags\": [],\n     \"useCases\": []"
    }
]

github_response_4 = []


def test_get_pr_files(requests_mock):
    """
       Scenario: Get a pack dir name from pull request files

       Given
       - A pull request
       - A file in the pull request is in a pack

       When
       - Getting the pack dir name from a pull request

       Then
       - Ensure the pack dir name is returned correctly
    """
    pr_number = '1'
    requests_mock.get(
        'https://api.github.com/repos/demisto/content/pulls/1/files',
        [{'json': github_response_1, 'status_code': 200},
         {'json': github_response_2, 'status_code': 200},
         {'json': github_response_4, 'status_code': 200}]
    )

    pack_dir = list(get_pr_files(pr_number))

    assert pack_dir == ['Slack']


def test_get_multiple_pr_files(requests_mock):
    """
       Scenario: Get a list of pack dir names from pull request files

       Given
       - A pull request
       - Files in the pull request are in a pack

       When
       - Getting the pack dir names from a pull request

       Then
       - Ensure pack dir names are returned correctly
    """
    pr_number = '1'
    requests_mock.get(
        'https://api.github.com/repos/demisto/content/pulls/1/files',
        [{'json': github_response_1, 'status_code': 200},
         {'json': github_response_2, 'status_code': 200},
         {'json': github_response_3, 'status_code': 200},
         {'json': github_response_4, 'status_code': 200}]
    )

    pack_dir = list(get_pr_files(pr_number))

    assert pack_dir == ['Slack', 'AnotherPackName']


def test_get_pr_files_no_pack(requests_mock):
    """
       Scenario: Get a pack dir name from pull request files

       Given
       - A pull request
       - No file in the pull request is in a pack

       When
       - Getting the pack dir name from a pull request

       Then
       - Ensure the pack dir name is empty
    """
    pr_number = '1'

    requests_mock.get(
        'https://api.github.com/repos/demisto/content/pulls/1/files',
        [{'json': github_response_1, 'status_code': 200},
         {'json': github_response_4, 'status_code': 200}]
    )

    pack_dir = list(get_pr_files(pr_number))

    assert pack_dir == []
