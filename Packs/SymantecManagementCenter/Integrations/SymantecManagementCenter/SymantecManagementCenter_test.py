from SymantecManagementCenter import main, LOCAL_CATEGORY_DB_TYPE
import demistomock as demisto


def test_add_policy_content_local_category_db(mocker, requests_mock):
    """
    Given:
     - URL to add to as content to category of LOCAL_CATEGORY_DB

    When:
     - Running add content command

    Then:
     - Ensure the expected request body is sent
     - Verify expected human readable output
    """
    content = {
        'content': {
            'categories': [
                {
                    'type': 'inline',
                    'name': 'category1',
                    'entries': [{'type': 'url', 'url': 'www.demisto.com', 'comment': None}]
                },
                {
                    'type': 'inline',
                    'name': 'category2',
                    'entries': [
                        {'type': 'url', 'url': 'www.google.com', 'comment': 'comment'},
                        {'type': 'url', 'url': 'www.apple.com', 'comment': 'comment'},
                    ]
                },
                {
                    'type': 'inline',
                    'name': 'category3',
                    'entries': [{'type': 'url', 'url': 'www.demisto.com', 'comment': 'comment'}]
                },
                {
                    'type': 'inline',
                    'name': 'category4',
                    'entries': [{'type': 'url', 'url': 'www.google.com', 'comment': 'comment'}]
                },
                {
                    'type': 'inline',
                    'name': 'category5',
                    'entries': [{'type': 'url', 'url': '8.8.8.8', 'comment': 'comment'}]
                },
                {
                    'type': 'inline',
                    'name': 'category6',
                    'entries': [
                        {'type': 'url', 'url': 'www.demisto.com', 'comment': 'comment'},
                        {'type': 'url', 'url': 'www.paloaltonetworks.net', 'comment': 'comment'}
                    ]
                }
            ]
        },
        'schemaVersion': '1.0',
        'revisionInfo': {
            'revisionNumber': '1.12',
            'revisionDescription': 'desc',
            'author': 'admin',
            'revisionDate': '2020-01-25T14:58:06'
        }
    }
    url_to_add = 'www.cnn.com'
    comment = 'test comment'
    mocker.patch.object(demisto, 'command', return_value='symantec-mc-add-policy-content')
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'url': 'https://server',
            'credentials': {}
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'uuid': 'uuid',
            'content_type': LOCAL_CATEGORY_DB_TYPE,
            'change_description': 'desc',
            'category': 'category2',
            'url': url_to_add,
            'description': comment
        }
    )
    mocker.patch.object(demisto, 'results')
    requests_mock.get('https://server/api/policies/uuid/content', json=content)
    requests_mock.post('https://server/api/policies/uuid/content', json={})
    main()
    expected_request_body = dict(content)
    expected_request_body['content']['categories'][1]['entries'].append({
        'type': 'url', 'url': url_to_add, 'comment': comment
    })
    assert requests_mock.request_history[1].json()['content'] == expected_request_body['content']
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results['HumanReadable'] == """### Successfully added content to the policy
|category|change_description|content_type|description|url|uuid|
|---|---|---|---|---|---|
| category2 | desc | LOCAL_CATEGORY_DB | test comment | www.cnn.com | uuid |
"""
