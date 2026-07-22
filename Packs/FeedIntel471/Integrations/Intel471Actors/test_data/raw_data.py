RAW_RESPONSE = {
    "lastUpdated": 1609661791534,
    "handles": [
        "testname"
    ],
    "links": {
        "forums": [
            {
                "name": "testforum",
                "actorHandle": "testname",
                "uid": "4671aeaf49c792689533b00664a5c3ef"
            }
        ],
        "forumTotalCount": 1,
        "instantMessageChannelTotalCount": 0,
        "forumPrivateMessageTotalCount": 0,
        "reportTotalCount": 0,
        "instantMessageTotalCount": 0,
        "instantMessageServerTotalCount": 0,
        "forumPostTotalCount": 3
    },
    "activeFrom": 1171802820000,
    "activeUntil": 1171802820000,
    "uid": "8d0b12d9a3fa8ed75afc38a42e491f9f"
}
CLIENT = {'source_name': 'JSON', 'feed_name_to_config': {
    'api_path': {'extractor': 'actors[*]', 'indicator_type': 'STIX Threat Actor',
                 'indicator': 'links_forums',
                 'mapping': {'handles': 'stixaliases', 'lastUpdated': 'updateddate',
                             'activeFrom': 'activefrom', 'activeUntil': 'activeuntil',
                             'links.forums.name': 'forum_name',
                             'links.forums.actorHandle': 'forum_handle',
                             'forumTotalCount': 'intel471forumtotalcount',
                             'forumPostTotalCount': 'intel471forumposttotalcount',
                             'reportTotalCount': 'intel471reporttotalcount',
                             'instantMessageTotalCount': 'intel471instantmessagetotalcount'},
                 'flat_json_with_prefix': True, 'custom_build_iterator': None,
                 'fetch_time': '10 minutes', 'handle_indicator_function': None}},
          'url': 'api_path', 'verify': False, 'auth': (
        'username',
        'password'), 'headers': None, 'cert': None, 'tlp_color': None}
FEED_DATA = {'extractor': 'actors[*]',
             'indicator_type': 'STIX Threat Actor',
             'indicator': 'links_forums',
             'mapping': {'handles': 'stixaliases', 'lastUpdated': 'updateddate', 'activeFrom': 'activefrom',
                         'activeUntil': 'activeuntil', 'links.forums.name': 'forum_name',
                         'links.forums.actorHandle': 'forum_handle', 'forumTotalCount': 'forumtotalcount',
                         'forumPostTotalCount': 'forumposttotalcount', 'reportTotalCount': 'intel471reporttotalcount',
                         'instantMessageTotalCount': 'instantmessagetotalcount'}, 'flat_json_with_prefix': True,
             'custom_build_iterator': None, 'fetch_time': '10 minutes', 'handle_indicator_function': None}
