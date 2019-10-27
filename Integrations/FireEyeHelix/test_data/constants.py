
SEARCH_AGGREGATIONS_SINGLE = {
    "groupby:subject": {
        "buckets": [
            {
                "key": "Test 1",
                "doc_count": 1
            },
            {
                "key": "Test 2",
                "doc_count": 2
            },
            {
                "key": "Test 3",
                "doc_count": 3
            },
            {
                "key": "Test 4",
                "doc_count": 4
            }
        ],
        "meta": {
            "field": "subject",
            "type": "groupby"
        }
    }
}

SEARCH_AGGREGATIONS_MULTI = {
    "groupby:srcipv4_to_subject": {
        "buckets": [
            {
                "key": "192.168.0.1|%$,$%|test1@demisto.com|%$,$%|accepted",
                "doc_count": 1
            },
            {
                "key": "192.168.0.2|%$,$%|test2@demisto.com|%$,$%|resume",
                "doc_count": 2
            },
            {
                "key": "192.168.0.3|%$,$%|test3@demisto.com|%$,$%|position",
                "doc_count": 3
            }
        ],
        "meta": {
            "fields": [
                "srcipv4",
                "to",
                "subject"
            ],
            "type": "multi_groupby"
        }
    }
}

EXPECTED_AGGREGATIONS_SINGLE_RESULT = [
    {'subject': 'Test 1', 'DocCount': 1},
    {'subject': 'Test 2', 'DocCount': 2},
    {'subject': 'Test 3', 'DocCount': 3},
    {'subject': 'Test 4', 'DocCount': 4}
]

EXPECTED_AGGREGATIONS_MULTI_RESULT = [
    {'srcipv4': '192.168.0.1', 'to': 'test1@demisto.com', 'subject': 'accepted', 'DocCount': 1},
    {'srcipv4': '192.168.0.2', 'to': 'test2@demisto.com', 'subject': 'resume', 'DocCount': 2},
    {'srcipv4': '192.168.0.3', 'to': 'test3@demisto.com', 'subject': 'position', 'DocCount': 3}
]
