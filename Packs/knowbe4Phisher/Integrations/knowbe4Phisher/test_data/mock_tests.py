create_request_test = [
    ("""mutation {{
  phisherCommentCreate(comment: \\"{}\\", id: \\"{}\\") {{
    errors {{
      field
      placeholders
      reason
    }}
    node {{
      body
      createdAt
    }}
  }}
}}""",
     'mutation {{\\n  phisherCommentCreate(comment: \\"{}\\", id: \\"{}\\") {{\\n    errors {{\\n      field\\n\
      placeholders\\n      reason\\n    }}\\n    node {{\\n      body\\n      createdAt\\n    }}\\n  }}\\n}}'),
    ("""query {{
  phisherMessages(all: false, page: 1, per: {}, query: ) {{
    nodes {{
      actionStatus
      attachments(status: UNKNOWN) {{
        actualContentType
        filename
        md5
        reportedContentType
        s3Key
        sha1
        sha256
        size
        ssdeep
        virustotal {{
          permalink
          positives
          scanned
          sha256
        }}
      }}
      category
      comments {{
        body
        createdAt
      }}
      events {{
        causer
        createdAt
        eventType
        id
        triggerer
      }}
      from
      id
      links(status: UNKNOWN) {{
        dispositions
        firstSeen
        id
        lastSeen
        scheme
        target
        url
        virustotal {{
          permalink
          positives
          scanned
          sha256
        }}
      }}
      phishmlReport {{
        confidenceClean
        confidenceSpam
        confidenceThreat
      }}
      pipelineStatus
      rawUrl
      reportedBy
      rules {{
        createdAt
        description
        id
        matchedCount
        name
        tags
      }}
      severity
      subject
      tags {{
        name
        type
      }}
    }}
    pagination {{
      page
      pages
      per
      totalCount
    }}
  }}
}}""",
     'query {{\\n  phisherMessages(all: false, page: 1, per: {}, query: ) {{\\n    nodes {{\\n      actionStatus\\n\
      attachments(status: UNKNOWN) {{\\n        actualContentType\\n        filename\\n        md5\\n  \
      reportedContentType\\n        s3Key\\n        sha1\\n        sha256\\n        size\\n        ssdeep\\n  \
      virustotal {{\\n          permalink\\n          positives\\n          scanned\\n          sha256\\n        }}\\n\
      }}\\n      category\\n      comments {{\\n        body\\n        createdAt\\n      }}\\n      events {{\\n  \
      causer\\n        createdAt\\n        eventType\\n        id\\n        triggerer\\n      }}\\n      from\\n      id\\n\
      links(status: UNKNOWN) {{\\n        dispositions\\n        firstSeen\\n        id\\n        lastSeen\\n        scheme\\n  \
      target\\n        url\\n        virustotal {{\\n          permalink\\n          positives\\n          scanned\\n    \
      sha256\\n        }}\\n      }}\\n      phishmlReport {{\\n        confidenceClean\\n        confidenceSpam\\n  \
      confidenceThreat\\n      }}\\n      pipelineStatus\\n      rawUrl\\n      reportedBy\\n      rules {{\\n  \
      createdAt\\n        description\\n        id\\n        matchedCount\\n        name\\n        tags\\n      }}\\n\
      severity\\n      subject\\n      tags {{\\n        name\\n        type\\n      }}\\n    }}\\n    pagination {{\\n\
      page\\n      pages\\n      per\\n      totalCount\\n    }}\\n  }}\\n}}')]


pagination_response = \
    [
        {
            "data": {
                "phisherMessages": {
                    "pagination": {
                        "page": 1,
                        "pages": 1,
                        "per": 28,
                        "totalCount": 13
                    }
                }
            }
        },
        {
            "data": {
                "phisherMessages": {
                    "pagination": {
                        "page": 1,
                        "pages": 1,
                        "per": 28,
                        "totalCount": 31
                    }
                }
            }
        }
    ]


response_fetch = [({}),
        ({"data":
            {"phisherMessages":
                {
                    "nodes":
                        [
                            {"actionStatus": "RECEIVED", "category": "UNKNOWN", "comments": [], "events":
                                [
                                    {"causer": 'null', "createdAt": "2021-08-08T14:06:11Z", "eventType": "CREATED",
                                     "id": "da4b66b2-adef-438d-83d0-e8d0067cd822", "triggerer": 'null'},
                                    {"causer": "KB4:URGENCY", "createdAt": "2021-08-08T14:06:31Z", "eventType": "OTHER", "id":
                                     "40e32f01-44ce-498a-9731-0ef8aeb07fbc", "triggerer": 'null'},
                                    {"causer": "E K", "createdAt": "2021-08-08T14:06:54Z", "eventType": "OTHER",
                                     "id": "82b81815-eebb-4ac5-b86d-0e70a72d518e", "triggerer": 'null'}],
                             "from": "ek@gmail.com", "id": "bac9cf67-fa8e-46d1-ad67-69513fc44b5b",
                             "phishmlReport": 'null', "pipelineStatus": "PROCESSED", "severity": "UNKNOWN_SEVERITY", "subject":
                             "Fwd: We have received your IT request", "tags": [{"name": "KB4:SECURITY", "type": "STANDARD"},
                                                                               {"name": "KB4:URGENCY", "type": "STANDARD"}]}
                        ],
                    "pagination": {"page": 1, "pages": 1, "per": 100, "totalCount": 31}}}})]
expected_fetch = [([]),
       ([{'name': 'Fwd: We have received your IT request', 'occurred': '2021-08-08T14:06:11+00:00', 'rawJSON':
           '{"actionStatus": "RECEIVED", "category": "UNKNOWN", "comments": [], "from": "ek@gmail.com", \
"id": "bac9cf67-fa8e-46d1-ad67-69513fc44b5b", "phishmlReport": "null", "pipelineStatus": "PROCESSED", "severity": \
"UNKNOWN_SEVERITY", "subject": "Fwd: We have received your IT request", "tags": [{"name": "KB4:SECURITY", "type": \
"STANDARD"}, {"name": "KB4:URGENCY", "type": "STANDARD"}], "created at": "2021-08-08T14:06:11+00:00"}'}])]


events_example = [
    {
        "causer": 'null',
        "createdAt": "2021-08-08T14:06:11Z",
        "eventType": "CREATED",
        "events": 'null',
        "id": "da4b66b2-adef-438d-83d0-e8d0067cd822",
        "triggerer": 'null'
    },
    {
        "causer": "KB4:URGENCY",
        "createdAt": "2021-08-08T14:06:31Z",
        "eventType": "OTHER",
        "events": {
            "added": [
                "KB4:SECURITY"
            ],
            "removed": []
        },
        "id": "40e32f01-44ce-498a-9731-0ef8aeb07fbc",
        "triggerer": 'null'
    },
    {
        "causer": "E K",
        "createdAt": "2021-08-08T14:06:54Z",
        "eventType": "OTHER",
        "events": {
            "changes": [
                {
                    "from": "false",
                    "name": "viewed",
                    "to": "true"
                }
            ]
        },
        "id": "82b81815-eebb-4ac5-b86d-0e70a72d518e",
        "triggerer": 'null'
    }
]
expected_time = ("2021-08-08T14:06:11Z")