MULTI_ERRORS_HTTP_RESPONSE = {
    "errors": [
        {
            "code": 403,
            "message": "access denied, authorization failed"
        },
        {
            "code": 401,
            "message": "test error #1"
        },
        {
            "code": 402,
            "message": "test error #2"
        }
    ],
    "meta": {
        "powered_by": "crowdstrike-api-gateway",
        "query_time": 0.000654734,
        "trace_id": "39f1573c-7a51-4b1a-abaa-92d29f704afd"
    }
}

NO_ERRORS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "crowdstrike-api-gateway",
        "query_time": 0.000654734,
        "trace_id": "39f1573c-7a51-4b1a-abaa-92d29f704afd"
    }
}
