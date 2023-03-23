events_dict = {
    "json_events": {
        "events": [
            {
                "name": "my event 1",
                "data": "some data 1"
            },
            {
                "name": "my event 2",
                "data": "some data 2"
            }
        ],
        "number_of_events": 2,
        "expected_format": "json",
        "expected_data": '{"name": "my event 1", "data": "some data 1"}\n{"name": "my event 2", "data": "some data 2"}'
    },
    "json_zero_events": {
        "events": [
        ],
        "number_of_events": 0,
    },
    "text_list_events": {
        "events": [
            "Some event 1",
            "Some event 2"
        ],
        "number_of_events": 2,
        "expected_format": "text",
        "expected_data": "Some event 1\nSome event 2"
    },
    "text_events": {
        "events": "Some event 1\nSome event 2",
        "number_of_events": 2,
        "expected_format": "text",
        "expected_data": "Some event 1\nSome event 2"
    },
    "cef_events": {
        "events": "Some cef event 1\nSome cef event 2",
        "number_of_events": 2,
        "format": "cef",
        "expected_format": "cef",
        "expected_data": "Some cef event 1\nSome cef event 2",
    },
    "big_event": {
        "events": [
            {
                "name": "my event 1",
                "data": "some data 1"
            },
            {
                "name": "my event 2",
                "data": "some data 2"
            },
            {
                "name": "my event 3",
                "data": "some data 3"
            },
            {
                "name": "my event 4",
                "data": "some data 4"
            },
            {
                "name": "my event 5",
                "data": "some data 5"
            },
            {
                "name": "my event 6",
                "data": "some data 6"
            }
        ],
        "number_of_events": 2,
        "expected_data": '{"name": "my event 5", "data": "some data 5"}\n{"name": "my event 6", "data": "some data 6"}',
        "expected_format": "json",
        "XSIAM_FILE_SIZE": 32
    }
}

log_error = \
    """Error sending new events into XSIAM.
Parameters used:
\tURL: https://api-url
\tHeaders: {{
        "authorization": "TOKEN",
        "format": "json",
        "product": "some product",
        "vendor": "some vendor",
        "content-encoding": "gzip",
        "collector-name": "test_brand",
        "instance-name": "test_integration_instance",
        "final-reporting-device": "www.test_url.com"
}}

Response status code: {status_code}
Error received:
\t{error_received}"""