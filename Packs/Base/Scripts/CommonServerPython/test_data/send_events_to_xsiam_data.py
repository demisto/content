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
    }
}
