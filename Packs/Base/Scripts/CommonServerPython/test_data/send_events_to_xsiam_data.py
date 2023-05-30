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
                "name": "Event 1",
                "data": "The only way to do great work is to love what you do. - Steve Jobs"
            },
            {
                "name": "Event 2",
                "data": "The best way to predict your future is to create it. - Abraham Lincoln"
            },
            {
                "name": "Event 3",
                "data": "The only thing we have to fear is fear itself. - Franklin D. Roosevelt"
            },
            {
                "name": "Event 4",
                "data": "The greatest glory in living lies not in never falling, but in rising every time we fall. - Nelson Mandela"
            },
            {
                "name": "Event 5",
                "data": "Believe you can and you're halfway there. - Theodore Roosevelt"
            },
            {
                "name": "Event 6",
                "data": "If you want to live a happy life, tie it to a goal, not to people or things. - Albert Einstein"
            },
            {
                "name": "Event 7",
                "data": "The only true wisdom is in knowing you know nothing. - Socrates"
            },
            {
                "name": "Event 8",
                "data": "Life is what happens when you're busy making other plans. - John Lennon"
            },
            {
                "name": "Event 9",
                "data": "Spread love everywhere you go. Let no one ever come to you without leaving happier. - Mother Teresa"
            },
            {
                "name": "Event 10",
                "data": "In three words I can sum up everything I've learned about life: it goes on. - Robert Frost"
            }
        ],
        "number_of_events": 10,
        "expected_data": '{"name": "Event 10", "data": "In three words I can sum up everything I\'ve learned about life: it goes on. - Robert Frost"}',
        "expected_format": "json",
        "XSIAM_FILE_SIZE": 300
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