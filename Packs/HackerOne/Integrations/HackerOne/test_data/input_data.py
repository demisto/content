MESSAGES = {
    "Common_ERROR_MESSAGE": "Unable to retrieve the data based on arguments.",
    "PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 100.",
    "PAGE_NUMBER": "{} is an invalid value for page number. Page number must be between 1 and int32.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "PROGRAM_HANDLE": "Program Handle is invalid. It should not be empty.",
    "INVALID_MAX_FETCH": "{} is an invalid value for Maximum number of incidents per fetch. "
                         "It must be between 1 and 100.",
    "FILTER": 'Please provide filter in a valid JSON format. Format accepted- \' '
              '{"attribute1" : "value1, value2" , "attribute2" : "value3, value4"} \'.',
    "INVALID_POSITIVE_INT": "{} is an invalid value for {}. It must be between {} and {}."
}

HTTP_ERROR = {
    401: "Unauthenticated. Check the configured Username and API Key.",
    403: "Forbidden. Verify the URL.",
    404: "Please verify the value of Program Handle as well as the value of the URL. "
         "\n Or the URL is not reachable. Please try again later.",
    500: "The server encountered an internal error for HackerOne and was unable to complete your request."
}
exception_handler_params = [
    (400,
     {"errors": [{"detail": "The parameter 'program' is invalid.", "title": "Invalid Parameter"}]},
     "The parameter 'program' is invalid."),
    (400,
     {"errors": [{"title": "Invalid Parameter"}]},
     "Invalid Parameter"),
    (400, {"errors": [{"status": "400"}]}, MESSAGES["Common_ERROR_MESSAGE"]),
    (404, {"errors": [{}]}, HTTP_ERROR[404]),
    (401, {"errors": [{}]}, HTTP_ERROR[401]),
    (500, {"errors": [{}]}, HTTP_ERROR[500]),
    (403, {"errors": [{}]}, HTTP_ERROR[403]),
    (423, {"errors": [{}]}, MESSAGES['Common_ERROR_MESSAGE']),
    (483, {"errors": []}, MESSAGES['Common_ERROR_MESSAGE']),
    (223, {"errors": {}}, MESSAGES['Common_ERROR_MESSAGE']),
    (267, {}, MESSAGES['Common_ERROR_MESSAGE']),

]

report_list_args = [
    ({"program_handle": " abc , xyz", "filter_by_keyword": "abc"},
     {"filter[program][]": ["abc", "xyz"], "filter[keyword]": "abc"}),
    ({"program_handle": "abc", "sort_by": "swag_awarded_at"},
     {"filter[program][]": ["abc"], "sort": ["-reports.swag_awarded_at"]}),
    ({"program_handle": "abc", "sort_by": "-swag_awarded_at"},
     {"filter[program][]": ["abc"], "sort": ["reports.swag_awarded_at"]}),
    ({"program_handle": "abc", "sort_by": "swag_awarded_at,-first_program_activity_at"},
     {"filter[program][]": ["abc"], "sort": ["-reports.swag_awarded_at", "reports.first_program_activity_at"]}),
    ({"program_handle": "ignored", "advanced_filter": '{"filter[reporter][]": "abc", "filter[program][]": "abc"}'},
     {"filter[program][]": ["abc"], "filter[reporter][]": ["abc"]}),
    ({"program_handle": "abc", "advanced_filter": '{"filter[hacker_published]": "true"}'},
     {"filter[program][]": ["abc"], "filter[hacker_published]": "true"}),
    ({"program_handle": "abc", "state": "new"},
     {"filter[program][]": ["abc"], "filter[state][]": ["new"]}),
    ({"program_handle": "abc", "state": "new,resolved"},
     {"filter[program][]": ["abc"], "filter[state][]": ["new", "resolved"]}),
    ({"program_handle": "abc", "severity": "low"},
     {"filter[program][]": ["abc"], "filter[severity][]": ["low"]}),
    ({"program_handle": "abc", "severity": "low,medium"},
     {"filter[program][]": ["abc"], "filter[severity][]": ["low", "medium"]}),
    ({"program_handle": "abc", "severity": "low,medium", "advanced_filter": '{"filter[severity][]": "high"}'},
     {"filter[program][]": ["abc"], "filter[severity][]": ["high"]}),
    ({"program_handle": "abc", "state": "new", "advanced_filter": '{"filter[state][]": "triage"}'},
     {"filter[program][]": ["abc"], "filter[state][]": ["triage"]}),
    ({"program_handle": "abc", "keyword": "new", "advanced_filter": '{"filter[keyword]": "abc"}'},
     {"filter[program][]": ["abc"], "filter[keyword]": "abc"})
]

invalid_args_for_program_list = [
    ({"page_size": "-1"}, MESSAGES["INVALID_POSITIVE_INT"].format("-1", "page_size", 1, 100)),
    ({"page_number": "2147483648"}, MESSAGES["INVALID_POSITIVE_INT"].format("2147483648", "page_number", 1, 2147483647)),
    ({"page_size": "101"}, MESSAGES["INVALID_POSITIVE_INT"].format("101", "page_size", 1, 100)),
    ({"page_number": "-1"}, MESSAGES["INVALID_POSITIVE_INT"].format("-1", "page_number", 1, 2147483647)),
    ({"page_number": "a"}, 'Invalid number: "page_number"="a"'),
    ({"page_size": "abc"}, 'Invalid number: "page_size"="abc"'),
    ({"page_size": "0"}, MESSAGES["INVALID_POSITIVE_INT"].format("0", "page_size", 1, 100)),
    ({"limit": "0"}, MESSAGES["INVALID_POSITIVE_INT"].format("0", "limit", 1, 1000)),
    ({"limit": "1001"}, MESSAGES["INVALID_POSITIVE_INT"].format("1001", "limit", 1, 1000)),
]

valid_params_for_fetch_incidents = [
    ("20", "2020-09-07T04:59:51Z", ['something_h1b', 'checker_h1b'], "", "", "{}", "1",
     {'page[size]': '20', 'filter[created_at__gt]': '2020-09-07T04:59:51',
      'filter[program][]': ['something_h1b', 'checker_h1b'], 'sort': 'reports.created_at', 'page[number]': '1'}),
    ("20", "2020-09-07T04:59:51Z", ['something_h1b'], "", "", "{}", "1",
     {'page[size]': '20', 'filter[created_at__gt]': '2020-09-07T04:59:51',
      'filter[program][]': ['something_h1b'], 'sort': 'reports.created_at', 'page[number]': '1'}),
    ("20", "2020-09-07T04:59:51Z", ['something_h1b'], "", "",
     '{"filter[closed_at__gt]":"2020-10-26T10:48:16.834Z","filter['
     'reporter_agreed_on_going_public]":"false"}', "1",
     {'page[size]': '20', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', 'filter[closed_at__gt]': '2020-10-26T10:48:16.834Z',
      'filter[reporter_agreed_on_going_public]': 'false', 'page[number]': '1'}),
    ("1", "2020-09-07T04:59:51Z", ['something_h1b'], "", "",
     '{"filter[severity][]":"low", "filter[reporter_agreed_on_going_public]": ""}', "1",
     {'page[size]': '1', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', 'filter[severity][]': ['low'], 'page[number]': '1'}),
    ("1", "2020-09-07T04:59:51Z", ['something_h1b'], "", "", '{}', "1",
     {'page[size]': '1', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', 'page[number]': '1'}),
    ("1", "2020-09-07T04:59:51Z", ['something_h1b'], "", "",
     '{"filter[program][]": "hacker_one"}', "1",
     {'page[size]': '1', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['hacker_one'],
      'sort': 'reports.created_at', 'page[number]': '1'}),
    ("4", "2020-09-07T04:59:51Z", ['something_h1b'], "", "",
     '{"filter[program][]": "hacker_one"}', "1",
     {'page[size]': '4', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['hacker_one'],
      'sort': 'reports.created_at', 'page[number]': '1'}),
    ("4", "2020-09-07T04:59:51Z", ['something_h1b'], "low, medium", "",
     '{"filter[severity][]": "high"}', "1",
     {'page[size]': '4', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', "filter[severity][]": ["high"], 'page[number]': '1'}),
    ("4", "2020-09-07T04:59:51Z", ['something_h1b'], ["low, medium"], "",
     '{"filter[state][]": "new"}', "1",
     {'page[size]': '4', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', "filter[severity][]": ["low, medium"], "filter[state][]": ["new"], 'page[number]': '1'}),
    ("4", "2020-09-07T04:59:51Z", ['something_h1b'], "", "triaged",
     '{"filter[state][]": "new"}', "1",
     {'page[size]': '4', 'filter[created_at__gt]': '2020-09-07T04:59:51', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', "filter[state][]": ["new"], 'page[number]': '1'}),

]

invalid_params_for_fetch_incidents = [
    (101, "", "", MESSAGES["INVALID_MAX_FETCH"].format("101")),
    (0, "", "", MESSAGES["INVALID_MAX_FETCH"].format("0")),
    (1, "", "", MESSAGES["PROGRAM_HANDLE"]),
    (1, ["abc"], '{1}', MESSAGES["FILTER"]),
    (1, ["abc"], '1:1', MESSAGES["FILTER"]),
    (1, ["abc"], '{1+1}', MESSAGES["FILTER"]),
    (1, ["abc"], '{a:10}', MESSAGES["FILTER"]),
    (1, ["abc"], 'a', MESSAGES["FILTER"])

]

invalid_args_for_report_list = [
    ({"program_handle": "abc", "advanced_filter": "abc"}, MESSAGES["FILTER"]),
]
