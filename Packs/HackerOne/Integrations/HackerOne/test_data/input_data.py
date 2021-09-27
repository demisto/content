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


common_args = [
    ({}, {"page[size]": 50}),
    ({"page_size": ""}, {"page[size]": 50}),
    ({"page_size": "1"}, {"page[size]": 1}),
    ({"page_size": "100"}, {"page[size]": 100}),
    ({"page_number": "0"}, {'page[size]': 50, "page[number]": 0}),
    ({"page_number": "1"}, {'page[size]': 50, "page[number]": 1}),
    ({"page_size": "1", "page_number": "1"}, {"page[size]": 1, "page[number]": 1})
]

report_list_args = [
    ({"program_handle": " abc , xyz", "filter_by_keyword": "abc"},
     {"filter[program][]": ["abc", "xyz"], "filter[keyword]": "abc", 'page[size]': 50}),
    ({"program_handle": "abc", "sort_by": "swag_awarded_at, "},
     {"filter[program][]": ["abc"], "sort": ["reports.swag_awarded_at"], 'page[size]': 50}),
    ({"program_handle": "abc", "sort_by": "-swag_awarded_at, "},
     {"filter[program][]": ["abc"], "sort": ["-reports.swag_awarded_at"], 'page[size]': 50}),
    ({"program_handle": "abc", "sort_by": "swag_awarded_at,-first_program_activity_at"},
     {"filter[program][]": ["abc"], "sort": ["reports.swag_awarded_at", "-reports.first_program_activity_at"],
      'page[size]': 50}),
    ({"program_handle": "ignored", "advanced_filter": '{"filter[reporter][]": "abc", "filter[program][]": "abc"}'},
     {"filter[program][]": ["abc"], "filter[reporter][]": ["abc"], 'page[size]': 50}),
    ({"program_handle": "abc", "advanced_filter": '{"filter[hacker_published]": "true"}'},
     {"filter[program][]": ["abc"], "filter[hacker_published]": "true", 'page[size]': 50}),
    ({"program_handle": "abc", "state": "new, "},
     {"filter[program][]": ["abc"], "filter[state][]": ["new"], 'page[size]': 50}),
    ({"program_handle": "abc", "state": "new,resolved"},
     {"filter[program][]": ["abc"], "filter[state][]": ["new", "resolved"], 'page[size]': 50}),
    ({"program_handle": "abc", "severity": "low, "},
     {"filter[program][]": ["abc"], "filter[severity][]": ["low"], 'page[size]': 50}),
    ({"program_handle": "abc", "severity": "low,medium"},
     {"filter[program][]": ["abc"], "filter[severity][]": ["low", "medium"], 'page[size]': 50}),
    ({"program_handle": "abc", "severity": "low,medium", "advanced_filter": '{"filter[severity][]": "high"}'},
     {"filter[program][]": ["abc"], "filter[severity][]": ["high"], 'page[size]': 50}),
    ({"program_handle": "abc", "state": "new", "advanced_filter": '{"filter[state][]": "triage"}'},
     {"filter[program][]": ["abc"], "filter[state][]": ["triage"], 'page[size]': 50}),
    ({"program_handle": "abc", "keyword": "new", "advanced_filter": '{"filter[keyword]": "abc"}'},
     {"filter[program][]": ["abc"], "filter[keyword]": "abc", 'page[size]': 50})
]

invalid_args_for_program_list = [
    ({"page_size": "-1"}, MESSAGES["PAGE_SIZE"].format("-1")),
    ({"page_number": "2147483648"}, MESSAGES["PAGE_NUMBER"].format("2147483648")),
    ({"page_size": "101"}, MESSAGES["PAGE_SIZE"].format("101")),
    ({"page_number": "-1"}, MESSAGES["PAGE_NUMBER"].format("-1")),
    ({"page_number": "a"}, '"a" is not a valid number'),
    ({"page_size": "abc"}, '"abc" is not a valid number'),
    ({"page_size": "0"}, MESSAGES["PAGE_SIZE"].format("0"))
]

valid_params_for_fetch_incidents = [
    ({"max_fetch": "20", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b , checker_h1b"},
     {'page[size]': 20, 'filter[created_at__gt]': '2020-09-07T04:59:51Z',
      'filter[program][]': ['something_h1b', 'checker_h1b'], 'sort': 'reports.created_at'}),
    ({"max_fetch": "20", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b, "},
     {'page[size]': 20, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at'}),
    ({"max_fetch": "20", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[closed_at__gt]":"2020-10-26T10:48:16.834Z","filter['
                   'reporter_agreed_on_going_public]":"false"}'},
     {'page[size]': 20, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', 'filter[closed_at__gt]': '2020-10-26T10:48:16.834Z',
      'filter[reporter_agreed_on_going_public]': 'false'}),
    ({"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[severity][]":"low", "filter[reporter_agreed_on_going_public]": ""}'},
     {'page[size]': 1, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', 'filter[severity][]': ['low']}),
    ({"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{}'},
     {'page[size]': 1, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at'}),
    ({"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[program][]": "hacker_one"}'},
     {'page[size]': 1, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['hacker_one'],
      'sort': 'reports.created_at'}),
    ({"max_fetch": "4", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[program][]": "hacker_one"}'},
     {'page[size]': 4, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['hacker_one'],
      'sort': 'reports.created_at'}),
    ({"max_fetch": "4", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[severity][]": "high"}', "severity": "low, medium"},
     {'page[size]': 4, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', "filter[severity][]": ["high"]}),
    ({"max_fetch": "4", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[state][]": "new"}', "severity": ["low, medium"]},
     {'page[size]': 4, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', "filter[severity][]": ["low, medium"], "filter[state][]": ["new"]}),
    ({"max_fetch": "4", "first_fetch": "2020-09-07T04:59:51Z", "program_handle": "something_h1b",
      "filter_by": '{"filter[state][]": "new"}', "state": "triaged"},
     {'page[size]': 4, 'filter[created_at__gt]': '2020-09-07T04:59:51Z', 'filter[program][]': ['something_h1b'],
      'sort': 'reports.created_at', "filter[state][]": ["new"]}),

]

invalid_params_for_fetch_incidents = [
    ({"max_fetch": "a"}, '"a" is not a valid number'),
    ({"max_fetch": "101"}, MESSAGES["INVALID_MAX_FETCH"].format("101")),
    ({"max_fetch": "0"}, MESSAGES["INVALID_MAX_FETCH"].format("0")),
    ({"max_fetch": "1", "first_fetch": "None", "program_handle": "abc"}, '"None" is not a valid date'),
    ({"max_fetch": "1", "first_fetch": "1 day"}, MESSAGES["PROGRAM_HANDLE"]),
    ({"max_fetch": "1", "first_fetch": "1 day", "program_handle": "   "}, MESSAGES["PROGRAM_HANDLE"]),
    ({"max_fetch": "1", "first_fetch": "1 day", "program_handle": "abc", "filter_by": '{1}'}, MESSAGES["FILTER"]),
    ({"max_fetch": "1", "first_fetch": "1 day", "program_handle": "abc", "filter_by": '1'}, MESSAGES["FILTER"]),
    ({"max_fetch": "1", "first_fetch": "1 day", "program_handle": "abc", "filter_by": '{1+1}'}, MESSAGES["FILTER"]),
    ({"max_fetch": "1", "first_fetch": "1 day", "program_handle": "abc", "filter_by": '{a:10}'}, MESSAGES["FILTER"]),
    ({"max_fetch": "1", "first_fetch": "1 day", "program_handle": "abc", "filter_by": 'a'}, MESSAGES["FILTER"]),
]

invalid_args_for_report_list = [
    ({"program_handle": ""}, MESSAGES['PROGRAM_HANDLE']),
    ({"program_handle": "abc", "advanced_filter": "abc"}, MESSAGES["FILTER"]),
]
