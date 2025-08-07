exception_handler_params = [
    (404, "The resource cannot be found."),
    (
        407,
        "Proxy Error - cannot connect to proxy. Either try clearing the 'Use system proxy' check-box or"
        "check the host, authentication details and connection details for the proxy.",
    ),
    (500, "The server encountered an internal error for VMWare Workspace ONE UEM and was unable to complete " "your request."),
]

authentication_params = [
    (401, "test_data/invalid_username_password_error_msg.json"),
    (403, "test_data/invalid_api_key_error_msg.json"),
]

vmuem_devices_search_validation_errors_params = [
    ({"last_seen": "abc"}, 'Invalid date: "last_seen"="abc"', "", ""),
    ({"page_size": "abc"}, 'Invalid number: "page_size"="abc"', "", ""),
    ({"page_size": "-1"}, "", "INVALID_PAGE_SIZE", ""),
    ({"page": "abc"}, 'Invalid number: "page"="abc"', "", ""),
    ({"page": "-1"}, "", "INVALID_PAGE", ""),
    ({"ownership": "abc"}, "", "INVALID_OWNERSHIP", ""),
    ({"sort_order": "abc"}, "", "INVALID_SORT_ORDER", ""),
]

device_osupdates_list_cmd_arg = [
    (404, "The resource cannot be found.", {"uuid": "dummy"}),
]
