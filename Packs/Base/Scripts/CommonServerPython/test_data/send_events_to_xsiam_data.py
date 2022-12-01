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
        "expected_data": '{"name": "my event 1", "data": "some data 1", "_final_reporting_device_name": "www.example_url.com", \
"_instance_name": "test_integration_instance"}\n{"name": "my event 2", "data": "some data 2", \
"_final_reporting_device_name": "www.example_url.com", "_instance_name": "test_integration_instance"}'
    },
    "json_zero_events": {
        "events": [
        ],
        "number_of_events": 0,
    },
    "text_list_events": {
        "events": [
            "{name: event 1}",
            "{name: event 2}"
        ],
        "number_of_events": 2,
        "expected_format": "text",
        "expected_data": '{name: event 1, _final_reporting_device_name: www.example_url.com, _instance_name: \
test_integration_instance}\n{name: event 2, _final_reporting_device_name: www.example_url.com, \
_instance_name: test_integration_instance}'
    },
    "text_events": {
        "events": "{name: event 1}\n{name: event 2}",
        "number_of_events": 2,
        "expected_format": "text",
        "expected_data": '{name: event 1, _final_reporting_device_name: www.example_url.com, _instance_name: \
test_integration_instance}\n{name: event 2, _final_reporting_device_name: www.example_url.com, \
_instance_name: test_integration_instance}'
    },
    "cef_events": {
        "events": "name=event 1\nname=event 2",
        "number_of_events": 2,
        "format": "cef",
        "expected_format": "cef",
        "expected_data": 'name=event 1 _final_reporting_device_name=www.example_url.com _instance_name=test_integration_instance\n\
name=event 2 _final_reporting_device_name=www.example_url.com _instance_name=test_integration_instance'
    },
    "test_add_system_fields_to_events_case_1": {
        'events': [{"name": "my event 1"}, {"name": "my event 2"}],
        'separator': "",
        'value_sign': "",
        'spaces': "",
        'end_of_event_sign': "",
        'run_parameterless': True,
        'expected_results': [{"name": "my event 1", "_final_reporting_device_name": "www.example_url.com", "_instance_name":
                             "test_integration_instance"}, {"name": "my event 2", "_final_reporting_device_name":
                             "www.example_url.com", "_instance_name": "test_integration_instance"}]
    },
    "test_add_system_fields_to_events_case_2": {
        'events': [{"name": "my event 1"}, {"name": "my event 2"}],
        'separator': ",",
        'value_sign': ":",
        'spaces': " ",
        'end_of_event_sign': "}",
        'run_parameterless': False,
        'expected_results': [{"name": "my event 1", "_final_reporting_device_name": "www.example_url.com", "_instance_name":
                             "test_integration_instance"}, {"name": "my event 2", "_final_reporting_device_name":
                             "www.example_url.com", "_instance_name": "test_integration_instance"}]
    },  
    "test_add_system_fields_to_events_case_3": {
        'events': ["{name: event 1}", "{name: event 2}"],
        'separator': "",
        'value_sign': "",
        'spaces': "",
        'end_of_event_sign': "",
        'run_parameterless': True,
        'expected_results': ['{name: event 1, _final_reporting_device_name: www.example_url.com, _instance_name: \
test_integration_instance}', '{name: event 2, _final_reporting_device_name: www.example_url.com, \
_instance_name: test_integration_instance}']
    },
    "test_add_system_fields_to_events_case_4": {
        'events': ["name=event 1", "name=event 2"],
        'separator': " ",
        'value_sign': "=",
        'spaces': "",
        'end_of_event_sign': "",
        'run_parameterless': False,
        'expected_results': ['name=event 1 _final_reporting_device_name=www.example_url.com \
_instance_name=test_integration_instance', 'name=event 2 _final_reporting_device_name=www.example_url.com \
_instance_name=test_integration_instance']
    },
    "test_add_system_fields_to_events_case_5": {
        'events': [],
        'separator': " ",
        'value_sign': "=",
        'spaces': "",
        'end_of_event_sign': "",
        'run_parameterless': True,
        'expected_results': []
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
        "content-encoding": "gzip"
}}

Response status code: {status_code}
Error received:
\t{error_received}"""