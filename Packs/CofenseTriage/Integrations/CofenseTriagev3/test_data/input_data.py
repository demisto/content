import time
import dateparser

MESSAGES = {
    'NO_RECORDS_FOUND': "No {} were found for the given argument(s).",
    "API_TOKEN": "No API token found. Please try again.",
    "PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 200.",
    "PAGE_NUMBER": "{} is an invalid value for page number. Page number must be greater than 0",
    "FILTER": 'Please provide the filter in the valid JSON format. Format accepted- \' '
              '{"attribute1_operator" : "value1, value2" , "attribute2_operator" : "value3, value4"} \'',
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "INVALID_MAX_FETCH": "{} is an invalid value for maximum fetch. Maximum fetch must be between 1 and 200.",
    "INVALID_FIRST_FETCH": "Argument 'First fetch time interval' should be a valid date or relative timestamp such as "
                           "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "INVALID_LOCATION_FOR_CATEGORY_ID": "If Category ID is provided in fetch incident parameters, the Report Location "
                                        "cannot be 'Inbox' or 'Reconnaissance'.",
    "INVALID_LOCATION_FOR_CATEGORIZATION_TAGS": "If Categorization Tags are provided in fetch incident parameters, "
                                                "the Report Location cannot be 'Inbox' or 'Reconnaissance'.",
    "INVALID_LOCATION_FOR_TAGS": "If Tags are provided in fetch incident parameters, the Report Location "
                                 "must be 'Reconnaissance'.",
    "BODY_FORMAT": "Invalid value for body format. Body format must be text or json.",
    "INTEGRATION_SUBMISSION_TYPE": "Invalid value for integration submission type. Type must be urls or "
                                   "attachment_payloads.",
    "INVALID_BOOLEAN": "Argument does not contain a valid boolean-like value",
    "INVALID_IMAGE_TYPE": "Invalid value for type. Type must be png or jpg."
}

# To be used for testing all the cases of exception handler
exception_handler = [("Bad request", 404,
                      {"errors": [{"detail": "The record identified by -1 could not be found."}]},
                      "Resource not found: invalid endpoint was called.\n"
                      "Details: The record identified by -1 could not be found."),
                     ("Unprocessable Entity", 422, {"errors": [{"detail": "threat_key - can't be blank"},
                                                               {"detail": "threat_value - can't be blank"}]},
                      "Unprocessable Entity\nDetails: threat_key - can't be blank,threat_value - can't be blank"),
                     ("Bad request", 404, "API not found.",
                      "Resource not found: invalid endpoint was called.\nDetails: API not found.")]

# To be used for testing all the negative scenarios of the function validate_arguments
validate_args = [
    ({"page_size": -1}, MESSAGES["PAGE_SIZE"].format(-1)),
    ({"page_size": 201}, MESSAGES["PAGE_SIZE"].format(201)),
    ({"page_size": 0}, MESSAGES["PAGE_SIZE"].format(0)),
    ({"page_number": "0"}, MESSAGES["PAGE_NUMBER"].format(0)),
    ({"page_number": "abc"}, "\"abc\" is not a valid number"),
    ({"page_number": "-1"}, MESSAGES["PAGE_NUMBER"].format(-1)),
    ({"page_number": "-1"}, MESSAGES["PAGE_NUMBER"].format(-1)),
    ({"updated_at": "abc"}, '"abc" is not a valid date')
]

invalid_args_for_threat_indicator_list = [
    ({"filter_by": '{"threat_level_eq"= "Benign", "updated_at_gt"="2020-10-21T20:54:24.185Z"}'}),
    ({"filter_by": '{"threat_level_eq":'}),
    ({"filter_by": "123"}),
    ({"filter_by": ':"12"}'})
]

list_report_cmd_arg = [
    ({"match_priority": "ab"}, "\"ab\" is not a valid number"),
]

list_category_cmd_arg = [
    ({"is_malicious": "test"}, MESSAGES["INVALID_BOOLEAN"]),
    ({"page_number": "-1"}, MESSAGES["PAGE_NUMBER"].format(-1))
]

create_threat_indicators_cmd_arg = [
    ({"threat_level": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("threat_level")),
    ({"threat_level": "1", "threat_type": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("threat_type")),
    ({"threat_level": "1", "threat_type": "a", "threat_value": ""},
     MESSAGES["REQUIRED_ARGUMENT"].format("threat_value"))
]

list_rule_cmd_arg = [
    ({"active": "test"}, MESSAGES["INVALID_BOOLEAN"]),
    ({"page_number": "-1"}, MESSAGES["PAGE_NUMBER"].format(-1)),
    ({"priority": "a"}, "\"a\" is not a valid number")
]

list_cluster_cmd_arg = [
    ({"match_priority": "test"}, "\"test\" is not a valid number"),
    ({"total_reports_count": "a"}, "\"a\" is not a valid number")
]

# To be used for testing all the scenarios of the function get_token
integration_context = [{}, {'api_token': "dummy_token"}, {'api_token': "dummy_token", 'valid_until': time.time() - 1}]

fetch_incident_params = [
    ({"max_fetch": "201"}, MESSAGES["INVALID_MAX_FETCH"].format("201")),
    ({"max_fetch": "-1"}, MESSAGES["INVALID_MAX_FETCH"].format("-1")),
    ({"first_fetch": "abc"}, '"abc" is not a valid date'),
    ({"max_fetch": "3", "first_fetch": "2 days ago", "match_priority": ['abc']}, "\"abc\" is not a valid number"),
]

check_fetch_incident_configuration_args = [
    ({"filter[location]": "Inbox,Recon", "filter[categorization_tags]": "test"}, {},
     MESSAGES["INVALID_LOCATION_FOR_CATEGORIZATION_TAGS"]),
    ({"filter[location]": "Inbox",
      "filter[categorization_tags]": "test"}, {},
     MESSAGES["INVALID_LOCATION_FOR_CATEGORIZATION_TAGS"]),
    ({"filter[location]": "Processed", "filter[tags]": "test"}, {},
     MESSAGES["INVALID_LOCATION_FOR_TAGS"]),
    ({"filter[location]": "Inbox"}, {"category_id": 2},
     MESSAGES["INVALID_LOCATION_FOR_CATEGORY_ID"]),
]

list_reporter_cmd_arg = [
    ({"reputation_score": "test"}, '"test" is not a valid number'),
    ({"vip": "0"}, MESSAGES["INVALID_BOOLEAN"])
]

list_comment_cmd_arg = [
    ({"body_format": "csv"}, MESSAGES["BODY_FORMAT"])
]

valid_dates = [
    ({"created_at": "2 minutes"}, dateparser.parse("2 minutes").strftime("%Y-%m-%d")),
    ({"created_at": "2 hours"}, dateparser.parse("2 hours").strftime("%Y-%m-%d")),
    ({"created_at": "2 days"}, dateparser.parse("2 days").strftime("%Y-%m-%d")),
    ({"created_at": "2 weeks"}, dateparser.parse("2 weeks").strftime("%Y-%m-%d")),
    ({"created_at": "2 months"}, dateparser.parse("2 months").strftime("%Y-%m-%d")),
    ({"created_at": "2 years"}, dateparser.parse("2 years").strftime("%Y-%m-%d")),
    ({"created_at": "2020-10-21T20:54:23.444Z"}, dateparser.parse('2020-10-21T20:54:23.444Z').strftime("%Y-%m-%d"))
]

update_threat_indicators_cmd_arg = [
    ({}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"id": "1"}, MESSAGES["REQUIRED_ARGUMENT"].format("threat_level")),
    ({"id": "1", "threat_level": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("threat_level"))
]

get_integration_submission_cmd_arg = [
    ({"id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("integration_submission_id")),
    ({"id": "1", "type": "abc"}, MESSAGES["INTEGRATION_SUBMISSION_TYPE"])
]

report_image_download = [
    ({"id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("id")),
    ({"id": "4", "type": "jpeg"}, MESSAGES["INVALID_IMAGE_TYPE"])
]
