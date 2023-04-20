# HEADING: --------------- COMMAND FUNCTIONS TESTS ARGUMENTS ---------------


# Test function: test_handle_auth_token_fail
# Arguments: (status_code, args, expected_output)
from VersaDirector import AUTH_EXISTING_TOKEN, AUTH_EXCEEDED_MAXIMUM, AUTH_INVALID_ACCESS_TOKEN, AUTH_BAD_CREDENTIALS

case_500 = (500, {"token_name": "token_name_mock"}, AUTH_EXISTING_TOKEN)
case_400 = (400, {"token_name": "token_name_mock"}, AUTH_EXCEEDED_MAXIMUM)
case_no_args_general_error = (404, {"token_name": "token_name_mock"}, "Auth process failed.")
case_401 = (401, {"client_id": "client_id_mock", "client_secret": "client_secret_mock"}, AUTH_INVALID_ACCESS_TOKEN)
case_with_args_general_error = (404, {"client_id": "client_id_mock", "client_secret": "client_secret_mock"}, AUTH_BAD_CREDENTIALS)
test_handle_auth_token_fail_args = [case_500, case_400, case_no_args_general_error, case_401, case_with_args_general_error]


# Test function: test_template_access_policy_rule_create_command, test_template_access_policy_rule_edit_command
template_access_policy_rule_create_command_custom_rule_json = {
    "access-policy": {
        "name": "test1",
        "description": "",
        "rule-disable": "false",
        "tag": [],
        "match": {
            "source": {
                "zone": {},
                "address": {"address-list": [], "negate": ""},
                "site-name": [],
                "user": {
                    "user-type": "any",
                    "local-database": {"status": "disabled"},
                    "external-database": {"status": "disabled"},
                },
            },
            "destination": {"zone": {}, "address": {"address-list": [], "negate": ""}, "site-name": []},
            "application": {"predefined-application-list": [], "user-defined-application-list": []},
            "url-category": {"user-defined": []},
            "url-reputation": {"predefined": []},
            "ttl": {},
        },
        "set": {
            "lef": {"event": "never", "options": {"send-pcap-data": {"enable": False}}},
            "action": "deny",
            "tcp-session-keepalive": "disabled",
        },
    }
}
template_access_policy_rule_command_custom_rule_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    template_access_policy_rule_create_command_custom_rule_json
)


# Test function: test_appliance_custom_url_category_create_command, test_appliance_custom_url_category_edit_command
appliance_custom_url_category_command_json = {
    "url-category": {
        "category-name": "test",
        "category-description": "description",
        "confidence": 100,
        "urls": {"strings": [], "patterns": []},
    }
}
appliance_custom_url_category_command_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    appliance_custom_url_category_command_json
)

# Test function: test_appliance_access_policy_rule_create_command
appliance_access_policy_rule_json = {
    "access-policy": {
        "name": "test_rule",
        "description": "",
        "rule-disable": "false",
        "tag": [],
        "match": {
            "source": {
                "zone": {},
                "address": {"address-list": [], "negate": ""},
                "site-name": [],
                "user": {
                    "user-type": "any",
                    "local-database": {"status": "disabled"},
                    "external-database": {"status": "disabled"},
                },
            },
            "destination": {"zone": {}, "address": {"address-list": [], "negate": ""}, "site-name": []},
            "application": {"predefined-application-list": [], "user-defined-application-list": []},
            "url-category": {"user-defined": []},
            "url-reputation": {"predefined": []},
            "ttl": {},
        },
        "set": {
            "lef": {"event": "never", "options": {"send-pcap-data": {"enable": False}}},
            "action": "deny",
            "tcp-session-keepalive": "disabled",
        },
    }
}
appliance_access_policy_rule_command_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    appliance_access_policy_rule_json
)


# Test function: test_template_sdwan_policy_rule_create_command, test_template_sdwan_policy_rule_edit_command
template_sdwan_policy_rule_json = {
    "rule": {
        "name": "rule_name",
        "description": "",
        "tag": [],
        "rule-disable": "false",
        "match": {
            "source": {
                "zone": {},
                "address": {"address-list": []},
                "user": {
                    "user-type": "any",
                    "local-database": {"status": "disabled"},
                    "external-database": {"status": "disabled"},
                },
            },
            "destination": {"zone": {}, "address": {"address-list": []}},
            "application": {"predefined-application-list": [], "user-defined-application-list": []},
            "url-category": {"user-defined": []},
            "url-reputation": {"predefined": []},
            "ttl": {},
        },
        "set": {"lef": {"event": "never", "profile-default": "true", "rate-limit": "10"}, "action": "", "tcp-optimization": {}},
        "monitor": {},
    }
}
template_sdwan_policy_rule_command_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    template_sdwan_policy_rule_json
)


# Test function: test_appliance_sdwan_policy_rule_create_command, test_appliance_sdwan_policy_rule_edit_command
appliance_sdwan_policy_rule_json = {
    "rule": {
        "name": "rule_name",
        "description": "",
        "tag": [],
        "rule-disable": "false",
        "match": {
            "source": {
                "zone": {},
                "address": {"address-list": "[]"},
                "user": {
                    "user-type": "any",
                    "local-database": {"status": "disabled"},
                    "external-database": {"status": "disabled"},
                },
            },
            "destination": {"zone": {}, "address": {"address-list": "[]"}},
            "application": {
                "predefined-application-list": "[]",
                "user-defined-application-list": "[]",
            },
            "url-category": {"user-defined": "[]"},
            "url-reputation": {"predefined": "[]"},
            "ttl": {},
        },
        "set": {
            "lef": {"event": "never", "profile-default": "true", "rate-limit": 10},
            "action": "",
            "tcp-optimization": {},
            "forwarding-profile": "",
            "nexthop-address": "",
            "routing-instance": "",
        },
        "monitor": {},
    }
}
appliance_sdwan_policy_rule_command_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    appliance_sdwan_policy_rule_json
)


# Test function: template_address_object_create_command, template_address_object_edit_command
template_address_object_json = {
    "address": {
        "name": "object_name",
        "description": "",
        "tag": [],
        "address_object_type": "object_value",
    }
}
template_address_object_command_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    template_address_object_json
)


# Test function: appliance_address_object_create_command, appliance_address_object_edit_command
appliance_address_object_json = {
    "address": {
        "name": "object_name",
        "description": "",
        "tag": [],
        "address_object_type": "object_value",
    }
}
appliance_address_object_command_readable_output = "Command run successfully.\nRequest Body:\n\n" + str(
    appliance_address_object_json
)


# HEADING: --------------- HELPER FUNCTIONS TESTS ARGUMENTS ---------------


# Test function: test_set_organization
# Arguments: (organization_form_args,organization_form_params, expected_output)
case_organization_form_args = ("args", None, "args")
case_organization_form_params = (None, "params", "params")
case_organization_form_both = ("args", "params", "args")
set_organization_args = [
    case_organization_form_args,
    case_organization_form_params,
    case_organization_form_both,
]


# Test function: test_set_offset, test_set_offset_fail
# Arguments: (page, page_size, expected_output)
case_page_none_and_page_size_zero = (None, 0, 0)
case_page_none_and_page_size_value = (None, 1, 1)
case_page_none_and_page_size_none = (None, None, None)
case_page_value_and_page_size_value = (2, 2, 4)

case_page_value_and_page_size_none = (1, None)
case_page_negative_and_page_size_positive = (-1, 1)
case_page_positive_and_page_size_negative = (1, -1)
case_page_negative_and_page_size_negative = (-1, -1)

set_offset_args = [
    case_page_none_and_page_size_zero,
    case_page_none_and_page_size_value,
    case_page_none_and_page_size_none,
    case_page_value_and_page_size_value,
]

set_offset_args_fail = [
    case_page_value_and_page_size_none,
    case_page_negative_and_page_size_positive,
    case_page_positive_and_page_size_negative,
    case_page_negative_and_page_size_negative,
]

# Test function: test_create_client_header
# Arguments: (use_token, username, password, client_id, client_secret, access_token, (auth, headers))
case_basic_auth = (
    "use_basic_auth",
    "username",
    "password",
    "",
    "",
    "",
    (("username", "password"), {"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="}),
)
case_auth_token_only = (
    "",
    "",
    "",
    "",
    "",
    "access_token",
    (None, {"Authorization": "Bearer access_token"}),
)
case_context_args_already_created = (
    "",
    "",
    "",
    "client_id",
    "client_secret",
    "access_token",
    (None, {"Authorization": "Bearer access_token"}),
)
create_client_header_args = [case_basic_auth, case_auth_token_only, case_context_args_already_created]
