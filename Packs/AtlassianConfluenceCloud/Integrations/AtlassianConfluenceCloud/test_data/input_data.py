MESSAGES = {
    "REQUIRED-URL-FIELD": "Site Name can not be empty.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "LIMIT": "{} is an invalid value for limit. Limit must be between 0 and int32.",
    "START": "{} is an invalid value for start. Start must be between 0 and int32.",
    "INVALID_ACCESS_TYPE": "Invalid value for access type. Access type parameter must be one of 'user', 'admin', "
                           "or 'site-admin' ",
    "HR_DELETE_CONTENT": "Content with Id {} is deleted successfully.",
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "INVALID_STATUS": "Invalid value for status. Status must be one of 'current', 'draft' or 'trashed'.",
    "INVALID_CONTENT_TYPE": "Invalid value for content type. Content type parameter can be 'page' or 'blogpost' ",
    "BAD_REQUEST": "Bad request: An error occurred while fetching the data.",
    "REQUIRED_SORT_KEY": "If 'sort_order' is specified, 'sort_key' is required.",
    "INVALID_DATE": '"dummy" is not a valid date',
    "INVALID_STATUS_SEARCH": "Invalid value for status. Status must be one of 'current', 'any', 'archived', 'draft' "
                             "or 'trashed'.",
    "INVALID_PERMISSION": "If the 'permission_account_id' or 'permission_group_name' arguments are given, "
                          "the 'permission_operations' argument must also be given.",
    "PERMISSION_FORMAT": "Please provide the permission in the valid JSON format. "
                         "Format accepted - 'operation1:targetType1,operation2:targetType2'",
    "ADVANCE_PERMISSION_FORMAT": "Please provide the 'advanced_permissions' in the valid JSON format. ",
    "INVALID_SPACE_STATUS": "Invalid value for status. Status must be one of 'current' or 'archived'.",
    "INVALID_CONTENT_TYPE_UPDATE_CONTENT": "Invalid value for content type. Content type parameter can be 'page', "
                                           "'blogpost', 'comment' or 'attachment'.",
    "INVALID_BODY_REPRESENTATION": "Invalid value for body_representation. Body representation must be one of "
                                   "'editor', 'editor2' or 'storage'.",
    "INVALID_DELETION_TYPE": "Invalid value for deletion_type. Deletion type must be one of 'move to trash', "
                             "'permanent delete' or 'permanent delete draft'.",
    "INVALID_TITLE_LENGTH": "Title cannot be longer than 255 characters.",
    "INVALID_SPACE_NAME_LENGTH": "Space name cannot be longer than 200 characters.",
    "INVALID_SPACE_KEY": "Space Key cannot be longer than 255 characters and should contain alphanumeric characters "
                         "only.",
    "PRIVATE_SPACE_PERMISSION": "Permission can not be granted for a private space."
}

exception_handler_params = [
    (401, "An error occurred while validating the credentials, please check the username or password."),
    (404, "The resource cannot be found."),
    (500, "The server encountered an internal error for Atlassian Confluence Cloud "
          "and was unable to complete your request."),
    (507, "The server encountered an internal error for Atlassian Confluence Cloud "
          "and was unable to complete your request.")
]

exception_handler_forbidden_response = {
    (403, "Current user not permitted to use Confluence"),
}

list_group_invalid_args = [
    ({"limit": -1}, MESSAGES["LIMIT"].format(-1)),
    ({"limit": 2147483648}, MESSAGES["LIMIT"].format(2147483648)),
    ({"offset": -1}, MESSAGES["START"].format(-1)),
    ({"offset": 2147483648}, MESSAGES["START"].format(2147483648)),
    ({"access_type": "abc"}, MESSAGES["INVALID_ACCESS_TYPE"])
]

content_create_invalid_args = [
    ({"title": "abc", "space_key": "demo", "type": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("type")),
    ({"title": "abc", "space_key": "demo", "type": "abc"}, MESSAGES["INVALID_CONTENT_TYPE"]),
    ({"title": "", "space_key": "demo", "type": "abc"}, MESSAGES['REQUIRED_ARGUMENT'].format("title")),
    ({"title": "abc", "space_key": "", "type": "page"}, MESSAGES['REQUIRED_ARGUMENT'].format("space_key")),
    ({"title": "pnifgQopYghcLjxjpEUXKexOtu6x74FI9u2tKD5vkt8qDEd1YcgS1YVgTIo6iT9j4K38hdxO5lQFJHezqiJ3"
               "pozCuVBeEXQofIgGzwGE2mrew7yVLU5B1mlazmTkt1sxjF75iPUOtpIVI8fOaNm6LDmxrQ2Y1V8m9kITohRxt"
               "BdhUHGeciHBvIvG6XOl0GSID5yUE0Lc1EkDxNW778jLO62ngtuWhDR2E5jernuPeCqYbvr8JEEjoOGKWKdflRwk",
      "space_key": "demo", "type": "page"}, MESSAGES["INVALID_TITLE_LENGTH"])
]

delete_content_invalid_args = [
    ({"content_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("content_id")),
    ({"content_id": "123", "deletion_type": "dummy"}, MESSAGES["INVALID_DELETION_TYPE"])
]

comment_create_invalid_args = [
    ({"body_value": "", "body_representation": "storage", "container_id": "1234"},
     MESSAGES["REQUIRED_ARGUMENT"].format("Comment body_value")),
    ({"body_value": "hello", "body_representation": "", "container_id": "1234"},
     MESSAGES["REQUIRED_ARGUMENT"].format("body_representation")),
    ({"body_value": "hello", "body_representation": "storage", "container_id": ""},
     MESSAGES["REQUIRED_ARGUMENT"].format("container_id")),
    ({"body_value": "hello", "body_representation": "abc", "container_id": "1234"},
     MESSAGES["INVALID_BODY_REPRESENTATION"])
]

list_user_invalid_args = [
    ({"limit": -1}, MESSAGES["LIMIT"].format(-1)),
    ({"limit": 2147483648}, MESSAGES["LIMIT"].format(2147483648)),
    ({"offset": -1}, MESSAGES["START"].format(-1)),
    ({"offset": 2147483648}, MESSAGES["START"].format(2147483648)),
]

content_search_invalid_args = [
    ({"query": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("query")),
    ({"query": "type=page", "limit": -1}, MESSAGES['LIMIT'].format(-1)),
    ({"query": "type=page", "limit": 2147483648}, MESSAGES['LIMIT'].format(2147483648))
]

content_search_invalid_arg_value = [
    ({"query": "type=dummy"}, MESSAGES['BAD_REQUEST']),
    ({"query": "type=page", "cursor": "abcdefg"}, MESSAGES['BAD_REQUEST'])
]

create_space_invalid_args = [
    ({"unique_key": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("unique_key")),
    ({"unique_key": "unique", "name": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("name")),
    ({"unique_key": "unique", "name": "space_name", "is_private_space": "abc"},
     "Argument does not contain a valid boolean-like value"),
    ({"unique_key": "unique", "name": "space_name", "advanced_permissions": "{\"subjects\"=\"user\"}"},
     MESSAGES["ADVANCE_PERMISSION_FORMAT"]),
    ({"unique_key": "!@#$", "name": "space_name", "advanced_permissions": "{\"subjects\":\"user\"}"},
     MESSAGES["INVALID_SPACE_KEY"]),
    ({"unique_key": "Acxeqrs5j038A3Yb0TSZ0NRnoYd4DfxxzEfFZPvtyJnmEEgzVYlxq1fFYVkxvvwaUXmE8De4zLbkSZkv8"
                    "7CmGTzaFRaTvf5EFlrgb4FRNGzBZ2K3wL0ZPAHeNadopRAonCcEV516DmE5ZeUdkONG1EFWFIDBfmshb1Z2"
                    "sjBVLggTnSVmZRVHl7me9jThnv3PGmbynozhL9bUnGh1UxD4nzEiv13dO55YtbYYXhHw7Kuw8eJ3s2xjj"
                    "102mq3RpE0w",
      "name": "space_name", "advanced_permissions": "{\"subjects\":\"user\"}"},
     MESSAGES["INVALID_SPACE_KEY"]),
    ({"unique_key": "unique", "name": "gKcpqsOfX80ySDWwDXwU1WtcxPurxpvo2IQGXoJFpYsaoreivzjKRqOQ"
                                      "JjPnesXmGyF9WdMCPjEOEJokgOaGh2wSd5MRv0i3YPe3ZLMGqM8lmX8KeuTs"
                                      "ghnr8AvzANcqWC4tettmyPmQBrAm8zADfZ9kkQrpQQUO0Sd4xQ8ycfYQW2Xf77AO"
                                      "2nOB5UBeHHACSXEJiv0H1"},
     MESSAGES["INVALID_SPACE_NAME_LENGTH"]),
    ({"unique_key": "unique", "name": "space_name", "is_private_space": True,
      "advanced_permissions": "{\"subjects\":\"user\"}"},
     MESSAGES["PRIVATE_SPACE_PERMISSION"]),

]

create_space_invalid_permission = [
    ({"permission_account_id": "123", "permission_group_name": "abc", "permission_operations": ""},
     MESSAGES["INVALID_PERMISSION"]),
    ({"permission_account_id": "123", "permission_group_name": "abc",
      "permission_operations": "create:page, :space, read:,   ,"},
     MESSAGES["PERMISSION_FORMAT"]),

]

list_space_invalid_args = [
    ({"limit": -1}, MESSAGES["LIMIT"].format(-1)),
    ({"limit": 2147483648}, MESSAGES["LIMIT"].format(2147483648)),
    ({"offset": -1}, MESSAGES["START"].format(-1)),
    ({"offset": 2147483648}, MESSAGES["START"].format(2147483648)),
    ({"status": "abc"}, MESSAGES["INVALID_SPACE_STATUS"])
]

content_list_invalid_arg_value = [
    ({"limit": -1}, MESSAGES["LIMIT"].format(-1)),
    ({"limit": 2147483648}, MESSAGES["LIMIT"].format(2147483648)),
    ({"offset": -1}, MESSAGES["START"].format(-1)),
    ({"offset": 2147483648}, MESSAGES["START"].format(2147483648)),
    ({"type": "dummy"}, MESSAGES['INVALID_CONTENT_TYPE']),
    ({"sort_order": "asc"}, MESSAGES['REQUIRED_SORT_KEY']),
    ({"creation_date": "dummy"}, MESSAGES['INVALID_DATE']),
    ({"status": "dummy"}, MESSAGES['INVALID_STATUS_SEARCH'])
]

content_update_invalid_arg_value = [
    ({"content_id": "2097159", "title": "", "type": "page", "version": 2},
     MESSAGES['REQUIRED_ARGUMENT'].format("title")),
    ({"content_id": "2097159", "title": "dummy", "type": "", "version": 2},
     MESSAGES['REQUIRED_ARGUMENT'].format("type")),
    ({"content_id": "2097159", "title": "dummy", "type": "dummy", "version": 2},
     MESSAGES['INVALID_CONTENT_TYPE_UPDATE_CONTENT']),
    ({"content_id": "2097159", "title": "dummy", "type": "comment", "version": 2, "body_value": "Testing",
      "body_representation": "dummy"}, MESSAGES['INVALID_BODY_REPRESENTATION']),
    ({"content_id": "2097159", "title": "dummy", "type": "comment", "version": 2},
     MESSAGES['REQUIRED_ARGUMENT'].format("'body_value' and 'body_representation'")),
    ({"content_id": "", "title": "dummy", "type": "page", "version": 2},
     MESSAGES['REQUIRED_ARGUMENT'].format("content_id")),
    ({"content_id": "2097159", "title": "dummy", "type": "page", "version": ""},
     MESSAGES['REQUIRED_ARGUMENT'].format("version"))
]
