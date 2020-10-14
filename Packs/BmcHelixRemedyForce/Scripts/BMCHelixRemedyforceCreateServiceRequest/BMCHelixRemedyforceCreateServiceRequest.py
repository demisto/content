import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

import json
from typing import Dict, Any

DEFAULT_ARGS = [
    "category_id",
    "client_id",
    "queue_id",
    "staff_id",
    "status_id",
    "urgency_id",
    "service_request_definition_id",
    "service_request_definition_params"
]

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

GET_COMMANDS: Dict[str, str] = {
    'category_id': 'bmc-remedy-category-details-get',
    'client_id': 'bmc-remedy-user-details-get',
    'queue_id': 'bmc-remedy-queue-details-get',
    'staff_id': 'bmc-remedy-user-details-get',
    'status_id': 'bmc-remedy-status-details-get',
    'urgency_id': 'bmc-remedy-urgency-details-get',
    'service_request_definition_id': 'bmc-remedy-service-request-definition-get',
    'impact_id': 'bmc-remedy-impact-details-get',
    'account_id': 'bmc-remedy-account-details-get'
}

ERROR_MESSAGES = 'Could not get the contents from the command result: '


def remove_null_fields_and_convert_additional_fields_in_string(additional_fields):
    """
    To remove null from additional fields and convert into string.

    :type additional_fields: ''Dict''
    :param additional_fields: additional fields for create service request

    :return: joint string of additional fields
    :rtype: ``str``
    """

    additional_fields = remove_empty_elements(additional_fields)
    field_list = list()
    for each_field in additional_fields:
        field_list.append("{}={}".format(each_field, additional_fields[each_field]))
    return ";".join(field_list)


def generate_command_args_with_additional_fields(additional_fields):
    """
    Generate dictionary of command arguments with additional fields.

    :type additional_fields: ``Dict``
    :param additional_fields: Additional fields for create service request

    :return: JSON of command arguments.
    :rtype: ``dict``
    """
    command_args: Dict[str, str] = {}
    actual_additional_fields: Dict[str, str] = {}
    for each_field in additional_fields:
        if each_field in DEFAULT_ARGS:
            command_args[each_field] = additional_fields[each_field]
        else:
            actual_additional_fields[each_field] = additional_fields[each_field]
    command_args["additional_fields"] = remove_null_fields_and_convert_additional_fields_in_string(
        actual_additional_fields)
    return command_args


def remove_extra_space_from_args(args):
    """
    Remove leading and trailing spaces from all the arguments and remove empty arguments.

    :param args: Dictionary of arguments

    :return: Dictionary of arguments
    :rtype: ``Dict``
    """
    return {key: value.strip() for (key, value) in args.items() if value and len(value.strip()) > 0}


def get_service_request_definition_id(service_request_definition_id, service_request_definition,
                                      service_request_definition_command, service_request_definition_command_args,
                                      using_argument):
    """
    To get service_request_definition_id from given service_request_definition by executing command
    'bmc-remedy-service-request-definition-get' and
    if service_request_definition_id is passed then it will return that service_request_definition_id.

    :type service_request_definition_id: ``str``
    :param service_request_definition_id: service_request_definition_id

    :type service_request_definition: ``str``
    :param service_request_definition: Service request definition name

    :type service_request_definition_command: ``str``
    :param service_request_definition_command: command name to get service_request_definition_id

    :type service_request_definition_command_args: ``dict``
    :param service_request_definition_command_args: JSON of command arguments

    :type using_argument: ``str``
    :param using_argument: Instance name

    :return: service_request_definition_id
    :rtype: ``str``
    """
    if service_request_definition_id:
        return service_request_definition_id
    elif service_request_definition:
        if using_argument:
            service_request_definition_command_args["using"] = using_argument
        service_request_definition_results = demisto.executeCommand(
            service_request_definition_command, args=service_request_definition_command_args)
        service_request_definition_data = demisto.get(service_request_definition_results[0], 'Contents')
        message_type = find_entry_type(demisto.get(service_request_definition_results[0], 'Type'))
        if not service_request_definition_data:
            human_readable_from_get_service_request_command = demisto.get(
                service_request_definition_results[0], "HumanReadable")
            if human_readable_from_get_service_request_command:
                show_service_request_result(message_type, human_readable_from_get_service_request_command)
            show_service_request_result("error", ERROR_MESSAGES + json.dumps(
                service_request_definition_results))
        if isinstance(service_request_definition_data, dict):
            service_request_definitions = demisto.get(service_request_definition_data, "Result")
            if service_request_definitions:
                return demisto.get(service_request_definitions, "Id")
        else:
            show_service_request_result(message_type, service_request_definition_data)


def show_service_request_result(message_type, message):
    """
    Send message to warroom according to it's type passed in message_type parameter.

    :type message_type: ``str``
    :param message_type: Type of the message like: error, warning etc.

    :type message: ``str``
    :param message: Message which will be sent to war room.
    """
    if message_type == 'error':
        return_error(message)
    elif message_type == 'warning':
        return_warning(message=message, exit=True)
    else:
        return_results(message)
        sys.exit(0)


def process_field_id(command, command_args):
    """
    Execute the command with given command args and process the results.

    :type command: ``str``
    :param command: command name

    :type command_args: ``dict``
    :param command_args: JSON of command arguments

    :return: field_id
    :rtype: ``str``
    """
    field_results = demisto.executeCommand(command, args=command_args)
    field_data = demisto.get(field_results[0], 'Contents')
    message_type = find_entry_type(demisto.get(field_results[0], 'Type'))
    if not field_data:
        human_readable_from_get_command = demisto.get(field_results[0], "HumanReadable")
        if human_readable_from_get_command:
            show_service_request_result(message_type, human_readable_from_get_command)
        show_service_request_result("error", ERROR_MESSAGES + json.dumps(field_results))
    if isinstance(field_data, dict):
        all_fields = demisto.get(field_data, "records")
        if all_fields:
            return demisto.get(all_fields[0], "Id")
    elif isinstance(field_data, list):
        final_field = demisto.get(field_data[0], "Id")
        if final_field:
            return final_field
    else:
        show_service_request_result(message_type, field_data)


def get_field_id(field_id, field, command, command_args, using_argument):
    """
    To get field_id from given field by executing command in mentioned argument and
    if field_id is passed then it will return that field_id.

    :type field_id: ``str``
    :param field_id: field_id

    :type field: ``str``
    :param field: field name

    :type command: ``str``
    :param command: command name

    :type command_args: ``dict``
    :param command_args: JSON of command arguments

    :type using_argument: ``str``
    :param using_argument: Instance name

    :return: field_id
    :rtype: ``str``
    """
    if field_id:
        return field_id
    elif field:
        if using_argument:
            command_args["using"] = using_argument
        return process_field_id(command, command_args)


def find_entry_type(entry_type):
    """
    Find and retuen entry type for context output if entry_type will not match to anything then
    return 'note' bydefault.

    :type entry_type: ``str``
    :param entry_type: Number for entry type.

    :return: Actual key attached with given entry_type
    :rtype: ``str``
    """
    for each_type in entryTypes:
        if entry_type == entryTypes[each_type]:
            return each_type
    return 'note'


def main():
    """
    PARSE AND VALIDATE SCRIPT ARGUMENTS AND EXECUTE THE COMMAND: 'bmc-remedy-service-request-create'.
    """
    args = remove_extra_space_from_args(demisto.args())
    using_argument = args.get("using")
    additional_fields: Dict[str, Any] = {
        'client_id': get_field_id(
            args.get('client_id'),
            args.get('client_user_name'),
            GET_COMMANDS["client_id"],
            {"username": args.get('client_user_name')},
            using_argument
        ),
        'category_id': get_field_id(
            args.get('category_id'),
            args.get('category'),
            GET_COMMANDS["category_id"],
            {"category_name": args.get('category')},
            using_argument
        ),
        'queue_id': get_field_id(
            args.get('queue_id'),
            args.get('queue'),
            GET_COMMANDS["queue_id"],
            {"queue_name": args.get('queue')},
            using_argument
        ),
        'staff_id': get_field_id(
            args.get('staff_id'),
            args.get('staff_user_name'),
            GET_COMMANDS["staff_id"],
            {"username": args.get('staff_user_name'), "is_staff": True},
            using_argument
        ),
        'status_id': get_field_id(
            args.get('status_id'),
            args.get('status'),
            GET_COMMANDS["status_id"],
            {"status_name": args.get('status')},
            using_argument
        ),
        'urgency_id': get_field_id(
            args.get('urgency_id'),
            args.get('urgency'),
            GET_COMMANDS["urgency_id"],
            {"urgency_name": args.get('urgency')},
            using_argument
        ),
        'impact_id': get_field_id(
            args.get("impact_id"),
            args.get("impact"),
            GET_COMMANDS["impact_id"],
            {"impact_name": args.get("impact")},
            using_argument
        ),
        'account_id': get_field_id(
            args.get("account_id"),
            args.get("account"),
            GET_COMMANDS["account_id"],
            {"account_name": args.get("account")},
            using_argument
        ),
        'service_request_definition_id': get_service_request_definition_id(
            args.get("service_request_definition_id"),
            args.get("service_request_definition"),
            GET_COMMANDS["service_request_definition_id"],
            {"service_request_definition_name": args.get("service_request_definition")},
            using_argument
        ),
        'service_request_definition_params': args.get("service_request_definition_params")
    }
    command_args = generate_command_args_with_additional_fields(additional_fields)
    command_args = remove_empty_elements(command_args)
    if using_argument:
        command_args["using"] = using_argument
    command_res = demisto.executeCommand('bmc-remedy-service-request-create', command_args)
    result = {}
    try:
        entry = command_res[0]
        context_output_type = find_entry_type(demisto.get(entry, "Type"))
        context_outputs = demisto.get(entry, "EntryContext")
        human_readable = demisto.get(entry, "HumanReadable")
        contents_format = demisto.get(entry, "ContentsFormat")
        if isError(entry):
            return_error(entry['Contents'])
        else:
            record_data = demisto.get(entry, 'Contents')
            if not record_data:
                return_error(ERROR_MESSAGES + json.dumps(entry))
            else:
                if demisto.get(record_data, "ErrorMessage"):
                    result = record_data['ErrorMessage']
                else:

                    # Output entry
                    result = {
                        'Type': entryTypes[context_output_type],
                        'Contents': record_data,
                        'ContentsFormat': contents_format,
                        'ReadableContentsFormat': formats['markdown'],
                        'HumanReadable': human_readable,
                        'EntryContext': context_outputs
                    }
    except Exception as ex:
        return_error(str(ex))

    demisto.results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
