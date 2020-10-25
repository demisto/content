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
    "template_id",
    "description",
    "due_date",
    "opened_date"
]

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

GET_COMMANDS_FOR_INCIDENT: Dict[str, str] = {
    'category_id': 'bmc-remedy-category-details-get',
    'client_id': 'bmc-remedy-user-details-get',
    'queue_id': 'bmc-remedy-queue-details-get',
    'staff_id': 'bmc-remedy-user-details-get',
    'status_id': 'bmc-remedy-status-details-get',
    'urgency_id': 'bmc-remedy-urgency-details-get',
    'impact_id': 'bmc-remedy-impact-details-get',
    'account_id': 'bmc-remedy-account-details-get',
    'service_offering_id': 'bmc-remedy-service-offering-details-get',
    'template_id': 'bmc-remedy-template-details-get',
    'broadcast_id': 'bmc-remedy-broadcast-details-get',
    'asset_id': 'bmc-remedy-asset-details-get'
}

ERROR_MESSAGES = 'Could not get the contents from the command result: '


def remove_null_fields_and_convert_additional_fields_in_string_to_create_incident(additional_fields_for_incidents):
    """
    To remove null from additional fields and convert into string.

    :type additional_fields_for_incidents: ''Dict''
    :param additional_fields_for_incidents: additional fields for create service request

    :return: string having all additional fields separted by ';'
    :rtype: ``str``
    """
    additional_fields_for_incidents = remove_empty_elements(additional_fields_for_incidents)
    field_list_for_incident = list()
    for each_field in additional_fields_for_incidents:
        field_list_for_incident.append("{}={}".format(each_field, additional_fields_for_incidents[each_field]))
    return ";".join(field_list_for_incident)


def remove_extra_space_from_args(args):
    """
    Remove leading and trailing spaces from all the arguments and remove empty arguments.

    :param args: Dictionary of arguments

    :return: Dictionary of arguments
    :rtype: ``Dict``
    """
    return {key: value.strip() for (key, value) in args.items() if value and len(value.strip()) > 0}


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
    command_args["additional_fields"] = remove_null_fields_and_convert_additional_fields_in_string_to_create_incident(
        actual_additional_fields)
    return command_args


def show_incident_result(message_type_of_incident, message_of_incident):
    """
    Send message to warroom according to it's type passed in message_type_of_incident parameter.

    :type message_type_of_incident: ``str``
    :param message_type_of_incident: Type of the message like: error, warning etc.

    :type message_of_incident: ``str``
    :param message_of_incident: Message which will be sent to war room.
    """
    if message_type_of_incident == 'error':
        return_error(message_of_incident)
    elif message_type_of_incident == 'warning':
        return_warning(message=message_of_incident, exit=True)
    else:
        return_results(message_of_incident)
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
    message_type = find_entry_type_of_incident(demisto.get(field_results[0], 'Type'))
    if not field_data:
        human_readable_from_get_command = demisto.get(field_results[0], "HumanReadable")
        if human_readable_from_get_command:
            show_incident_result(message_type, human_readable_from_get_command)
        show_incident_result("error", ERROR_MESSAGES + json.dumps(field_results))
    if isinstance(field_data, dict):
        all_fields = demisto.get(field_data, "records")
        if all_fields:
            return demisto.get(all_fields[0], "Id")
    elif isinstance(field_data, list):
        final_field = demisto.get(field_data[0], "Id")
        if final_field:
            return final_field
    else:
        show_incident_result(message_type, field_data)


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


def find_entry_type_of_incident(entry_type_of_incident):
    """
    Find and retuen entry type for context output if entry_type_of_incident will not match to anything then
    return 'note' bydefault.

    :type entry_type_of_incident: ``str``
    :param entry_type_of_incident: Number for entry type.

    :return: Actual key attached with given entry_type_of_incident
    :rtype: ``str``
    """
    for each_type in entryTypes:
        if entry_type_of_incident == entryTypes[each_type]:
            return each_type
    return 'note'


def main():
    """
    PARSE AND VALIDATE SCRIPT ARGUMENTS AND EXECUTE THE COMMAND: 'bmc-remedy-incident-create'.
    """
    args = remove_extra_space_from_args(demisto.args())
    using_argument = args.get("using")
    additional_fields: Dict[str, Any] = {
        'client_id': get_field_id(
            args.get('client_id'),
            args.get('client_user_name'),
            GET_COMMANDS_FOR_INCIDENT["client_id"],
            {"username": args.get('client_user_name')},
            using_argument
        ),
        'category_id': get_field_id(
            args.get('category_id'),
            args.get('category'),
            GET_COMMANDS_FOR_INCIDENT["category_id"],
            {"category_name": args.get('category')},
            using_argument
        ),
        'queue_id': get_field_id(
            args.get('queue_id'),
            args.get('queue'),
            GET_COMMANDS_FOR_INCIDENT["queue_id"],
            {"queue_name": args.get('queue')},
            using_argument
        ),
        'staff_id': get_field_id(
            args.get('staff_id'),
            args.get('staff_user_name'),
            GET_COMMANDS_FOR_INCIDENT["staff_id"],
            {"username": args.get('staff_user_name'), "is_staff": True},
            using_argument
        ),
        'status_id': get_field_id(
            args.get('status_id'),
            args.get('status'),
            GET_COMMANDS_FOR_INCIDENT["status_id"],
            {"status_name": args.get('status')},
            using_argument
        ),
        'urgency_id': get_field_id(
            args.get('urgency_id'),
            args.get('urgency'),
            GET_COMMANDS_FOR_INCIDENT["urgency_id"],
            {"urgency_name": args.get('urgency')},
            using_argument
        ),
        'impact_id': get_field_id(
            args.get("impact_id"),
            args.get("impact"),
            GET_COMMANDS_FOR_INCIDENT["impact_id"],
            {"impact_name": args.get("impact")},
            using_argument
        ),
        'account_id': get_field_id(
            args.get("account_id"),
            args.get("account"),
            GET_COMMANDS_FOR_INCIDENT["account_id"],
            {"account_name": args.get("account")},
            using_argument
        ),
        'service_offering_id': get_field_id(
            args.get("service_offering_id"),
            args.get("service_offering"),
            GET_COMMANDS_FOR_INCIDENT["service_offering_id"],
            {"service_offering_name": args.get("service_offering")},
            using_argument
        ),
        'template_id': get_field_id(
            args.get("template_id"),
            args.get("template"),
            GET_COMMANDS_FOR_INCIDENT["template_id"],
            {"template_name": args.get("template")},
            using_argument
        ),
        'broadcast_id': get_field_id(
            args.get("broadcast_id"),
            args.get("broadcast"),
            GET_COMMANDS_FOR_INCIDENT["broadcast_id"],
            {"broadcast_name": args.get("broadcast")},
            using_argument
        ),
        'asset_id': get_field_id(
            args.get("asset_id"),
            args.get("asset"),
            GET_COMMANDS_FOR_INCIDENT["asset_id"],
            {"asset_name": args.get("asset")},
            using_argument
        ),
        'outage_start': args.get("outage_start"),
        'outage_end': args.get("outage_end"),
        'description': args.get("description"),
        'opened_date': args.get("opened_date"),
        'due_date': args.get("due_date")
    }
    command_args = generate_command_args_with_additional_fields(additional_fields)
    command_args = remove_empty_elements(command_args)
    if using_argument:
        command_args["using"] = using_argument
    command_res = demisto.executeCommand('bmc-remedy-incident-create', command_args)
    result = {}
    try:
        entry = command_res[0]
        context_output_type = find_entry_type_of_incident(demisto.get(entry, "Type"))
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
