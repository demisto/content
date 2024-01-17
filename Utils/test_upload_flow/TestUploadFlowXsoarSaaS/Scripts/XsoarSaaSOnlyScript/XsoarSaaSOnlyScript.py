import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def update_comment_or_worknote(args: Dict[str, Any]) -> CommandResults:
    ticket_id = args.get('ticket_id', 'none')
    note = args.get('note')
    tag = args.get('tag')
    table_name = args.get('table_name')
    using = args.get('instance_name')

    command_args = {}

    if ticket_id == 'none':
        ticket_id = demisto.incident()['CustomFields'].get('servicenowticketid')

    command_args['id'] = ticket_id
    command_args['ticket_type'] = table_name
    if tag == 'comment':
        command_args['comments'] = note
    else:
        command_args['work_notes'] = note
    command_args['using'] = using

    try:
        command_res = demisto.executeCommand("servicenow-update-ticket", command_args)
        resp = command_res[0]
        if isError(resp):
            raise Exception(resp['Contents'])
        else:
            result = resp['Contents']['result']
            output_results = {}

            output_results['Ticket ID'] = result['sys_id']
            output_results['Ticket Updated on'] = result['sys_updated_on']
            output_results['Ticket Updated by'] = result['sys_updated_by']
            output_results['Ticket Number'] = result['number']
            output_results['Table'] = result['sys_class_name']
            output_results['Ticket Created by'] = result['sys_created_by']
            output_results['Ticket Created on'] = result['sys_created_on']

            md = tableToMarkdown("ServiceNow Comment Added", [output_results])

    except Exception as ex1:
        return_error(str(ex1))
    return CommandResults(readable_output=md)


def main():
    try:
        res = update_comment_or_worknote(demisto.args())
        return_results(res)

    except Exception as ex2:
        return_error(f'Failed to execute ServiceNowAddComment. Error: {str(ex2)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
