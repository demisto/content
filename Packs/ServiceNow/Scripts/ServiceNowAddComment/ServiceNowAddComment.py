import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    ticketID = demisto.args().get('ticketID', 'none')
    note = demisto.args().get('note')
    tag = demisto.args().get('tag')
    table_name = demisto.args().get('table_name')
    using = demisto.args().get('using')

    command_args = {}

    if ticketID == 'none':
        ticketID = demisto.incident()['CustomFields'].get('servicenowticketid')

    command_args['id'] = ticketID
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
            return_error(resp['Contents'])
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
            demisto.results({
                "Contents": md,
                "ContentsFormat": formats["markdown"],
                "HumanReadable": md,
                "Type": entryTypes["note"],
                "IgnoreAutoExtract": True
            })

    except Exception as ex:
        return_error(str(ex))


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()

register_module_line('ServiceNowAddComment', 'end', __line__())
