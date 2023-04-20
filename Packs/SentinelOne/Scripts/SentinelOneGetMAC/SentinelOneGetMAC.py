import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_agent_details(args):
    mac_list = []
    res = demisto.executeCommand('sentinelone-get-agent', {'agent_id': args.get('agentId')})

    if not is_error(res):
        content = res[0].get('Contents')
        for result in content:
            hostname = result.get('computerName')
            for interface in result.get('networkInterfaces'):
                int_dict = {}
                int_dict['hostname'] = hostname
                int_dict['int_name'] = interface.get('name')
                int_dict['agentId'] = args.get('agentId')
                int_dict['ip'] = interface.get('inet')
                int_dict['mac'] = interface.get('physical')

                mac_list.append(int_dict)

        return CommandResults(
            outputs_prefix='SentinelOne.MAC',
            outputs=mac_list,
            readable_output=tableToMarkdown('SentinelOne MAC Address Results', mac_list),
            raw_response=res
        )

    else:
        return_error('Could not retrieve SentinelOne MAC Addresses for AgentID. {0}'.format(args.get('agentId')))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(get_agent_details(demisto.args()))


register_module_line('SentinelOne-Get-MAC', 'start', __line__())
