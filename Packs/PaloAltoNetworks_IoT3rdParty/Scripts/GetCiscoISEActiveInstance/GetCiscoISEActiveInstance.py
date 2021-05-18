import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_cisco_ise_active_instance_or_err_msg():
    """
    Get ise node details for all configured instances and determine
    which on is active/primary. All gather error messages if possible
    for nodes that are not in active state or have connnectivity issues.
    """
    err_msg = []
    active_instance = None
    # run common on all configured Cisco ISE nodes
    response = demisto.executeCommand("cisco-ise-get-nodes", {})
    for resp in response:
        local_instance = resp['ModuleName']
        if isError(resp):
            err = resp['Contents']
            err_msg.append(f'{err.split("-")[0]} , instance name = {local_instance}')
        else:
            # Check if the output has any node that matches the local instance
            # and is also a primary or is in standalone mode
            for node_data in resp['Contents']['CiscoISE.NodesData']:
                if node_data['isLocalIstance']:
                    if node_data['inDeployment'] is False or (
                            node_data['inDeployment'] is True and node_data['primaryPapNode'] is True):
                        active_instance = local_instance

    return active_instance, err_msg


def main():
    try:
        active_instance, err_msg = get_cisco_ise_active_instance_or_err_msg()
    except Exception as ex:
        return_error(str(ex))

    if active_instance is None:
        readable_status = "No Primary/Active Cisco ISE node found = %s" % err_msg
        results = CommandResults(
            readable_output=readable_status,
            outputs_prefix="PaloAltoIoTIntegrationBase.NodeErrorStatus",
            outputs=readable_status
        )
        # Write data to context and display result in war room
        return_results(results)
        # Also return error, so we can detect it in the playbook
        return_error(err_msg)
    else:
        readable_status = "Found active Cisco ISE node = %s" % active_instance
        results = CommandResults(
            readable_output=readable_status,
            outputs_prefix="PaloAltoIoTIntegrationBase.ActiveNodeInstance",
            outputs=active_instance
        )
        return_results(results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
