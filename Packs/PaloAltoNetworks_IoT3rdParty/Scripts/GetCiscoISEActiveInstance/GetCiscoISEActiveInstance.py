import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Run cisco-ise-get-nodes command on all ISE instances (primary and secondary)
# Primary and Secondary instances should be passed as an argument to the script (Using)
response = demisto.executeCommand("cisco-ise-get-nodes", {})
err_msg = []
active_instance = None


# Go over responses from all configures instances
for resp in response:
    local_instance = resp['ModuleName']
    if isError(resp):
        # Node is probably down or misconfigured. Dont do anything here,
        # just collect the error messages so we can report back to cloud if needed
        err = resp['Contents']
        err_msg.append(err.split('-')[0] + ", instance name = %s" % local_instance)
    else:
        # Check if the output has any node that matches the local instance
        # and is also a primary or is in standalone mode
        for node_data in resp['Contents']['CiscoISE.NodesData']:
            if node_data['isLocalIstance']:
                if node_data['inDeployment'] == False or (node_data['inDeployment'] == True and node_data['primaryPapNode'] == True):
                    active_instance = local_instance


# If no active instances are found that means we dont have any valid ise nodes.
# We can either report to cloud here or better write to the context data
# and do it in the playbook for better visibility
if active_instance == None:
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
