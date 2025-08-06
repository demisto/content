from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

def list_agents(args: Dict[str, Any]) -> CommandResults:
    ip = args.get("ip")
    params= f"networkInterfaceInetcontains={ip}" if ip else {}
    command_args = {
        assign_params(
            params=params,
            computer_name=args.get("hostname"),
            active_threats=args.get("min_active_threats"),
            scan_status=args.get("scan_status"),
            osTypes=args.get("os_type"),
            created_at=args.get("created_at"),
            limit=args.get("limit")
        )
    }
    try:
        demisto.debug(f"Calling sentinelone-list-agents, {command_args=}")
        command_res = demisto.executeCommand("sentinelone-list-agents", command_args)
        demisto.debug(f"After calling sentinelone-list-agentst, {command_res=}")
        if ip:
            res_ips = command_res.get("outputs", {}).get("ExternalIP")
            if ip not in [str(x) for x in res_ips]:
                demisto.debug(f"No agents found with IP {ip}, {res_ips=}")
                return CommandResults(
                    readable_output=f"No agents found with IP {ip}",
                    outputs_prefix="SentinelOneListAgents",
                    outputs=[]
                )
        
    except Exception as ex1:
        demisto.info(f"Failed to get list of the agents. {type(ex1)}: {ex1}, Trace:\n{traceback.format_exc()}")
        return_error(str(ex1))
        
    return command_res


def main():
    try:
        res = list_agents(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f"Failed to execute SentinelOneListAgents. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
