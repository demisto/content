from typing import Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def filter_by_agent_ip(ip: str, entry_outputs) -> CommandResults:
    """
    Filter agents by IP address and return CommandResults.
    Args:
        ip (str): agent_ip arg to filter agents.
        entry_outputs (list): list of agents from SentinelOne API response.

    Returns:
        CommandResults: A CommandResults object with filtered agents or an empty list.
    """
    matching_agents = []

    def check_agent_ip(agent):
        agent_external_ip = agent.get("externalIp")
        demisto.debug(f"{agent_external_ip=}")
        return agent_external_ip and str(agent_external_ip) == ip

    # Handle case when command_res is a list
    if isinstance(entry_outputs, list):
        for agent in entry_outputs:
            if check_agent_ip(agent):
                matching_agents.append(agent)

    # Handle case when command_res is a dict (original logic)
    else:
        if check_agent_ip(entry_outputs):
            matching_agents.append(entry_outputs)

    if not matching_agents:
        demisto.debug(f"No agents found with IP {ip} in list response")
        return CommandResults(readable_output=f"No agents found with IP {ip}")

    # Return the matching agents
    return CommandResults(
        readable_output=tableToMarkdown(
            "Sentinel One - List of Agents",
            matching_agents,
            headerTransform=pascalToSpace,
            removeNull=True,
            metadata="Provides summary information and details for all the agents that matched your search criteria",
        ),
        outputs_prefix="SentinelOne.Agents",
        outputs_key_field="id",
        outputs=matching_agents,
        raw_response=matching_agents,
    )


def list_agents(args: dict[str, Any]) -> CommandResults | None:
    """
    Executes sentinelone-list-agents command and filters results by agent_ip if given.
    Args:
        args (Dict[str, Any]): Dictionary containing arguments for filtering and listing agents.

    Raises:
        DemistoException: If there's an error in executing the command or processing results.

    Returns:
        CommandResults | None: Results of listing agents.
    """
    ip = args.get("agent_ip")
    params = f"externalIp__contains={ip}" if ip else {}
    command_args = assign_params(
        params=params,
        computer_name=args.get("hostname"),
        active_threats=args.get("min_active_threats"),
        scan_status=args.get("scan_status"),
        osTypes=args.get("os_type"),
        created_at=args.get("created_at"),
        limit=args.get("limit"),
    )
    demisto.debug(f"Calling sentinelone-list-agents, {command_args=}")
    command_res = execute_command("sentinelone-list-agents", command_args)
    demisto.debug(f"After calling sentinelone-list-agents, {command_res=}")
    if not command_res:
        return CommandResults(readable_output="No agents found.")

    if ip:
        return filter_by_agent_ip(ip, command_res)

    return CommandResults(
        readable_output=tableToMarkdown(
            "Sentinel One - List of Agents",
            command_res,
            headerTransform=pascalToSpace,
            removeNull=True,
            metadata="Provides summary information and details for all the agents that matched your search criteria",
        ),
        outputs_prefix="SentinelOne.Agents",
        outputs_key_field="ID",
        outputs=command_res,
        raw_response=command_res,
    )


def main():
    try:
        res = list_agents(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f"Failed to execute SentinelOneListAgents. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
