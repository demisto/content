"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" STANDALONE FUNCTION """




""" COMMAND FUNCTION """


def run_execute_command(command_name: str, args: dict[str, Any]) -> CommandResults:
    """
    Executes a command and processes its results.
    This function runs a specified command with given arguments, handles any errors,
    and prepares the command results for further processing.
    Args:
        command_name (str): The name of the command to execute.
        args (dict[str, Any]): A dictionary of arguments to pass to the command.
    Returns:

    """
    demisto.debug(f"BEI: Executing command: {command_name}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"The response {res}")
    return CommandResults()


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        ip_list = argToList(args.get("ip_list", []))
        rule_name = args.get("rule_name", "XSIAM - Block IP")
        log_forwarding_name = args.get("rule_name", "")
        address_group = args.get("address_group", "")
        tag = args.get("tag", "")
        custom_block_rule = argToBoolean(args.get("custom_block_rule", False))
        auto_commit = argToBoolean(args.get("auto_commit", True))
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", "Palo Alto Networks - Prisma SASE,Panorama,CheckPointFirewall_v2,FortiGate,"
                                                     "F5Silverline,Cisco ASA,Zscaler"))
        modules = demisto.getModules()
        enabled_brands = {
            module.get("brand")
            for module in modules.values()
            if module.get("state") == "active"
        }

        for brand in brands_to_run:
            if brand in enabled_brands:
                if brand == "Zscaler":
                    args = {
                        'ip': ip_list
                    }
                    command_name = 'zscaler-blacklist-ip'
                    return_results(run_execute_command(command_name, args))

                else:
                    return_error(f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                                 f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                                 f"CheckPointFirewall_v2, FortiGate, F5Silverline, Cisco ASA, Zscaler.")

    except Exception as ex:
        return_error(f"Failed to execute block-external-ip. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
