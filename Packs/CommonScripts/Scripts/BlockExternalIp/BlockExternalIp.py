from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" STANDALONE FUNCTION """


def create_human_readable(response: dict) -> str:
    message = response.get('Contents')
    demisto.debug(f"BEI: {message=}")
    headers = ['Status', 'Result', 'Created rule name', 'Used integration', 'Message']
    if 'Failed' in message:
        d = {
            "Status": "Done",
            "Result": "Failed",
            "Used integration": response.get('Metadata', {}).get('brand'),
            'Message': message
        }
        demisto.debug(f"BEI: in failed {d=}")
        return tableToMarkdown(
            name='Failed to create the new rule',
            t=d,
            headers=headers,
            removeNull=True
        )
    else:
        d = {
            "Status": "Done",
            "Result": "Success",
            "Used integration": response.get('Metadata', {}).get('brand'),
            "Created rule name": ""  # TODO: update here the rule name
        }
        demisto.debug(f"BEI: in success {d=}")
        return tableToMarkdown(
            name='A new rule was created',
            t=d,
            headers=headers,
            removeNull=True
        )


def create_context(response: dict) -> dict:
    message = response.get('Contents')
    source = response.get('Metadata', {}).get('brand')
    if 'Failed' in message:
        return {
            "Message": message,
            "Result": "Failed",
            "Source": source,
            "created_rule_name": "",
            "address_group": ""
        }
    else:
        return {
            "Message": "Rule created",
            "Result": "Success",
            "Source": source,
            "created_rule_name": "",  # TODO check that, the default is "XSIAM - Block IP"
            "address_group": ""  # TODO check that
        }


""" COMMAND FUNCTION """


def run_execute_command(command_name: str, args: dict[str, Any]) -> list[CommandResults]:
    """
    Executes a command and processes its results.
    This function runs a specified command with given arguments, handles any errors,
    and prepares the command results for further processing.
    Args:
        command_name (str): The name of the command to execute.
        args (dict[str, Any]): A dictionary of arguments to pass to the command.
    Returns:

    """
    demisto.debug(f"BEI: Executing command: {command_name} {args=}")
    res = demisto.executeCommand(command_name, args)
    demisto.debug(f"BEI: The response {res}")
    results = []
    for entry in res:
        hr = create_human_readable(entry)  # TODO check what to do if there are more hr from the commands.
        context = create_context(entry)
        demisto.debug(f"BEI: {hr=} {context=}")
        results.append(CommandResults(
            readable_output=hr,
            outputs_prefix="BlockExternalIPResults",
            outputs=context,
            raw_response=context
        ))
    return results


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        ip_list_arg = args.get("ip_list", [])
        ip_list_arr = argToList(ip_list_arg)
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
        demisto.debug(f"BEI: the enabled modules are: {enabled_brands=}")
        demisto.debug(f"BEI: {brands_to_run=}")

        for brand in brands_to_run:
            demisto.debug(f"BEI: the current brand is {brand}")
            if brand in enabled_brands:
                if brand == "Zscaler":
                    args = {
                        'ip': ip_list_arg
                    }
                    command_name = 'zscaler-blacklist-ip'
                    return_results(run_execute_command(command_name, args))
                elif brand == "Cisco ASA":
                    results = []
                    command_name = 'cisco-asa-create-rule'
                    for ip in ip_list_arr:
                        args = {
                            "destination": ip,
                            "interface_type": "Global",
                            "source": "0.0.0.0",
                            "permit": False
                        }
                        result = run_execute_command(command_name, args)
                        results.append(result)
                    demisto.debug(f"BEI: return {results=}")
                    return_results(results)
                elif brand == "F5Silverline":
                    command_name = "f5-silverline-ip-object-add"
                    results = []
                    for ip in ip_list_arr:
                        args = {
                            "list_type": "denylist",
                            "cidr_range": ip,
                            "tags": tag
                        }
                        result = run_execute_command(command_name, args)
                        results.append(result)
                    demisto.debug(f"BEI: return {results=}")
                    return_results(results)
                elif brand == "FortiGate":
                    command_name = "fortigate-ban-ip"
                    args = {
                        "ip_address": ip_list_arg
                    }
                    return_results(run_execute_command(command_name, args))

                else:
                    return_error(f"The brand {brand} isn't a part of the supported integration for 'block-external-ip'. "
                                 f"The supported integrations are: Palo Alto Networks - Prisma SASE, Panorama, "
                                 f"CheckPointFirewall_v2, FortiGate, F5Silverline, Cisco ASA, Zscaler.")
            else:
                demisto.info(f"The brand {brand} isn't enabled.")

    except Exception as ex:
        return_error(f"Failed to execute block-external-ip. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
