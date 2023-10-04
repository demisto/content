import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback


''' STANDALONE FUNCTION '''


def panorama_search_policy_command(args: Dict[str, Any]) -> list:
    """Takes rule_name and returns output of !pan-os-list-rules or null message.

    Args:
        args (Dict[str, Any]): Demisto.args() object.

    Returns:
        List: Return from !pan-os-list-rules or message.
    """
    rule_name = args.get('rule_name', None)

    if not rule_name:
        raise ValueError('rule_name not specified')

    # Find all device groups + shared.
    device_groups = []
    # Need a for loop in case multiple integrations are configured.
    dg_res = demisto.executeCommand("pan-os-platform-get-device-groups", {})
    for instance in dg_res:
        if instance.get('Contents') and not isError(instance):
            for dev in instance['Contents']:
                device_groups.append(dev['name'])

    # Error if no device groups found.
    if len(device_groups) == 0:
        raise ValueError('Unable to pull device groups')

    # Add "shared" device group
    device_groups.append('shared')

    # Search for rules
    pre_post = ['pre-rulebase', 'post-rulebase']
    for dg in device_groups:
        for entry in pre_post:
            response = demisto.executeCommand('pan-os-list-rules', {'device-group': dg, 'pre_post': entry, 'rulename': rule_name})
            # Need a for loop in case multiple integrations are configured.
            for res in response:
                if not isError(res):
                    return res
    return ["No matching rule found."]


''' MAIN FUNCTION '''


def main():
    try:
        return_results(panorama_search_policy_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute PanoramaSearchPolicy. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
