import json
import traceback
import ansible_runner
import ssh_agent_setup
from typing import Dict, cast

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type =  'local'

# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'k8s-k8s':
            return_results(generic_ansible('kubernetes', 'k8s', demisto.args()))
        elif demisto.command() == 'k8s-info':
            return_results(generic_ansible('kubernetes', 'k8s_info', demisto.args()))
        elif demisto.command() == 'k8s-scale':
            return_results(generic_ansible('kubernetes', 'k8s_scale', demisto.args()))
        elif demisto.command() == 'k8s-service':
            return_results(generic_ansible('kubernetes', 'k8s_service', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()