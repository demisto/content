import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any


COMMAND_ARGS_MAPPER = {
    #Command, endpoint_arg_name -> Command_arg_name
}

COMMAND_OUTPUT_MAPPER = {
    # Command, command_output_name -> endpoint_output_name
}


class Command:
    def __init__(self, brand: str, name: str, args: dict) -> None:
        """
        Initialize a Command object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
        """
        self.brand = brand
        self.name = name
        self.args = args


def run_command_if_exists(self, command: Command) -> Dict[str, Any]:
    #  Check if the brand associated with the command is in the list of available brands, if so, run it
    pass


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        agent_ids = argToList(args.get("agent_id", []))
        agent_ips = argToList(args.get("agent_ip", []))
        agent_host_names = argToList(args.get("agent_hostname", []))
        brands_to_run = argToList(args.get("brands", []))
        verbose = argToBoolean(args.get("verbose", False))

    except Exception as e:

        return_error(f'Failed to execute GetEndpointData. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
