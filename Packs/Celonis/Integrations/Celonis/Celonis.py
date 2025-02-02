"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = 'Celonis'
PRODUCT = 'Celonis'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

""" CLIENT CLASS """


class Client(BaseClient):
    pass


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    return "ok"


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    pass


def get_events(client: Client, args: dict) -> tuple[list, CommandResults]:
    pass


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    verify_certificate = not argToBoolean(params("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        headers = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )
        if command == "test-module":
            result = test_module(client)
            return result
        elif command == "fetch-events":
            pass
        elif command == "celonis-get-events":
            pass
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
