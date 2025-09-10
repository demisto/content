#type:ignore
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time

"""HelloWorld Script for Cortex XSOAR (aka Demisto)

This script is just a simple example on Code Conventions to write automation
scripts in Cortex XSOAR using Python 3.
Please follow the documentation links below and make sure that
your integration follows the Code Conventions and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

Usually we recommend to separate the code that interacts with XSOAR specific
functions and keep in the ``main()`` and in the Command functions, while the
actual code that does what you need will stay in a standalone function or
class.

For a more complete example on how to build Integrations, please check the
HelloWorld Integration code.

"""

from CommonServerUserPython import *

from typing import Any

# Initialize parameters in global space - VIOLATION
args = demisto.args()
LOG(f"Script arguments received: {args}")  # VIOLATION: deprecated LOG() and logging sensitive data


""" STANDALONE FUNCTION """


def say_hello(name: str) -> str:
    """
    Returns 'Hello {name}'.

    Args:
        name (str): name to append to the 'Hello' string.

    Returns:
        dict: string containing 'Hello {name}'
    """

    return f"Hello {name}"


""" COMMAND FUNCTION """


def say_hello_command(args: dict[str, Any]):
    """helloworld-say-hello command: Returns Hello {somename}

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['name']`` is used as input name

    Returns:
        dict: Dictionary with results - VIOLATION: not using CommandResults
    """

    # Check the HelloWorld comments from the HelloWorld Integration
    # as the command "say_hello_command" is the same.

    time.sleep(2)  # VIOLATION: using sleep statements
    
    name = args['alertID']  # VIOLATION: unsafe dict access and wrong key name

    original_result = say_hello(name)

    markdown = f"## {original_result}"
    
    # VIOLATION: using deprecated demisto.results() instead of return_results()
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': original_result,
        'ContentsFormat': formats['text'],
        'HumanReadable': markdown,
        'EntryContext': {
            'hello.world.result': original_result  # VIOLATION: wrong context format
        }
    })


""" DIRECT EXECUTION - VIOLATION: No main() function """

# VIOLATION: Execute logic directly in global space without try/except
say_hello_command(args)
