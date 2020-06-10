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

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any, Tuple
import traceback


''' STANDALONE FUNCTION '''


def say_hello(name: str) -> str:
    """Returns 'Hello {name}'

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: string containing 'Hello {name}'
    :rtype: ``str``
    """

    return f'Hello {name}'


''' COMMAND FUNCTION '''


def say_hello_command(args: Dict[str, Any]) -> Tuple[str, dict, str]:
    """helloworld-say-hello command: Returns Hello {somename}

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['name']`` is used as input name

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``str``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, str]``
    """

    # Check the HelloWorld comments from the HelloWorld Integration
    # as the command "say_hello_command" is the same.

    name = args.get('name', None)

    original_result = say_hello(name)

    markdown = f'## {original_result}'
    outputs = {
        'HelloWorld': {
            'hello': original_result
        }
    }

    return (
        markdown,
        outputs,
        original_result
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_outputs(*say_hello_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute HelloWorldScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
