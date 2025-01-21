import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
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


''' STANDALONE FUNCTION '''


def say_hello(name: str) -> str:
    """
    Returns 'Hello {name}'.

    Args:
        name (str): name to append to the 'Hello' string.

    Returns:
        dict: string containing 'Hello {name}'
    """

    return f'Hello {name}'


''' COMMAND FUNCTION '''


def say_hello_command(args: dict[str, Any]) -> CommandResults:
    """helloworld-say-hello command: Returns Hello {somename}

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['name']`` is used as input name

    Returns:
        CommandResults: CommandResults with output context and human readable string.
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

    return CommandResults(
        readable_output=markdown,
        outputs=outputs,
        outputs_key_field=None
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(say_hello_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute HelloWorldScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
