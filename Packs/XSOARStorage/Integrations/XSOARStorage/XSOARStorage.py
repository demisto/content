import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any, Dict


SIZE_LIMIT = 1024000

MAX_SIZE = int(demisto.params().get('maxsize', SIZE_LIMIT))
MAX_SIZE = MAX_SIZE if MAX_SIZE <= SIZE_LIMIT else SIZE_LIMIT


def xsoar_store_list_command(args: Dict[str, Any]) -> CommandResults:

    namespace = args.get('namespace', 'default')

    data = demisto.getIntegrationContext().get(namespace)

    if not data:
        if namespace == 'default':
            return_error("Namespace: <default> empty!")
        else:
            return_error(f"Namespace: <{namespace}> not found!")

    data = [key for key in demisto.getIntegrationContext().get(namespace, [])]

    number_of_keys = len(data)

    r_data = "\n".join(data)

    return CommandResults(
        readable_output=f"{number_of_keys} key(s) found: \n {r_data}",
        outputs_prefix=f"XSOAR.Store.{namespace}",
        outputs={"keys": data},
        raw_response=data
    )


def xsoar_store_put_command(args: Dict[str, Any]) -> CommandResults:

    namespace = args.get('namespace', 'default')

    key = args.get('key')
    input_data = args.get('data')

    current_data = demisto.getIntegrationContext()

    if (sys.getsizeof(current_data) + sys.getsizeof(input_data)) > MAX_SIZE:

        return_error(f"Store cannot be larger than {MAX_SIZE} bytes")

    if namespace in current_data:
        current_data[namespace][key] = input_data
    else:
        current_data[namespace] = {key: input_data}

    demisto.setIntegrationContext(current_data)

    return CommandResults(
        readable_output=f"put: <{input_data}> in key: <{key}> for namespace: <{namespace}>"
    )


def xsoar_store_get_command(args: Dict[str, Any]) -> CommandResults:

    namespace = args.get('namespace', 'default')

    key = args.get('key')

    data = demisto.getIntegrationContext().get(namespace)

    data = data.get(key)

    return CommandResults(
        readable_output=f"retrieved: <{data}> from key: <{key}> for namespace: <{namespace}>",
        outputs_prefix=f"XSOAR.Store.{namespace}.{key}",
        outputs=data
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.

            return_results('ok')

        elif demisto.command() == 'xsoar-store-list':
            return_results(xsoar_store_list_command(demisto.args()))

        elif demisto.command() == 'xsoar-store-put':
            return_results(xsoar_store_put_command(demisto.args()))

        elif demisto.command() == 'xsoar-store-get':
            return_results(xsoar_store_get_command(demisto.args()))

            # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


"""


Entry Point
-----------

This is the integration code entry point. It checks whether the ``__name__``
variable is ``__main__`` , ``__builtin__`` (for Python 2) or ``builtins`` (for
Python 3) and then calls the ``main()`` function. Just keep this convention.

"""


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
