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

# python 3.9 imports
from functools import wraps
from json import dumps, loads, JSONDecodeError
from traceback import format_exc

# accessdata imports
from accessdata.client import Client

# xsoar imports
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

""" decorator wrapping demisto commands """

_run_functions = {}


def wrap_demisto_command(command):
    def _func(func):
        @wraps(func)
        def _inside(*args, **kwargs):
            return func(*args, **kwargs)

        _run_functions[command] = func
        return _inside

    return _func


""" register demisto commands """

@wrap_demisto_command("exterro-ftk-trigger-workflow")
def _trigger_workflow(client, **kwargs):
    result = client.connect.trigger(**kwargs)
    if result["Status"]!=True:
        raise ValueError("Failed to trigger automation workflow.",result["Status"])

    return CommandResults(outputs_prefix='ExterroFTK.Workflow',
            outputs_key_field='Status',
            outputs=result)

@wrap_demisto_command("test-module")
def _test_module(client):
    # test the client can reach the case list
    try:
        client.cases
    except JSONDecodeError as exc:
        raise RuntimeError('False API key provided to FTK Connect.')
    except DemistoException as exc:
        raise RuntimeError('Authentication with FTK Connect failed.')

    return "ok"


""" define entry """  #


def main():
    # gather parameters
    params = demisto.params()

    # generate client arguments
    protocol = params.get("PROTOCOL", "http")
    port = params.get("PORT", "4443")
    address = params.get("SERVER", "localhost")
    url = f"{protocol}://{address}:{port}/"
    apikey = params.get("APIKEY", "")
    # check if using ssl
    is_secure = protocol[-1] == 's'

    # build client
    client = Client(url, apikey, validate=not is_secure)
    # if using ssl, gather certs and apply
    if is_secure:
        public_certificate = params.get("PUBLIC_CERT", None)
        client.session.cert = public_certificate

    try:
        # call function with supplied args
        command = demisto.command()
        func = _run_functions[command]
        args = demisto.args()

        # return value from called function
        return_values = func(client, **args)
        return_results(return_values)
    except Exception as exception:
        demisto.error(format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(exception)}')


""" Entry Point """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()