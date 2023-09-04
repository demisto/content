import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# python 3.9 imports
from json import JSONDecodeError
from traceback import format_exc

# accessdata imports
from accessdata.client import Client

# xsoar imports
from CommonServerUserPython import *


def _trigger_workflow(client, **kwargs):
    result = client.connect.trigger(**kwargs)
    if result.get("Status") is not True:
        raise ValueError("Failed to trigger automation workflow.", result.get("Status"))

    return CommandResults(outputs_prefix='Accessdata.Workflow',
                          outputs_key_field='Status',
                          outputs=result)


def _test_module(client):  # pragma: no cover
    # test the client can reach the case list
    try:
        client.cases
    except JSONDecodeError as exc:
        raise RuntimeError('False API key provided to FTK Connect.', exc)
    except DemistoException as exc:
        raise RuntimeError('Authentication with FTK Connect failed.', exc)

    return "ok"


def main():  # pragma: no cover
    # gather parameters
    params = demisto.params()

    # generate client arguments
    protocol = params.get("protocol", "http")
    port = params.get("port", "4443")
    address = params.get("server", "localhost")
    url = f"{protocol}://{address}:{port}/"
    apikey = params.get("apikey", "")
    # check if using ssl
    is_secure = protocol[-1] == 's'

    # build client
    client = Client(url, apikey, validate=not is_secure)
    # if using ssl, gather certs and apply
    if is_secure:
        public_certificate = params.get("public_cert", None)
        client.session.cert = public_certificate

    try:
        # call function with supplied args
        command = demisto.command()
        args = demisto.args()
        if args.get("case_ids") is not None:
            args["case_ids"] = argToList(args.get("case_ids"))
        if args.get("target_ips") is not None:
            args["target_ips"] = argToList(args.get("target_ips"))
        if command == "exterro-ftk-trigger-workflow":
            return_results(_trigger_workflow(client, **args))
        if command == "test-module":
            return_results(_test_module(client))
    except Exception as exception:
        demisto.error(format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(exception)}')


""" Entry Point """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
