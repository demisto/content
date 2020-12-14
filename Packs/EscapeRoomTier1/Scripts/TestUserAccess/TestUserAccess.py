import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

VICTORY_MESSAGE = '''# Congratulations
![](https://media.giphy.com/media/l2Je19AZkPF7r6gXm/giphy.gif)
Oh, password policy. It's one of these annoying buzzwords. We prefer to call it an unrequested security surplus.

You freed my Smithers from the cold chains of the password policy prison.
I shall grant you a present, check the context.

And now Smithers, Release the hounds!
'''


def main(args):
    server = args.get('server_url')
    user_name = args.get('user_name')
    password = '1234'

    try:
        client = demisto_client.configure(base_url=server, username=user_name,
                                          password=password, verify_ssl=False)
        client.generic_request(path='/health', method='GET')

        results = CommandResults(readable_output=VICTORY_MESSAGE, outputs={'MrBurns.Present': 'hello'})
        return_results(results)
    except ApiException as exc:  # pylint: disable=W0703
        return_error(exc.body)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.args())
