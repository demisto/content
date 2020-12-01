import demistomock as demisto
from CommonServerPython import *

import adal
import urllib3.util
urllib3.disable_warnings()


def get_refresh_token(tenant_id: str, authentication: dict, client_id: str, proxy: bool) -> CommandResults:
    user_name = authentication.get('identifier', '')
    password = authentication.get('password', '')
    proxies = {}
    if proxy:
        proxies = handle_proxy()
    authority_uri = f"https://login.microsoftonline.com/{tenant_id}"
    resource_uri = 'https://management.core.windows.net/'
    context = adal.AuthenticationContext(authority_uri, api_version=None, verify_ssl=False, proxies=proxies)
    code = context.acquire_token_with_username_password(resource_uri, user_name, password, client_id)

    return CommandResults(outputs_prefix='MicrosoftLoginHelper',
                          outputs_key_field=' _clientId',
                          outputs=code,
                          readable_output="Refresh token added to context.")


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        if demisto.command() == 'ms-login-helper-get-refresh-token':
            return_results(get_refresh_token(**params, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
# TODO: see if we need to create a new docker
