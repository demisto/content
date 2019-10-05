import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# The command demisto.command() holds the command sent from the user.
from cloakensdk.client import SyncClient
from cloakensdk.resources import Url

PROXY = handle_proxy("proxy", False)


def get_client():
    server = demisto.params()["server_url"]
    verify = not demisto.params().get('insecure', False)
    password = demisto.params()["credentials"]["password"]
    username = demisto.params()["credentials"]["identifier"]
    client = SyncClient(
        server_url=server,
        username=username,
        verify=verify,
        password=password
    )
    return client


if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    client = get_client()
    demisto.results('ok')

if demisto.command() == 'cloaken-unshorten-url':
    client = get_client()
    url = demisto.args()['url']
    resource = Url(client)
    resource.unshorten(url)
    response = resource.full_request()

    response_code = response.get('response_code', 'NA')
    response_status = response.get('status', 'FAILED')
    if response_status == 'Success':
        # successfully unshortened the url
        url_data = response.get('data', {}).get('unshortened_url')
        cloaken_context = {
            'OriginalURL': url,
            'UnshortenedURL': url_data,
            'Status': response_code
        }
        ec = {
            outputPaths['url']: {
                'Data': url_data
            },
            'Cloaken': cloaken_context
        }
        return_outputs(
            tableToMarkdown('Cloakened URL', cloaken_context),
            ec,
            cloaken_context
        )
    elif response_code == 400:
        # url was malformed
        context = {
            'original_url': url,
            'unshortened_url': '',
            'status': response_code
        }
        return_outputs(
            tableToMarkdown("Not able to resolve or malformed URL ", context),
            {},
            context
        )
    else:
        # server error or unavailable
        return_error('Error Cloaken Unshorten: ' + str(response.get('data', 'key missing')))
