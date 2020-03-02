import demistomock as demisto
from CommonServerPython import *
import urllib3

from cloakensdk.client import SyncClient
from cloakensdk.resources import Url
from cloakensdk import utility

# Disable insecure warnings
urllib3.disable_warnings()


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
            'Status': response_code,
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
        return_warning("Not able to resolve or malformed URL ")
    else:
        # server error or unavailable
        return_error('Error Cloaken Unshorten: ' + str(response.get('data', 'key missing')))

if demisto.command() == 'cloaken-screenshot-url':
    client = get_client()
    url = demisto.args()["url"]
    screenshot = utility.RasterizeAndRetrieveImage(client, url=url)
    context = {"Url": url, "Status": 'failed'}
    try:
        result = screenshot.get_screenshot()
        if result.get("data", "") != "":
            stored_img = fileResult(result.get("filename", "screenshot.png"),
                                    result.get("data", ""), "image")
            demisto.results({'Type': entryTypes['image'],
                             'ContentsFormat': formats['text'],
                             'File': stored_img['File'],
                             'FileID': stored_img['FileID'],
                             'Contents': ''
                             })
            context["Status"] = "Success"
            return_outputs(tableToMarkdown("Screenshot Succeeded", context),
                           {"CloakenScreenshot": context},
                           context
                           )
        else:
            return_warning("No Screenshot data available")

    except utility.RasterizeTimeout as e:
        return_warning("Screenshot Timed Out: " + str(e))
    except utility.RasterizeException as e:
        return_warning("Screenshot Failed: " + str(e))
