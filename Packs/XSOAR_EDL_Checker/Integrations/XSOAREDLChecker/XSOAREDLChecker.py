import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


''' HELPER FUNCTIONS '''


def get_base_url(xsoar_version):
    """
    Returns the url to be used to check the EDL, depends on the XSOAR version.
    """
    url = demisto.demistoUrls().get('server')
    if xsoar_version == "6.x":
        # return the server url for xsoar 6
        return url
    else:
        # construct the url for xsoar 8
        url = f"{url[:8]}ext-{url[8:]}/xsoar"
        return url


def edl_http_request(base_url, edl_name, verify, creds):
    """
    HTTP Request to check EDL, using basic auth if creds are provided
    Returns the full response.
    """
    response: Dict | requests.Response
    try:
        if creds:
            username = creds.get('username')
            password = creds.get('password')
            response = requests.get(url=f'{base_url}/instance/execute/{edl_name}', auth=(username, password), verify=verify)
        else:
            response = requests.get(url=f'{base_url}/instance/execute/{edl_name}', verify=verify)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        response = {
            "error": str(e)
        }
    return response


def create_creds(creds):
    """
    Create the credential object for basic auth
    Returns the creds object
    """

    creds = {
        'username': creds.get('identifier'),
        'password': creds.get('password')
    }

    return creds


def check_indicators_on_list(response, content_type):
    """
    Check the number of indicators returned based on the content-type returned (application/json or text/plain, text/csv etc.)
    """
    if content_type == 'application/json':
        return len(response.json())
    else:
        return len(response.text.split('\n'))


''' COMMAND FUNCTIONS '''


def get_edl_command(base_url, edl_name, verify, creds=None):
    """
    Get the EDL, and check whether it returned a 200, 401 unauthorized if the creds are wrong, or the error if it's something else
    """

    # make the request
    response = edl_http_request(base_url, edl_name, verify, creds)

    # check the response
    if type(response) is dict:
        status = 400
        edl_response = response["error"]
        edl_items_on_list = 0
    else:
        # check the status code so we can build a response
        status = response.status_code

        if status == 200:
            edl_response = f'{edl_name} returned a {status} response, all should be well'
            edl_items_on_list = check_indicators_on_list(response, response.headers.get('Content-Type'))
        elif status == 401:
            edl_response = 'Basic authentication failed. Make sure you are using the right credentials.'
            edl_items_on_list = 0
        elif status == 400 and type(response) is not dict:
            if response.json().get('error'):
                edl_response = response.json().get('error')
            else:
                edl_response = "Bad request."
            edl_items_on_list = 0
        else:
            edl_response = f"Bad request {status=}"
            edl_items_on_list = 0
            demisto.debug(f"unknown status {status}")

    # outputs for war room and context
    output = {
        'Name': edl_name,
        'Status': status,
        'Response': edl_response,
        'ItemsOnList': edl_items_on_list
    }

    # build and return the result.
    readable = tableToMarkdown(f"EDL Response for {edl_name}", output, headers=['Name', 'Status', 'Response', 'ItemsOnList'])
    result = CommandResults(readable_output=readable, outputs_prefix='EDLChecker', outputs=output, ignore_auto_extract=True)

    return result, output


def main():
    base_url = get_base_url(demisto.params().get('xsoarversion'))
    edl_name = demisto.params().get('edl_name')
    verify = not demisto.params().get('insecure', False)
    credentials = demisto.params().get('credentials', None)

    if credentials:
        credentials = create_creds(credentials)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            result, output = get_edl_command(base_url, edl_name, verify, credentials)
            if output.get("Status") == 200:
                return_results("ok")
            else:
                return_error(output.get("Response"))

        elif demisto.command() == 'xsoaredlchecker-get-edl':
            result, output = get_edl_command(base_url, edl_name, verify, credentials)
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
