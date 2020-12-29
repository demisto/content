import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import json
import collections

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
URL_SUFFIX_COACH_USER = 'apis/coachuser/'


# Allows nested keys to be accesible
def makehash():
    return collections.defaultdict(makehash)


'''MAIN FUNCTIONS'''


class Client(BaseClient):
    """
    Calls SecurityAdvisor API and returns results
    """

    def coach_end_user_request(self, data):
        """
        calls coach user api
        """
        response_data_json = self._http_request(
            method='POST',
            url_suffix=URL_SUFFIX_COACH_USER,
            json_data=data,
            data=data,
        )
        return response_data_json


def coach_end_user_command(client, args):
    """
    Returns Coaching status of user

    Args:
        client: SecurityAdvisor client
        args: all command arguments

    Returns:
        json version of coaching status for user
        readable_output: This will be presented in Warroom - should be in markdown syntax - human readable
        outputs: Dictionary/JSON - saved in incident context in order to be used as input for other tasks in the
                 playbook
        raw_response: Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    user = args.get('user')
    context = args.get('context')
    data = json.dumps({"username": user, "context": context})
    result = client.coach_end_user_request(data)

    contxt = makehash()
    contxt['user'] = user
    contxt['context'] = context
    contxt['message'] = result['message']
    contxt['coaching_status'] = result['coaching_status']
    contxt['coaching_score'] = result['coaching_score']
    contxt['coaching_date'] = result['coaching_date']
    outputs = ({
        'SecurityAdvisor.CoachUser(val.user == obj.user && val.context == obj.context)': contxt,
    })

    readable_output = tableToMarkdown("Coaching Status", [contxt])

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def test_module(client):
    """Test Module when testing integration"""
    data = json.dumps({
        "username": "track@securityadvisor.io",
        "context": "malware"
    })
    client.coach_end_user_request(data)

    return 'ok'


''' EXECUTION '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    base_url = demisto.params().get('url', 'https://www.securityadvisor.io/')
    proxy = demisto.params().get('proxy')
    api_key = demisto.params().get('apikey')
    verify_certificate = not demisto.params().get('insecure', False)
    if not demisto.params().get('proxy', False):
        try:
            del os.environ['HTTP_PROXY']
            del os.environ['HTTPS_PROXY']
            del os.environ['http_proxy']
            del os.environ['https_proxy']
        except KeyError:
            pass
    LOG('Command being called is %s' % (demisto.command()))

    try:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Token ' + api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        if demisto.command() == 'coach-end-user':
            return_outputs(*coach_end_user_command(client, demisto.args()))
        elif demisto.command() == 'test-module':
            test_module(client)
            demisto.results('ok')
    # Log exceptions
    except Exception as e:
        return_error('Failed to execute %s command. Error: %s' %
                     (demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
