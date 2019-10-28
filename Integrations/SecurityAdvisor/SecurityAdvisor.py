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

    def http_request_coachuser(self, data):
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
    result = client.http_request_coachuser(data)
    readable_output = "## {0}".format(result)
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

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def test_module(client):
    """Test Module when testing integration"""
    data = json.dumps(
        {"username": "track@securityadvisor.io", "context": "malware"})
    client.http_request_coachuser(data)
    return('ok')


''' EXECUTION '''
LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'coach-end-user':
        coach_end_user_command()
    elif demisto.command() == 'test-module':
        user = 'track@securityadvisor.io'
        context = "malware"
        send_message(user, context)
        demisto.results('ok')
except Exception, e:
    demisto.debug('Error in SecurityAdvisor')
    LOG(e.message)
    return_error(e.message)
