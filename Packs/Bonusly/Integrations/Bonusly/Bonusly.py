import json
import math

import demistomock as demisto
import requests
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS/PARAMS '''
#PARAMS = demisto.params()
API_KEY = demisto.params().get('api_key')

# Remove trailing slash to prevent wrong URL path to service
SERVER = "http://bonus.ly"

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

# Service base URL
BASE_URL = SERVER + '/api/v1'

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + API_KEY
}


def http_request(url_suffix, method='POST', data={}, err_operation=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    # data.update({})
    res = requests.request(
        method=method,
        url=BASE_URL + url_suffix,
        verify=USE_SSL,
        data=json.dumps(data),
        headers=HEADERS
    )
    # demisto.log(res.content.decode('utf-8'))
    return json.loads(res.content.decode('utf-8'))


def test_connection():
    path = "/users/me"
    data = {}
    res = http_request(path, method="GET", data=data)
    return res


########################################################
# Actual functions
########################################################

def aboutme():

    path = "/users/me"
    data = {}
    result = http_request(path, method="GET", data=data)
    return result['result']


def create_bonus(points, recipient, reason, keyword):

    path = "/bonuses"
    # Due to bonusly account, reason must be in form "+5 @user.name <description> #<keyword>"
    # Example keywords might include inclusion, execution, collaboration, disruption
    data = {
        "reason": "+" + points + " @" + recipient + " " + reason + " #" + keyword
    }

    res = http_request(path, method="POST", data=data)
    if res['success'] == True:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': res['result'],
            'HumanReadable': res['result'],
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'bonusly': {
                    'createBonus': res['result']
                }
            }
        })
    else:
        demisto.results({
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": res
        })


def list_rewards():
    path = "/rewards"
    data = {}
    res = http_request(path, method="GET", data=data)
    ec = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'bonusly': {
                'listRewards': res['result']
            }
        }
    }
    return ec


def redeem_points(reward_denomination_id):
    userid = aboutme()['id']
    path = "/users/" + userid + "/redemptions"
    data = {
        "denomination_id": reward_denomination_id
    }
    res = http_request(path, method="POST", data=data)

    if res['success'] == True:
        ec = {
            'Type': entryTypes['note'],
            'Contents': res.result.reward_details.name,
            'ContentsFormat': formats['text'],
            'HumanReadable': res.result.reward_details.name,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'bonusly': {
                    'redeemPoints': res['result']
                }
            }
        }
    else:
        ec = {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": res['message']
        }
    return ec


def past_redemptions(limit=1):
    userid = aboutme()['id']
    path = "/users/" + userid + "/redemptions?limit=" + limit
    data = {}

    res = http_request(path, method="GET", data=data)
    if res['success'] == True:
        ec = {
            'Type': entryTypes['note'],
            'Contents': res['result'],
            'ContentsFormat': formats['text'],
            'HumanReadable': res['result'],
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'bonusly': {
                    'pastRedemptions': res['result']
                }
            }
        }
    else:
        ec = {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": res
        }
    return ec


def find_user_by_email(email):
    path = "/users?email=" + email
    data = {}
    res = http_request(path, method="GET", data=data)

    # demisto.log(json.dumps(res['result']))
    # demisto.log(json.dumps(res['result'][0]['display_name']))

    if res['success'] == True:
        ec = {
            'Type': entryTypes['note'],
            'Contents': res['result'],
            'ContentsFormat': formats['text'],
            'HumanReadable': res['result'],
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'bonusly': {
                    'foundUser': {
                        'username': res['result'][0]['username'],
                        'email': res['result'][0]['email']
                    }
                }
            }
        }
    else:
        ec = {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": res['message']
        }
    return ec


########################################################
########################################################


try:
    # Remove proxy if not set to true in params
    # handle_proxy()
    # active_command = "qussery-points" # demisto.command()
    # print(find_last_redemption_bytype("donation"))

    if demisto.command() == 'test-module':
        res = test_connection()

        if 'result' in res:
            if 'id' in res['result']:
                demisto.results('ok')
            else:
                demisto.results('test failed')
        else:
            demisto.results('test failed')

    elif demisto.command() == 'bonusly-aboutme':
        result = aboutme()
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'bonusly': {
                    'aboutme': result
                }
            }
        })

    elif demisto.command() == 'bonusly-create-bonus':
        create_bonus(demisto.args().get('Points'), demisto.args().get('Recipient'),
                     demisto.args().get('Reason'), demisto.args().get('Keyword'))

    elif demisto.command() == 'bonusly-list-rewards':
        demisto.results(list_rewards())

    elif demisto.command() == 'bonusly-redeem-points':
        demisto.results(redeem_points(demisto.args().get('reward_denomination_id')))

    elif demisto.command() == 'bonusly-past-redemptions':
        demisto.results(past_redemptions(demisto.args().get('limit')))

    elif demisto.command() == 'bonusly-find-user-by-email':
        demisto.results(find_user_by_email(demisto.args().get('email')))


# Log exceptions
except Exception as e:
    # LOG(e)
    # LOG.print_log()
    #return_error(f'Unexpected error: {e}')
    print(e)
