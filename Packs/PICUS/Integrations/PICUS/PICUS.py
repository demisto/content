import json
import os
import re
import traceback
import urllib

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from requests.exceptions import ConnectionError, HTTPError

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARIABLES'''
VERIFY_SSL = not demisto.params().get('insecure', False)

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client:

    :type name: ``str``
    :param name:

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
            else demisto.params().get('server')
        SERVER = demisto.params().get('server')
        CREDENTIALS = demisto.params().get('apikey')
        AUTH_HEADERS = {'Content-Type': 'application/json'}

        params = "Bearer " + CREDENTIALS
        headers = {"X-Refresh-Token": params}
        endpoint = "/authenticator/v1/access-tokens/generate"
        url = SERVER + endpoint
        req = requests.post(url, headers=headers, verify=VERIFY_SSL)
        parsed = json.loads(req.content)
        data = parsed['data']
        accessToken = data['access_token']

    except DemistoException as e:
        if ('Forbidden' in str(e)) or not(accessToken):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def getAccessToken():
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    ''' GLOBAL VARS '''
    CREDENTIALS = demisto.params().get('apikey')
    AUTH_HEADERS = {'Content-Type': 'application/json'}

    params = "Bearer " + CREDENTIALS
    headers = {"X-Refresh-Token": params}
    endpoint = "/authenticator/v1/access-tokens/generate"
    url = SERVER + endpoint
    req = requests.post(url, headers=headers, verify=VERIFY_SSL)
    if req.status_code == 200:
        pass
    else:
        demisto.results(req.content)
        sys.exit(1)

    parsed = json.loads(req.content)
    data = parsed['data']
    accessToken = data['access_token']
    expirydate = data['expire_at']
    #print("Access Token Expiry Date : ", expirydate)
    results = parsed['data']

    return accessToken


''' Token instead of accesstoken
    if TOKEN:
        AUTH_HEADERS['SEC'] = str(TOKEN)


    if not TOKEN :
        raise Exception('Either credentials or auth token should be provided.')

    if not demisto.params()['proxy']:
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']
'''


def vectorCompare(requestContent):

    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/attack-results/compare-a-vector"

    accessToken = "Bearer " + requestContent
    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    begin_date = demisto.args().get('begin_date')
    end_date = demisto.args().get('end_date')
    trusted = demisto.args().get('trusted')
    untrusted = demisto.args().get('untrusted')
    data = {'begin_date': begin_date,
            'end_date': end_date,
            'trusted': trusted,
            'untrusted': untrusted,
            }

    cookies = {'X-Api-Token': accessToken}
    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results_insecures = parsed['data']['variants'][0]['insecures'] if 'data' in parsed else ''

    return {
        'Type': entryTypes['note'],
        'Contents': results_insecures,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Insecures', results_insecures)
    }

    results_insecure_to_secures = parsed['data']['variants'][0]['insecure_to_secures'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results_insecure_to_secures,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Insecure to Secures', results_insecure_to_secures)
    }

    results_secure_to_insecures = parsed['data']['variants'][0]['secure_to_insecures'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results_secure_to_insecures,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Secures to Insecure', results_secure_to_insecures)
    }

    results_secures = parsed['data']['variants'][0]['secures'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results_secures,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Secures', results_secures)
    }


'''Response:
{
  "data": {
    "trusted": "string",
    "untrusted": "string",
    "variants": [
      {
        "insecure_to_secures": [
          {
            "md5": "string",
            "name": "string",
            "since": "string",
            "threat_id": "string"
          }
        ],
        "insecures": [
          {
            "md5": "string",
            "name": "string",
            "since": "string",
            "threat_id": "string"
          }
        ],
        "secure_to_insecures": [
          {
            "md5": "string",
            "name": "string",
            "since": "string",
            "threat_id": "string"
          }
        ],
        "secures": [
          {
            "md5": "string",
            "name": "string",
            "since": "string",
            "threat_id": "string"
          }
        ],
        "variant_name": "string"
      }
    ]
  },
  "success": true
}
'''


def attackResultList(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/attack-results/list"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    attack_result = demisto.args().get('attack_result')
    begin_date = demisto.args().get('begin_date')
    console_output_info = bool(demisto.args().get('console_output_info'))
    end_date = demisto.args().get('end_date')
    from_time = demisto.args().get('from_time')
    page = int(demisto.args().get('page'))
    size = int(demisto.args().get('size'))
    threat_parameters = demisto.args().get('threat_parameters')
    vector1 = demisto.args().get('vector1')
    vector2 = demisto.args().get('vector2')

    data = {'attack_result': attack_result,
            'begin_date': begin_date,
            'console_output_info': console_output_info,
            'end_date': end_date,
            'from_time': from_time,
            'page': page,
            'size': size,
            'threat_parameters': threat_parameters,
            'vectors': [{'trusted': vector1,
                         'untrusted': vector2
                         }]
            }

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)
    results = parsed['data']['results'] if 'data' in parsed else ''

    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Picus-Attack-Result-List', results)
    }


'''Response:
{
  "attack_result": "secure",
  "begin_date": "2018-10-29",
  "console_output_info": true,
  "end_date": "2019-10-29",
  "from_time": "2017-10-29T04:48:35.919615635Z",
  "page": 5,
  "size": 10,
  "threat_parameters": {
    "begin_date": "2018-10-29",
    "categories": [
      [
        "Malicious Code"
      ],
      [
        "Attack Scenario",
        "Defense Evasion",
        "Indicator Removal from Tools"
      ]
    ],
    "cve": "string",
    "end_date": "2019-10-29",
    "kill_chains": [
      "Delivery",
      "Compromise"
    ],
    "md5": "stringstringstringstringstringst",
    "method": "PCI and PII",
    "severity": "High",
    "sha256": "string",
    "threat_id": 100682
  },
  "vectors": [
    {
      "trusted": "Trusted-Peer-Name",
      "untrusted": "Untrusted-Peer-Name"
    }
  ]
}
'''


def specificThreatsResults(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/attack-results/threat-specific-latest"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    cve = demisto.args().get('cve')
    md5 = demisto.args().get('md5')
    page = int(demisto.args().get('page'))
    sha256 = demisto.args().get('sha256')
    size = int(demisto.args().get('size'))
    threat_id = int(demisto.args().get('threat_id'))

    data = {'cve': cve,
            'md5': md5,
            'page': page,
            'sha256': sha256,
            'size': size,
            'threat_id': threat_id,
            }

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)
    results = parsed['data']['results'] if 'data' in parsed else ''

    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Picus-Specific-Threats-Results', results)
    }


'''Response:
{
  "data": {
    "page_number": 2,
    "results": {
      "CVE": "string",
      "MD5": "string",
      "SHA256": "string",
      "l1_category_name": "string",
      "pid": "string",
      "threat_name": "string",
      "vectors": [
        {
          "id": 0,
          "name": "string",
          "variants": [
            {
              "destination_port": 443,
              "last_time": "2017-10-29T08:38:53.1035948Z",
              "name": "HTTP",
              "result": "Secure",
              "since": "2017-10-29T08:38:53.1035948Z",
              "source_port": 12255
            }
          ]
        }
      ]
    },
    "size": 5,
    "total_count": 548
  },
  "success": true
}
'''


def peerList(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/peers/list"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint

    req = requests.post(url, headers=headers, verify=VERIFY_SSL)
    parsed = json.loads(req.content)
    results = parsed['data']['peers'] if 'data' in parsed else ''

    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Picus-Peer-List', results)
    }


'''Response:
{
  "data": {
    "peers": [
      {
        "is_alive": true,
        "latest_attack": "2020-09-04T13:26:03.524Z",
        "name": "Windows10-Peer",
        "registered_ip": "\"\"",
        "type": "Network"
      }
    ],
    "total_count": 0
  },
  "success": true
}
'''


def attackAllVectors(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/schedule/attack/all-possible-vectors"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    threat_id = int(demisto.args().get('threat_id'))
    data = {'threat_id': threat_id}
    try:
        req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    except Exception as e:
        print(e)
    parsed = json.loads(req.content)

    results = parsed['data']['vectors'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PICUS-Attack-All-Vectors', results)
    }


'''Response:
{
  "data": {
    "vectors": [
      {
        "trusted": "string",
        "untrusted": "string",
        "variants": [
          {
            "name": "string",
            "result": "success"
          }
        ]
      }
    ]
  },
  "success": true
}
'''


def attackSingle(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/schedule/attack/single"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    threat_id = int(demisto.args().get('threat_id'))
    variant = demisto.args().get('variant')
    vector1 = demisto.args().get('vector1')
    vector2 = demisto.args().get('vector2')
    data = {'threat_id': threat_id,
            'variant': variant,
            'trusted': vector1,
            'untrusted': vector2
            }

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results = parsed['data'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PICUS-Attack-Single', results)
    }


'''Response:
{
  "data": {
    "result": "success"
  },
  "success": true
}
'''


def triggerUpdate(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/settings/trigger-update"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint

    req = requests.post(url, headers=headers, verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results = parsed
    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PICUS-Trigger-Update', results)
    }


'''Response:
{
  "data": true,
  "success": true
}
'''


def version(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/settings/version"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint

    req = requests.post(url, headers=headers, verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results = parsed['data'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PICUS-Version', results)
    }


'''Response:
{
  "data": {
    "last_update_date": "string",
    "update_time": 0,
    "version": 0
  },
  "success": true
}
'''


def mitigationList(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/threats/mitigations/list"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    products = []
    begin_date = demisto.args().get('begin_date')
    end_date = demisto.args().get('end_date')
    page = int(demisto.args().get('page'))
    products = [demisto.args().get('products')]
    signature_id = demisto.args().get('signature_id')
    size = int(demisto.args().get('size'))
    threat_id = int(demisto.args().get('threat_id'))

    data = {'begin_date': begin_date,
            'end_date': end_date,
            'page': page,
            'products': products,
            'signature_id': signature_id,
            'size': size,
            'threat_id': threat_id
            }

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results = parsed['data']['mitigations'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PICUS-Mitigation-List', results)
    }


'''Response:
{
  "begin_date": "2018-10-29",
  "end_date": "2019-10-29",
  "page": 5,
  "products": "Product1",
  "signature_id": "12345",
  "size": 10,
  "threat_id": 123456
}
'''


def mitreMatrix(requestContent):

    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/threats/mitre-matrix"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint

    req = requests.get(url, headers=headers, verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results = parsed['data'] if 'data' in parsed else ''
    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PICUS-Mitre-Matrix', results)
    }


'''Response:
{
  "data": [
    {
      "tactic_id": 0,
      "tactic_name": "string",
      "techniques": [
        {
          "actions": [
            {
              "action_id": "string",
              "action_name": "string",
              "affected_platforms": [
                {
                  "architecture": "string",
                  "platform": "string"
                }
              ],
              "description": "string",
              "is_critical": true
            }
          ],
          "technique_id": "string",
          "technique_name": "string"
        }
      ]
    }
  ],
  "success": true
}
'''


def sigmaRulesList(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/threats/sigma-rules/list"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint

    size = int(demisto.args().get('size'))
    page = int(demisto.args().get('page'))

    data = {
        'Page Size': size,
        'Page': page,
    }

    header = ['Sigma Rule List Count', 'Size', 'Page']
    result_info = {}

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)
    results = parsed['data']['sigma_rules'] if 'data' in parsed else ''

    result_info['Sigma Rule List Count'] = parsed['data']['total_count'] if 'data' in parsed else ''
    hr = tableToMarkdown('Sigma Rule List Info', result_info, header, removeNull=True)
    hr += tableToMarkdown('Sigma Rules', results)

    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr
    }


'''Response:
{
  "data": {
    "page_number": 2,
    "sigma_rules": [
      {
        "actions": [
          {
            "description": "string",
            "id": 0,
            "name": "string"
          }
        ],
        "content": "title: Gathering PnP Device List Information via powershell status: experimental...",
        "id": 0
      }
    ],
    "size": 5,
    "total_count": 548
  },
  "success": true
}
'''


def vectorList(requestContent):
    SERVER = demisto.params().get('server')[:-1] if str(demisto.params().get('server')).endswith('/') \
        else demisto.params().get('server')
    endpoint = "/user-api/v1/vectors/list"

    accessToken = "Bearer " + requestContent

    headers = {"X-Api-Token": accessToken}

    url = SERVER + endpoint
    add_user_details = bool(demisto.args().get('add_user_details'))
    page = int(demisto.args().get('page'))
    size = int(demisto.args().get('size'))
    data = {'add_user_details': add_user_details,
            'page': page,
            'size': size
            }

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    parsed = json.loads(req.content)

    results = parsed['data']['vectors'] if 'data' in parsed else ''

    header = ['name', 'description', 'trusted', 'untrusted', 'is_disabled', 'type']
    hr = tableToMarkdown('Picus Vector List', results, header, removeNull=True)

    return {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr
    }


'''Response:
{
  "data": {
    "page_number": 2,
    "size": 5,
    "total_count": 548,
    "vectors": [
      {
        "description": "string",
        "heartbeat_results": [
          {
            "is_successful": true,
            "module": "PTS",
            "result_time": "2018-08-21T13:00:33.590599407Z",
            "variant": "HTTP"
          }
        ],
        "is_disabled": true,
        "name": "Email-Peer-2 - Email-Peer-1",
        "trusted": "Windows10-Peer",
        "type": "string",
        "untrusted": "Network-Peer",
        "users": [
          {
            "role": "admin",
            "username": "oliver"
          }
        ]
      }
    ]
  },
  "success": true
}
'''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    ''' EXECUTION '''
    #LOG('command is %s' % (demisto.command(), ))
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        LOG('Command being called is {command}'.format(command=demisto.command()))
        if demisto.command() == 'picus-get-access-token':
            getAccessToken()
        elif demisto.command() == 'Picus-Vector-Compare':  # Makes a comparison of the given vector's results
            token = getAccessToken()
            demisto.results(vectorCompare(token))
        elif demisto.command() == 'Picus-Attack-Result-List':  # Returns the list of the attack results\nhave optional parameters for pagination and filtration
            token = getAccessToken()
            demisto.results(attackResultList(token))
        elif demisto.command() == 'Picus-Specific-Threats-Results':  # Returns the list of the attack results of a single threat\nhave optional
            token = getAccessToken()
            demisto.results(specificThreatsResults(token))
        elif demisto.command() == 'Picus-Peer-List':  # Returns the peer list with current statuses
            token = getAccessToken()
            demisto.results(peerList(token))
        elif demisto.command() == 'Picus-Attack-All-Vectors':  # Schedules given attack on all possible vectors
            token = getAccessToken()
            demisto.results(attackAllVectors(token))
        elif demisto.command() == 'Picus-Attack-Single':  # Schedules a single attack on requested vector
            token = getAccessToken()
            demisto.results(attackSingle(token))
        elif demisto.command() == 'Picus-Trigger-Update':  # Triggers the update mechanism manually, returns if the update-command is taken successfully
            token = getAccessToken()
            demisto.results(triggerUpdate(token))
        elif demisto.command() == 'Picus-Version':  # Returns the current version and the update time config
            token = getAccessToken()
            demisto.results(version(token))
        elif demisto.command() == 'Picus-Mitigation-List':  # Returns the list of the mitigations of threats\nhave optional parameters for pagination and filtration, this route may not be used associated with your license
            token = getAccessToken()
            demisto.results(mitigationList(token))
        elif demisto.command() == 'Picus-Mitre-Matrix':  # Returns the mitre matrix metadata\ntakes no parameters
            token = getAccessToken()
            demisto.results(mitreMatrix(token))
        elif demisto.command() == 'Picus-Sigma-Rules-List':  # Returns the list of the sigma rules of scenario actions\nhave optional parameters for pagination and filtration, this route may not be used associated with your license
            token = getAccessToken()
            demisto.results(sigmaRulesList(token))
        elif demisto.command() == 'Picus-Vector-List':  # Returns the list of the vectors all disabled and enabled ones\nhave optional parameters for pagination
            token = getAccessToken()
            demisto.results(vectorList(token))
        elif demisto.command() == 'test-module':
            demisto.results(test_module())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
