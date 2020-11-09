import json

import dateparser
import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

''' Created by Osama Shenoda contact osama.samaan.hanna@gmail.com '''

''' IMPORTS '''


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def OpenDNSgetBlackList(myDomainsrequest):
    #print("inside get list")
    #print("url ",myDomainsrequest)
    r = requests.get(myDomainsrequest)
    r_j = r.json()
    # print(r_j.keys())
    metadata = r_j["meta"]
    mydata = r_j["data"]
    # print(type(mydata))
    # print(metadata)
    nextPage = r_j["meta"]["next"]
    # print(nextPage)
    while nextPage:
        r = requests.get(nextPage)
        r_j = r.json()
        # print(r_j.keys())
        metadata = r_j["meta"]
        mydata.extend(r_j["data"])
        # print(metadata)
        nextPage = r_j["meta"]["next"]
        # print(nextPage)
    i = 0
    finalData = []
    while i < len(mydata):
        finalData.append(mydata[i]["name"])
        i = i + 1
    # print(finalData)
    return finalData


def OpenDNScheckDomainInBlackList(myDomainsrequest, domain):
    blist = OpenDNSgetBlackList(myDomainsrequest)
    if domain in blist:
        return "exists"

    else:
        return "NotExist"


def OpenDNSblockDomain(myDomainsrequest, myEventsrequest, domain):
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    #print("durl: ",myDomainsrequest)
    #print("domain :",domain)
    checkStatus = OpenDNScheckDomainInBlackList(myDomainsrequest, domain)
    if checkStatus == "NotExist":
        status = True
    print("Status : ", checkStatus)
    if checkStatus == "NotExist":

        myobj = {
            "alertTime": "2020-01-13T11:14:26.0Z",
            "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
            "deviceVersion": "13.7a",
            "dstDomain": str(domain),
            "dstUrl": "http://" + str(domain) + "/a-bad-url",
            "eventTime": "2020-01-13T13:30:26.0Z",
            "protocolVersion": "1.0a",
            "providerName": "Security Platform"
        }

        #print("my object : ", myobj)
        r2 = requests.post(myEventsrequest, json=myobj, verify=False)
        r2_j = r2.json()
        r_code = r2.status_code
        # r_code ==>
        # 202 Accepted—Everything worked as expected.
        # 400 Bad Request—Likely missing a required parameter or malformed JSON. Please check the syntax on your query.
        # 403 Unauthorized—Request had Authorization header but token was missing or invalid. Please ensure your API token is valid.
        # 404 Not Found—The requested item doesn't exist, check the syntax of your query or ensure the IP and/or domain are valid. If deleting a domain, ensure the id is correct.
        # 500, 502, 503, 504 Server errors—Something went wrong on our end.
        if int(r_code) == 202:
            ActionResult = "Success"
            status = True
        else:
            ActionResult = "Failed"
            status = False

        #print("Result :", r2_j)
        #print("Response Code :", r_code)

        human_readable_data = {
            'Domain': str(domain),
            'Action Result Code': r_code,
            'Response :': r2_j['id'],
            'ActionResult': ActionResult
        }

        outputs = {
            'OpenDNSblockDomain': {
                'Domain': str(domain),
                'Action Result Code': r_code,
                'Response :': r2_j['id'],
                'ActionResult': ActionResult
            }
        }

        headers = ['Domain', 'Action Result Code', 'Response', 'ActionResult']
        human_readable = tableToMarkdown('OpenDNSblockDomain info', human_readable_data, headers=headers, removeNull=True)
        return_outputs(human_readable, outputs, r2_j)
        return status
    else:
        human_readable_data = {
            'Domain': str(domain),
            'Action Result Code': "Already Blocked",
            'Response :': "Already Blocked",
            'ActionResult': "Already Blocked"
        }

        outputs = {
            'OpenDNSblockDomain': {
                'Domain': str(domain),
                'Action Result Code': "Already Blocked",
                'Response :': "Already Blocked",
                'ActionResult': "Already Blocked"
            }
        }

        headers = ['Domain', 'Action Result Code', 'Response', 'ActionResult']
        human_readable = tableToMarkdown('OpenDNSblockDomain info', human_readable_data, headers=headers, removeNull=True)
        return_outputs(human_readable, outputs)
        return True


def OpenDNSdeleteDomain(myDomainsrequest, myEventsrequest, domain):
    #print("we are inside del function")
    delRequest = myDomainsrequest + "&where[name]=" + str(domain)
    #print("delRequest ",delRequest)
    r3 = requests.delete(delRequest, timeout=2.50)
    # r3_txt=r3.json()
    #print("Response  ", r3_txt)
    r_code = r3.status_code
    #print("delRequest status ", r_code)
    if int(r_code) == 204:
        message = domain + " Domain was removed from blacklist"
    else:
        message = domain + " Not in the blacklist or Error"
    demisto.results(message)


def test_module(myDomainsrequest):
    try:
        r = requests.get(myDomainsrequest)
        r_code = r.status_code
        if int(r_code) == 200:
            status = 'ok'
        else:
            status = 'Error'
        # print(r_code)
    except Exception as e:
        LOG(e)
        return_error(e.message)
    demisto.results(status)


def main():

    domain = demisto.args().get('domain')
    baseurl = demisto.params().get('url')
    APIKey = demisto.params().get('APIKey')
    myEventsrequest = str(baseurl) + "events?customerKey=" + str(APIKey)
    myDomainsrequest = str(baseurl) + "domains?customerKey=" + str(APIKey)
    # print(myDomainsrequest)
    try:
        if demisto.command() == 'open-dns-block-domain':
            OpenDNSblockDomain(myDomainsrequest, myEventsrequest, domain)
        elif demisto.command() == 'OpenDNSgetBlackList':
            OpenDNSgetBlackList(myDomainsrequest)
        elif demisto.command() == 'OpenDNScheckDomainInBlackList':
            OpenDNScheckDomainInBlackList(myDomainsrequest, domain)
        elif demisto.command() == 'OpenDNSdeleteDomain':
            OpenDNSdeleteDomain(myDomainsrequest, myEventsrequest, domain)
        elif demisto.command() == 'test-module':
            # Tests connectivity and credentails on login
            test_module(myDomainsrequest)
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
