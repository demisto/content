from base64 import b64encode
from datetime import datetime, timedelta

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()


quarantineName = demisto.params()['quarantineName']
userName = demisto.params()['userName']
password = demisto.params()['password']
urlBase = demisto.params()['baseurl']

passcode = bytes(userName + ":" + password, "utf-8")
token = b64encode(passcode).decode("ascii")


def ironportQuarantineReleaseEmail(mid):

    url = urlBase + "/esa/api/v2.0/quarantine/messages"

    payload = '{"action":"release","mids": [' + str(mid) + '],"quarantineName": "' + \
        str(quarantineName) + '","quarantineType":"pvo"}'
    headers = {
        'Authorization': 'Basic ' + str(token),
        'Content-Type': 'text/plain'
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    # print(response.text.encode('utf8'))
    # print(response.status_code)

    if str(response.status_code) == "200":
        # message = response.json()['data']['totalCount']
        if int(response.json()['data']['totalCount']) == 1:
            message = "The Email is Released Successfully!"
        else:
            message = "We could not find the EMail!"

    else:
        message = "Failed to Release!"
    return message


def ironportSpamReleaseEmail(mid):

    url = urlBase + "/esa/api/v2.0/quarantine/messages"

    payload = '{"action":"release","mids": [' + str(mid) + '],"quarantineType":"spam"}'
    headers = {
        'Authorization': 'Basic ' + str(token),
        'Content-Type': 'text/plain'
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    # print(response.text.encode('utf8'))
    # print(response.status_code)

    if str(response.status_code) == "200":
        # print(response.json()['data']['totalCount'])
        if int(response.json()['data']['totalCount']) == 1:
            message = "The Email is Released Successfully!"
        else:
            message = "We could not find the EMail!"

    else:
        message = "Failed to Release!"
    return message


def generateStartEndDates(x):
    myend = datetime.utcnow() + timedelta(days=int(1))
    end = myend.strftime("%Y-%m-%dT00:00:00.000Z")
    mystart = datetime.today() - timedelta(days=int(x))
    start = mystart.strftime("%Y-%m-%dT00:00:00.000Z")
    return start, end

# Search in Policy-Based Quarantined


def ironPortSearchQuarantines(periodInDays, senderPattern, recipientPattern, subjectPattern, limit):

    start, end = generateStartEndDates(periodInDays)
    searchPeriod = "&startDate=" + str(start) + "&endDate=" + str(end)
    searchOptions = "&limit=" + str(limit) + "&offset=0&orderBy=received&orderDir=desc"
    # envelopeSenderFilterBy=contains&envelopeSenderFilterValue=abc
    searchPart = ""
    if str(senderPattern) != "None":
        searchPart += "&envelopeSenderFilterBy=contains&envelopeSenderFilterValue=" + str(senderPattern)
    else:
        searchPart += ""
    # envelopeRecipientFilterBy=starts_with&envelopeRecipientFilterValue=xyz
    if str(recipientPattern) != "None":
        searchPart += "&envelopeRecipientFilterBy=contains&envelopeRecipientFilterValue=" + str(recipientPattern)
    else:
        searchPart += ""
    # subjectFilterBy=ends_with&subjectFilterValue=sub
    if str(subjectPattern) != "None":
        searchPart += "&subjectFilterBy=contains&subjectFilterValue=" + str(subjectPattern)
    else:
        searchPart += ""

    # print("senderSearchPart :", searchPart)
    # print("Serach Period start :",start , " END :",end)
    url = urlBase + \
        "/esa/api/v2.0/quarantine/messages?quarantineType=pvo&quarantines=Outbreak,Virus,File+Analysis,Unclassified,Policy" + \
        searchOptions + searchPeriod + searchPart
    # print("URL : ",url)

    headers = {
        'Authorization': 'Basic ' + str(token)
    }

    response = requests.request("GET", url, headers=headers, verify=False)
    r_j = response.json()
    # print("Output :", r_j)

    count = r_j['meta']['totalCount']
    data = r_j['data']
    # print(type(data))
    # print("Count :", count)
    # print("Emails :", tableToMarkdown('Email List: ', data))
    myoutput = []
    for i in data:
        email = {}
        email["MID"] = i['mid']
        email["received"] = i['attributes']['received']
        email["sender"] = i['attributes']['sender']
        email["recipient"] = i['attributes']['recipient']
        email["subject"] = i['attributes']['subject']
        email["esaHostName"] = i['attributes']['esaHostName']
        email["inQuarantines"] = i['attributes']['inQuarantines']
        email["quarantineForReason"] = i['attributes']['quarantineForReason'][0]
        email["quarantineName"] = i['attributes']['quarantineForReasonDict'][0]['quarantineName']
        email["scheduledExit"] = i['attributes']['scheduledExit']
        email["size"] = i['attributes']['size']

        myoutput.append(email)

    outputs = {
        "IronPortQuarantineSeacrhOutputCount": count,
        "IronPortQuarantineSeacrhOutput": myoutput
    }
    human_readable = tableToMarkdown("Emails Details :", myoutput, removeNull=True)
    return_outputs(human_readable, outputs)


# Search in SPAM-Based Quarantined

def ironPortSearchSpam(periodInDays, senderPattern, recipientPattern, subjectPattern, limit):

    start, end = generateStartEndDates(periodInDays)
    searchPeriod = "&startDate=" + str(start) + "&endDate=" + str(end)
    searchOptions = "&limit=" + str(limit) + "&offset=0&orderBy=date&orderDir=desc"

    # envelopeSenderFilterBy=contains&envelopeSenderFilterValue=xyz
    searchPart = ""

    # ilterBy=subject&filterOperator=contains&filterValue=abc.com
    if str(subjectPattern) != "None":
        searchPart += "&filterBy=subject&filterOperator=contains&filterValue=" + str(subjectPattern)
    else:
        searchPart += ""
    if str(senderPattern) != "None":
        searchPart += "&filterBy=from_address&filterOperator=contains&filterValue=" + str(senderPattern)
    else:
        searchPart += ""

    # envelopeRecipientFilterBy=contains&envelopeRecipientFilterValue=xyz
    if str(recipientPattern) != "None":
        searchPart += "&filterBy=to_address&filterOperator=contains&filterValue=" + str(recipientPattern)
    else:
        searchPart += ""

    # print("searchPart :", searchPart)
    # print("Search Period start :",start , " END :",end)
    url = urlBase + "/esa/api/v2.0/quarantine/messages?quarantineType=spam" + searchOptions + searchPeriod + searchPart
    # /esa/api/v2.0/quarantine/messages?quarantineType=spam&endDate=2020-06-30T00:00:00.000Z&limit=50&offset=0&startDate=2020-06-28T00:00:00.000Z&orderBy=date&orderDir=desc
    # print("URL : ", url)
    headers = {
        'Authorization': 'Basic ' + str(token)
    }

    response = requests.request("GET", url, headers=headers, verify=False)
    r_j = response.json()
    # print("Output :", r_j)

    count = r_j['meta']['totalCount']
    data = r_j['data']
    # print(type(data))
    # print("Count :", count)
    # print("Emails :", tableToMarkdown('Email List: ', data))
    myoutput = []
    for i in data:
        email = {}
        email["MID"] = i['mid']
        email["received"] = i['attributes']['date']
        email["sender"] = i['attributes']['fromAddress']
        email["recipient"] = i['attributes']['envelopeRecipient']
        email["subject"] = i['attributes']['subject']
        email["toAddress"] = i['attributes']['toAddress']
        email["size"] = i['attributes']['size']

        myoutput.append(email)

    outputs = {
        "ironPortSearchSpamCount": count,
        "IronPortSpamSeacrhOutput": myoutput
    }
    # print()
    human_readable = tableToMarkdown("Emails Details :", myoutput, removeNull=True)
    return_outputs(human_readable, outputs)


# Search All Emails

def ironPortSearch(periodInDays, senderPattern, recipientPattern, subjectPattern, limit):

    start, end = generateStartEndDates(periodInDays)
    searchPeriod = "&startDate=" + str(start) + "&endDate=" + str(end)
    searchOptions = "searchOption=messages&offset=0&limit=" + str(limit)
    # envelopeSenderfilterOperator=is&envelopeSenderfilterValue=confikr.qa
    searchPart = ""
    if str(senderPattern) != "None":
        searchPart += "&envelopeSenderfilterOperator=contains&envelopeSenderfilterValue=" + str(senderPattern)
        searchBy = "searchBySender"
    else:
        searchPart += ""
    # envelopeRecipientfilterOperator=contains&envelopeRecipientfilterValue=confikr
    if str(recipientPattern) != "None":
        searchPart += "&envelopeRecipientfilterOperator=contains&envelopeRecipientfilterValue=" + str(recipientPattern)
        searchBy = "searchByRecipient"
    else:
        searchPart += ""
    # subjectfilterOperator=begins_with&subjectfilterValue=test
    if str(subjectPattern) != "None":
        searchPart += "&subjectfilterOperator=contains&subjectfilterValue=" + str(subjectPattern)
        searchBy = "searchBySubject"
    else:
        searchPart += ""

    # print("senderSearchPart :", searchPart)
    # print("Serach Period start :",start , " END :",end)
    url = urlBase + "/esa/api/v2.0/message-tracking/messages?" + searchOptions + searchPeriod + searchPart
    # print("URL : ",url)

    headers = {
        'Authorization': 'Basic ' + str(token)
    }

    response = requests.request("GET", url, headers=headers, verify=False)
    r_j = response.json()
    # print("Output :", r_j)

    count = r_j['meta']['totalCount']
    data = r_j['data']
    # print(type(data))
    # print("Count :", count)
    # print("Emails :", tableToMarkdown('Email List: ', data))
    myoutput = []
    for i in data:
        email = {}
        email["MID"] = i['attributes']['mid']
        email["hostName"] = i['attributes']['hostName']
        email["sbrs"] = i['attributes']['sbrs']
        email["allIcid"] = i['attributes']['allIcid']
        email["serialNumber"] = i['attributes']['serialNumber']
        email["sender"] = i['attributes']['sender']
        email["recipient"] = i['attributes']['recipient']
        email["verdictChart"] = i['attributes']['verdictChart']
        email["messageID"] = i['attributes']['messageID']
        email["timestamp"] = i['attributes']['timestamp']
        email["replyTo"] = i['attributes']['replyTo']
        email["morDetails"] = i['attributes']['morDetails']
        email["icid"] = i['attributes']['icid']
        email["direction"] = i['attributes']['direction']
        # email["finalSubject"] = i['attributes']['finalSubject']
        email["senderDomain"] = i['attributes']['senderDomain']
        email["subject"] = i['attributes']['subject']
        email["senderGroup"] = i['attributes']['senderGroup']
        email["mailPolicy"] = i['attributes']['mailPolicy']
        email["senderIp"] = i['attributes']['senderIp']
        # email["recipientMap"] = i['attributes']['recipientMap']
        email["messageStatus"] = i['attributes']['messageStatus']
        email["isCompleteData"] = i['attributes']['isCompleteData']
        email["friendly_from"] = i['attributes']['friendly_from']

        myoutput.append(email)
    countOutput = "IronPortSeacrhOutputCount" + searchBy
    resultOutput = "IronPortSeacrhOutput" + searchBy
    # print("Names:", countOutput, resultOutput)
    outputs = {
        countOutput: count,
        resultOutput: myoutput
    }

    human_readable = tableToMarkdown("Emails Details :", myoutput, removeNull=True)
    return_outputs(human_readable, outputs)


def main():

    try:

        if demisto.command() == 'test-module':
            # Tests connectivity and credentails on login
            # generateStartEndDates(1)
            return "ok"

        elif demisto.command() == 'iron-port-quarantine-release-email':
            mesId = demisto.args().get('mid')
            ironportQuarantineReleaseEmail(mesId)

        elif demisto.command() == 'iron-port-spam-release-Email':
            mesId = demisto.args().get('mid')
            ironportSpamReleaseEmail(mesId)

        elif demisto.command() == 'iron-port-search-quarantines':
            period = demisto.args().get('periodInDays')
            # senderPattern=""
            senderPattern = demisto.args().get('senderPattern')
            recipientPattern = demisto.args().get('recipientPattern')
            subjectPattern = demisto.args().get('subjectPattern')
            limit = demisto.args().get('limit')
            # print("senderPattern :",senderPattern)
            ironPortSearchQuarantines(period, senderPattern, recipientPattern, subjectPattern, limit)

        elif demisto.command() == 'iron-port-search-spam':
            period = demisto.args().get('periodInDays')
            # senderPattern=""
            senderPattern = demisto.args().get('senderPattern')
            recipientPattern = demisto.args().get('recipientPattern')
            subjectPattern = demisto.args().get('subjectPattern')
            limit = demisto.args().get('limit')
            # print("senderPattern :",senderPattern)
            ironPortSearchSpam(period, senderPattern, recipientPattern, subjectPattern, limit)

        elif demisto.command() == 'iron-port-search':
            period = demisto.args().get('periodInDays')
            # senderPattern=""
            senderPattern = demisto.args().get('senderPattern')
            recipientPattern = demisto.args().get('recipientPattern')
            subjectPattern = demisto.args().get('subjectPattern')
            limit = demisto.args().get('limit')
            # print("senderPattern :",senderPattern)
            ironPortSearch(period, senderPattern, recipientPattern, subjectPattern, limit)

    except Exception as e:
        LOG.print_log(e)
#


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
