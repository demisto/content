
''' IMPORT '''

import json
import requests
import urllib

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' PARAMS '''

SERVER_IP = demisto.params().get("server_ip")
APIKEY = demisto.params().get("apikey")
TAG_NAME = demisto.params().get("tag_name")

# Genian NAC Policy Center (Server) URL
BASE_URL = "https://"+SERVER_IP+":8443/mc2"
# Genian NAC REST API Request URL
REQUEST_BASE_URL = "https://"+SERVER_IP+":8443/mc2/rest/"
# Should We use SSL
USE_SSL = not demisto.params().get("insecure", False)
# Response Content Type
HEADER = {
    "accept" : "application/json",
    "content-type" : "application/json;charset=UTF-8"
}


''' HELPER FUNCTIONS '''

def http_request(method:str, url:str, body:dict=None) -> any:
    """
    Makes an API call with the given arguments
    """
    try:
        result = requests.request(
            method,
            url,
            data=body,
            headers=HEADER,
            verify=USE_SSL,
        )
        if result.status_code < 200 or result.status_code >= 300:
            raise Exception("Error in Genian NAC Integration API Call. Code: {0} - {1}".format(str(result.status_code), str(result.reason)))

        json_result = result.json()

        return json_result

    except Exception as e:
        return_error(str(e))

def get_ip_nodeid(ip:str):
    URL = REQUEST_BASE_URL + "nodes/"+ip+"/managementscope?apiKey=" + APIKEY
    result = http_request("GET", URL)
    return result

def get_tag_list():
    URL = REQUEST_BASE_URL + "tags?page=1&pageSize=30&npName="+TAG_NAME+"&apiKey="+APIKEY
    result = http_request("GET", URL)
    return result


''' COMMANDS + REQUESTS FUNCTIONS '''

def assign_ip_tag(nodeid:str):
    URL = REQUEST_BASE_URL + "nodes/"+nodeid+"/tags?apiKey=" + APIKEY
    data = [{
        "id" : "",
        "name" : TAG_NAME,
        "description" : "",
        "startDate" : "",
        "expireDate" : "",
        "periodType" : "",
        "expiryPeriod" : ""
    }]
    result = http_request("POST", URL, body=json.dumps(data))
    return result

def assign_ip_tag_command():
    IP = demisto.getArg("ip")

    result = get_ip_nodeid(IP)
    nodeid = result[0]["nl_nodeid"]

    if not nodeid:
        demisto.results("IP not found. [{0}] is not exist in your network".format(IP))
    else:
        result2 = assign_ip_tag(nodeid)

        tag_check = "assign fail"
        for a in result2:
            if a["Name"] == TAG_NAME:
                tag_check = TAG_NAME
                break

        if tag_check == TAG_NAME:
            hr = "IP : [{0}], [{1}] Tag assign success.".format(IP, TAG_NAME)
            assign_tag = {
                "nodeId" : nodeid,
                "Name" : TAG_NAME
            }
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': result2,
                'ReadableContentsFormat': formats['text'],
                'HumanReadable': hr,
                'EntryContext': {
                    "genian.nac.tag.(val.Tag == obj.Tag)": assign_tag
                }
            })
        else:
            raise Exception("IP : [{0}], [{1}] Tag assign fail.".format(IP, TAG_NAME))

def unassign_ip_tag(nodeid:str, data):
    URL = REQUEST_BASE_URL + "nodes/"+nodeid+"/tags?apiKey=" + APIKEY
    result = http_request("DELETE", URL, body=data)
    return result

def unassign_ip_tag_command():
    IP = demisto.getArg("ip")

    result = get_ip_nodeid(IP)
    nodeid = result[0]["nl_nodeid"]

    if not nodeid:
        demisto.results("IP not found. [{0}] is not exist in your network".format(IP))
    else:
        result2 = get_tag_list()

        tag_check = "tag_not_exists"
        for a in result2["result"]:
            if a["NP_NAME"] == TAG_NAME:
                tag_check = a["NP_IDX"]
                break

        if tag_check != "tag_not_exists":
            if int(tag_check):
                data = "[\""+str(tag_check)+"\"]"
                result3 = unassign_ip_tag(nodeid, data)
                if str(result3) == "[]":
                    hr = "IP : [{0}], [{1}] Tag unassign success.".format(IP, TAG_NAME)
                    unassign_tag = {
                        "nodeId" : nodeid,
                        "Name" : TAG_NAME
                    }
                    demisto.results({
                        'Type': entryTypes['note'],
                        'ContentsFormat': formats['json'],
                        'Contents': result3,
                        'ReadableContentsFormat': formats['text'],
                        'HumanReadable': hr,
                        'EntryContext': {
                            "genian.nac.tag.(val.Tag == obj.Tag)": unassign_tag
                        }
                    })
                else:
                    raise Exception("IP : [{0}], [{1}] Tag unassign fail.".format(THREAT_IP, TAG_NAME))
            else:
                demisto.results("[{0}] Tag not found.".format(TAG_NAME))
        else:
            demisto.results("[{0}] Tag not found.".format(TAG_NAME))

def main():
    """Main execution block"""
    try:

        LOG("Command being called is {0}".format(demisto.command()))

        if demisto.command() == "test-module":
            demisto.results('ok')
        elif demisto.command() == 'genian-nac-assign-ip-tag':
            demisto.results(assign_ip_tag_command())
        elif demisto.command() == 'genian-nac-unassign-ip-tag':
            demisto.results(unassign_ip_tag_command())
        else:
            raise NotImplementedError("Command {} was not implemented.".format(demisto.command()))

    except Exception as e:
        return_error(str(e))

    finally:
        LOG.print_log()

# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
