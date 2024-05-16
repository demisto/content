import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests


def symantec_edr_cloud_full_device_scan(api_token,args,params):
    url=params.get('url')+'/v1/commands/scans/full'
    token=args.get('token')
    device_id = args.get('deviceid')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    data = {
        "device_ids": [device_id]
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        try:
            response_json = response.json()
            scandevice = {"symantecedrcloudscandevice": response_json}
            result = CommandResults(outputs=scandevice)
            return_results(result)
        except json.JSONDecodeError:
            # Handle non-JSON response
            scandevice = {"symantecedrcloudscandevice": response.text}
            result = CommandResults(outputs=scandevice)
            return_results(result)
    else:
        return_error(f"Failed to unquarantine device. Status code: {response.status_code}, Response: {response.text}")



def symantec_edr_update_deny_list_policy(api_token,args,params):
    url=params.get('url')+'/v1/policies/deny-list/'+args.get('policy_uid')+'/versions/'+args.get('policy_version')
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    json_data = {
    'features': [
        {
            'configuration': {
                'blacklistrules': [
                    {
                        'processfile': {
                            'sha2': args.get('sha256'),
                            'name': args.get('filename')
                        },
                    },
                ],
            },"properties":{"policy_name":"Deny List Policy - update name"},
            "state":{"locked":False}
        },
    ],
    }
    response=requests.patch(url,headers=headers,json=json_data)
    denypolicy={"symantecedrcloudupdatedenypolicy":response.json()}
    result=CommandResults(outputs=denypolicy)
    return_results(result)
    print(response.status_code)



def symantec_edr_cloud_get_policies(api_token,args,params):

    url=params.get('url')+'/v1/policies'
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    response=requests.get(url,headers=headers)
    policies={"symantecedrcloudpolicies":response.json()}
    result=CommandResults(outputs=policies)
    return_results(result)


def symantec_edr_cloud_get_devices(api_token,args,params):


    url = params.get('url')+"/v1/devices"
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    response = requests.get(url, headers=headers)
    devices={"symanteccloudedrdevices":response.json()}
    result=CommandResults(outputs=devices)
    return_results(result)


def symantec_edr_cloud_quarantine_device(api_token, args, params):
    url = params.get("url") + "/v1/commands/contain"
    token = args.get('token')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    device_id = args.get('deviceid')
    data = {
        "device_ids": [device_id]
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        try:
            response_json = response.json()
            quarantinedevice = {"symantecedrcloudquarantinedevice": response_json}
            result = CommandResults(outputs=quarantinedevice)
            return_results(result)
        except json.JSONDecodeError:
            # Handle non-JSON response
            quarantinedevice = {"symantecedrcloudquarantinedevice": response.text}
            result = CommandResults(outputs=quarantinedevice)
            return_results(result)
    else:
        return_error(f"Failed to unquarantine device. Status code: {response.status_code}, Response: {response.text}")


def symantec_edr_cloud_unquarantine_device(api_token, args, params):
    url = params.get("url") + "/v1/commands/allow"
    token = args.get('token')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    device_id = args.get('deviceid')
    data = {
        "device_ids": [device_id]
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        try:
            response_json = response.json()
            unquarantinedevice = {"symantecedrcloudunquarantinedevice": response_json}
            result = CommandResults(outputs=unquarantinedevice)
            return_results(result)
        except json.JSONDecodeError:
            # Handle non-JSON response
            unquarantinedevice = {"symantecedrcloudunquarantinedevice": response.text}
            result = CommandResults(outputs=unquarantinedevice)
            return_results(result)
    else:
        return_error(f"Failed to unquarantine device. Status code: {response.status_code}, Response: {response.text}")


def symantec_edr_cloud_threat_intel_protection_cve(api_token,args,params):
    url=params.get('url')+'/v1/threat-intel/protection/cve/'+str(args.get("CVE"))
    token=args.get("token")
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    response = requests.get(url, headers=headers)
    relatedfiledetails={"symantecedrcloudthreatintelprotectioncve":response.json()}
    result=CommandResults(outputs=relatedfiledetails)
    return_results(result)


def symantec_edr_cloud_threat_intel_protection_file(api_token,args,params):
    url=params.get('url')+'/v1/threat-intel/protection/file/'+str(args.get("filehash"))
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }

    response = requests.get(url, headers=headers)

    relatedfiledetails={"symantecedrcloudthreatintelprotection":response.json()}
    result=CommandResults(outputs=relatedfiledetails)
    return_results(result)


def symantec_edr_cloud_threat_intel_process_chain(api_token,args,params):
    url=params.get('url')+'/v1/threat-intel/processchain/file/'+str(args.get("filehash"))
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }

    response = requests.get(url, headers=headers)

    relatedfiledetails={"symantecedrcloudthreatintelprocesschain":response.json()}
    result=CommandResults(outputs=relatedfiledetails)
    return_results(result)


def symantec_edr_cloud_threat_intel_insight(api_token,args,params):
    url=params.get('url')+'/v1/threat-intel/insight/file/'+str(args.get("filehash"))
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    response = requests.get(url, headers=headers)

    filedetails={"symantecedrcloudthreatintelinsight":response.json()}
    result=CommandResults(outputs=filedetails)
    return_results(result)


def symantec_edr_cloud_threat_intel_data_related(api_token,args,params):
    url=params.get("url")+'/v1/threat-intel/related/file/'+str(args.get("filehash"))
    token=args.get('token')
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer '+token
    }
    response = requests.get(url, headers=headers)
    relatedfiledetails={"symantecedrcloudthreatintelrelated":response.json()}
    result=CommandResults(outputs=relatedfiledetails)
    return_results(result)

def symantec_edr_cloud_get_incidents(api_token,args,params):
    url = params.get("url")+'/v1/incidents'
    token=args.get('token')
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer '+token
    }

    data = {
        "start_date": args.get("start_date"),
        "end_date": args.get("end_date"),
        "next": 0,
        "limit": 5,
        "include_events": True,
        "query": ""
    }

    response = requests.post(url, headers=headers, json=data)
    incidents={"symantec_edr_cloud_incidents":response.json()}
    result=CommandResults(outputs=incidents)
    return_results(result)



def symantec_edr_cloud_get_file_details(api_token,args,params):
    token=args.get('token')
    url = params.get("url")+'/v1/files/'+str(args.get("filehash"))
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+token
    }

    response = requests.get(url, headers=headers)

    filedetails={"symantecedrcloudfiledetails":response.json()}
    result=CommandResults(outputs=filedetails)
    return_results(result)



def symantec_edr_cloud_get_devices_using_file_hash(api_token,args,params):
    token=args.get('token')
    url = params.get('url')+'/v1/files/'+str(args.get("filehash"))+"/devices"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+token
    }
    params= { 'limit':'2','pageOffset':'0'}
    response = requests.get(url, params, headers=headers)

    deviceresults={"symantecedrclouddeviceresultsfromfilehash":response.json()}
    result=CommandResults(outputs=deviceresults)
    return_results(result)


def symantec_edr_cloud_auth(api_token,args,params):
    url = params.get("url")+"/v1/oauth2/tokens"

    headers = {
        "accept": "application/json",
        "authorization": "Basic "+api_token,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, headers=headers, verify=False)
    token={"bearertoken":response.json()}
    result=CommandResults(outputs=token)
    return_results(result)


def symantec_edr_cloud_get_specific_incident(api_token,args,params):

    args=demisto.args()

    url = params.get("url")+"/v1/incidents/"+str(args.get("incidentid"))
    token=str(args.get("token"))

    headers = {
        'Authorization': 'Bearer '+token
    }
    response = requests.get(url, headers=headers)
    incident={"symantecedrcloudincidentdata":response.json()}
    result=CommandResults(outputs=incident)
    return_results(result)



def test_module(api_token,args, params):
    url = params.get("url")+"/v1/oauth2/tokens"

    headers = {
        "accept": "application/json",
        "authorization": "Basic "+api_token,
        "content-type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.post(url, headers=headers, verify=False)
        if response.status_code==200:
            return_results("ok")
        elif response.status_code==401 or response.status_code==400 or response.status_code==403:
            return_results(f"Make sure your API Key and URL is correct, error status code:{response.status_code}")
        else:
            return_results(f"Error status code: {response.status_code}")
    except Exception as e:
        return_error(f"Failed to execute test command.\nError:\n{str(e)}")




def main():
    command=demisto.command()
    params=demisto.params()
    args=demisto.args()
    api_token=params.get('credentials',{}).get('password')
    api_token=str(api_token)
    try:
        if command=="test-module":
            test_module(api_token,args,params)
        elif command=="symantec-edr-cloud-get-specific-incident":
            symantec_edr_cloud_get_specific_incident(api_token,args,params)
        elif command=="symantec-edr-cloud-auth":
            symantec_edr_cloud_auth(api_token,args,params)
        elif command=="symantec-edr-cloud-get-devices-using-file-hash":
            symantec_edr_cloud_get_devices_using_file_hash(api_token,args,params)
        elif command=="symantec-edr-cloud-get-file-details":
            symantec_edr_cloud_get_file_details(api_token,args,params)
        elif command=="symantec-edr-cloud-get-incidents":
            symantec_edr_cloud_get_incidents(api_token,args,params)
        elif command=="symantec-edr-cloud-threat-intel-data-related":
            symantec_edr_cloud_threat_intel_data_related(api_token,args,params)
        elif command=="symantec-edr-cloud-threat-intel-insight":
            symantec_edr_cloud_threat_intel_insight(api_token,args,params)
        elif command=="symantec-edr-cloud-threat-intel-process-chain":
            symantec_edr_cloud_threat_intel_process_chain(api_token,args,params)
        elif command=="symantec-edr-cloud-threat-intel-protection-file":
            symantec_edr_cloud_threat_intel_protection_file(api_token,args,params)
        elif command=="symantec-edr-cloud-threat-intel-protection-cve":
            symantec_edr_cloud_threat_intel_protection_cve(api_token,args,params)
        elif command=="symantec-edr-cloud-quarantine-device":
            symantec_edr_cloud_quarantine_device(api_token,args,params)
        elif command=="symantec-edr-cloud-unquarantine-device":
            symantec_edr_cloud_unquarantine_device(api_token,args,params)
        elif command=="symantec-edr-cloud-get-devices":
            symantec_edr_cloud_get_devices(api_token,args,params)
        elif command=="symantec-edr-cloud-get-policies":
            symantec_edr_cloud_get_policies(api_token,args,params)
        elif command=="symantec-edr-cloud-update-deny-list-policy":
            symantec_edr_update_deny_list_policy(api_token,args,params)
        elif command=="symantec-edr-cloud-scan-device":
            symantec_edr_cloud_full_device_scan(api_token,args,params)


    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
