import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import json

def binalyze_assign_image_acquisition_task(api_token, args, params):
    url = params.get("url") + "/api/public/acquisitions/acquire/image"

    payload = {
        "caseId": args.get("caseid"),
        "taskConfig": {
            "choice": "use-custom-options",
            "saveTo": {
                "windows": {
                    "location": "repository",
                    "path": args.get("RepositoryPath"),
                    "useMostFreeVolume": True,
                    "repositoryId": args.get("RepositoryID"),
                    "tmp": "Binalyze\\AIR\\tmp",
                    "directCollection": True
                },
                "linux": {
                    "location": "repository",
                    "path": "opt/binalyze/air",
                    "useMostFreeVolume": False,
                    "repositoryId": args.get("RepositoryID"),
                    "tmp": "opt/binalyze/air/tmp",
                    "directCollection": False
                },
                "macos": {
                    "location": "repository",
                    "path": "opt/binalyze/air",
                    "useMostFreeVolume": False,
                    "repositoryId": args.get("RepositoryID"),
                    "tmp": "opt/binalyze/air/tmp",
                    "directCollection": False
                }
            },
            "bandwidth": {
                "limit": 100000
            },
            "compression": {
                "enabled": True,
                "encryption": {
                    "enabled": False,
                    "password": "sakir"
                }
            }
        },
        "diskImageOptions": {
            "chunkSize": 1048576,
            "chunkCount": 0,
            "startOffset": 0,
            "endpoints": [
                {
                    "endpointId": args.get("EndpointId"),
                    "volumes": [
                        args.get("EndpointVolume")

                    ]
                }
            ]
        },
        "filter": {
            "searchTerm": "",
            "name": args.get("name"),
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [],
            "isolationStatus": [],
            "platform": [args.get("platform")],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationid"))
            ]
        }
    }
    if args.get('tags') is None:
        payload["filter"]["tags"] = []
    else:
        payload["filter"]["tags"] = [args.get('tags')]
    headers = {
        'Content-Type': 'application/json',
        'Authorization': api_token
    }
    payload_data=json.dumps(payload)
    response = requests.request("POST", url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_image_acquistion_task = {"binalyze_assign_image_acquistion_task": response.json()}
    result = CommandResults(outputs=binalyze_assign_image_acquistion_task)
    return_results(result)


def binalyze_assign_reboot_task(api_token,args,params):
    url = params.get("url")+"/api/public/assets/tasks/reboot?Content-Type=application/json"
    payload = {
        "filter": {
            "searchTerm": args.get("searchterm"),
            "name": args.get("name"),
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [],
            "isolationStatus": [],
            "platform": [],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationIds"))
            ]
        }
    }

    if args.get('tags') is None:
        payload["filter"]["tags"] = []
    else:
        payload["filter"]["tags"] = [args.get('tags')]

    headers = {
        "Content-Type": "application/json",
        "Authorization": api_token
    }
    payload_data = json.dumps(payload)
    response = requests.post(url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_reboot_task_by_filter = {"binalyze_assign_reboot_task": response.json()}
    result = CommandResults(outputs=binalyze_assign_reboot_task_by_filter)
    return_results(result)




def binalyze_assign_version_update_task(api_token,args,params):
    url = params.get("url")+"/api/public/assets/tasks/version-update"
    payload = {
        "filter": {
            "searchTerm": args.get("searchterm"),
            "name": args.get("name"),
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [],
            "isolationStatus": [],
            "platform": [],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationIds"))
            ]
        }
    }
    if args.get('tags') is None:
        payload["filter"]["tags"] = []
    else:
        payload["filter"]["tags"] = [args.get('tags')]

    headers = {
        "Content-Type": "application/json",
        "Authorization": api_token
    }
    payload_data = json.dumps(payload)
    response = requests.post(url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_version_update_task = {"binalyze_assign_version_update_task": response.json()}
    result = CommandResults(outputs=binalyze_assign_version_update_task)
    return_results(result)



def binalyze_assign_log_retrieval_task(api_token,args,params):
    url = params.get("url")+"/api/public/assets/tasks/retrieve-logs"
    payload = {
        "filter": {
            "searchTerm": args.get("searchterm"),
            "name": args.get("name"),
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [],
            "isolationStatus": [],
            "platform": [],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationIds"))
            ]
        }
    }
    if args.get('tags') is None:
        payload["filter"]["tags"] = []
    else:
        payload["filter"]["tags"] = [args.get('tags')]
    headers = {
        "Content-Type": "application/json",
        "Authorization": api_token
    }
    payload_data = json.dumps(payload)
    response = requests.post(url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_log_retrieval_task = {"binalyze_assign_log_retrieval_task": response.json()}
    result = CommandResults(outputs=binalyze_assign_log_retrieval_task)
    return_results(result)



def binalyze_assign_isolation_task(api_token,args,params):
    url = params.get("url")+"/api/public/assets/tasks/isolation"
    payload = {
        "enabled":True,
        "filter": {
            "searchTerm": args.get("searchterm"),
            "name": args.get("name"),
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [],
            "isolationStatus": [],
            "platform": [],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationIds"))
            ]
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": api_token
    }
    payload_data = json.dumps(payload)
    response = requests.post(url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_isolation_task = {"binalyze_assign_reboot_task": response.json()}
    result = CommandResults(outputs=binalyze_assign_isolation_task)
    return_results(result)


def binalyze_assign_shutdown_task(api_token,args,params):

    url = params.get("url")+"/api/public/assets/tasks/shutdown"
    payload = {
        "filter": {
            "searchTerm": args.get("searchterm"),
            "name": args.get("name"),
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [],
            "isolationStatus": [],
            "platform": [],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationIds"))
            ]
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": api_token
    }
    payload_data = json.dumps(payload)
    response = requests.post(url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_shutdown_task = {"binalyze_assign_shutdown_task": response.json()}
    result = CommandResults(outputs=binalyze_assign_shutdown_task)
    return_results(result)

def binalyze_assign_evidence_acquisition(api_token,args,params):
    url = params.get("url")+"/api/public/acquisitions/acquire"
    payload = {
        "caseId": args.get('caseId'),
        "droneConfig": {
            "autoPilot": bool(str(args.get('droneconfig_autopilot'))),
            "enabled": bool(str(args.get('droneconfig_enabled'))),
            "analyzers": [],
            "keywords": [],
        },
        "taskConfig": {
            "choice": "use-custom-options",
            "cpu": {
                "limit": int(args.get("cpulimit"))
            },
            "diskSpace": {
                "reserve": 0
            },
            "bandwidth": {
                "limit": 0
            },
            "compression": {
                "enabled": bool(str(args.get('compression'))),
                "encryption": {
                    "enabled": False,
                    "password": args.get('encryptionpassword')
                }
            },
            "saveTo": {
                "windows": {
                    "location": "local",
                    "useMostFreeVolume": True,
                    "repositoryId": None,
                    "path": "Binalyze\\AIR\\",
                    "volume": "C:",
                    "tmp": "Binalyze\\AIR\\tmp",
                    "directCollection": False
                },
                "linux": {
                    "location": "local",
                    "useMostFreeVolume": True,
                    "repositoryId": None,
                    "path": "opt/binalyze/air",
                    "tmp": "opt/binalyze/air/tmp",
                    "directCollection": False
                },
                "macos": {
                    "location": "local",
                    "useMostFreeVolume": False,
                    "repositoryId": None,
                    "path": "opt/binalyze/air",
                    "volume": "/",
                    "tmp": "opt/binalyze/air/tmp",
                    "directCollection": False
                },
                "aix": {
                    "location": "local",
                    "useMostFreeVolume": True,
                    "path": "opt/binalyze/air",
                    "volume": "/",
                    "tmp": "opt/binalyze/air/tmp",
                    "directCollection": False
                }
            }
        },
        "acquisitionProfileId": args.get("acquisitionProfileID"),
        "filter": {
            "searchTerm": args.get("searchterm"),
            "name": "",
            "ipAddress": args.get("ipAddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [args.get("managedStatus")],
            "isolationStatus": [args.get("isolationStatus")],
            "platform": [args.get("platform")],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationIds"))
            ]
        }
    }

    # Perform the conditional check for 'tags' field
    if args.get('tags') is None:
        payload["filter"]["tags"] = []
    else:
        payload["filter"]["tags"] = [args.get('tags')]

    if args.get('includedEndpointIds') is None:
        payload["filter"]["includedEndpointIds"] = []
    else:
        payload["filter"]["includedEndpointIds"] = [args.get("includedendpointids")]
    if args.get('droneconfig_analyzers') is None:
        payload["droneConfig"]["analyzers"]=[]
    else:
        payload["droneConfig"]["analyzers"]=[args.get('droneconfig_analyzers')]
    headers = {
        'Content-Type': 'application/json',
        'Authorization': api_token
    }

    payload_data=json.dumps(payload)
    response = requests.request("POST", url, headers=headers, data=payload_data, verify=False)
    binalyze_assign_evidence_acquisition = {"binalyze_assign_evidence_acquisition": response.json()}
    result = CommandResults(outputs=binalyze_assign_evidence_acquisition)
    return_results(result)




def binalyze_get_triage_rules(api_token,args,params):
    s=str(args.get("searchterm"))
    o=str(args.get("organizationid"))
    if args.get("searchterm") is not None:
        url = params.get("url")+"/api/public/triages/rules?pageSize=0&filter[searchTerm]="+s+"&filter[organizationIds]="+o
    else:
        url = params.get("url")+"/api/public/triages/rules?pageSize=0&filter[organizationIds]="+str(args.get('organizationid'))


    headers = {
    'Content-Type': 'application/json',
    'Authorization': api_token
    }

    response = requests.request("GET", url, headers=headers,verify=False)
    binalyzetriagerules={"binalyzetriagerules":response.json()}
    result=CommandResults(outputs=binalyzetriagerules)
    return_results(result)

def binalyze_get_cases(api_token,args,params):
    url=params.get("url")+"/api/public/cases?filter[organizationIds]=" + args.get('organizationid')

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': api_token
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    binalyze_get_cases = {"binalyze_get_cases": response.json()}
    result = CommandResults(outputs=binalyze_get_cases)
    return_results(result)

def binalyze_create_case(api_token,args,params):


    url=params.get("url")+"/api/public/cases"
    payload = json.dumps({
        "organizationId": int(args.get('organizationid')),
        "name": args.get('casename'),
        "ownerUserId": args.get('owneruserid'),
        "visibility": "public-to-organization",
        "assignedUserIds": []
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': api_token
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    binalyze_create_case={"binalyze_create_case":response.json()}
    result=CommandResults(outputs=binalyze_create_case)
    return_results(result)


def binalyze_get_users(api_token,args,params):

    organizationid=args.get('organizationid')
    url=params.get("url")+"/api/public/user-management/users?filter[organizationIds]=" + organizationid

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': api_token
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    binalyze_get_users = {"binalyze_get_users": response.json()}
    result = CommandResults(outputs=binalyze_get_users)
    return_results(result)

def binalyze_assign_triage_task_by_filter(api_token,args,params):
    url=params.get("url")+"/api/public/triages/triage"
    payload = {
        "caseId": args.get('caseId'),
        "triageRuleIds": [],
        "taskConfig": {
            "choice": "use-custom-options"
        },
        "mitreAttack": {
            "enabled": bool(str(args.get('mitreattackenabled')))
        },
        "filter": {
            "searchTerm": args.get("SearchTerm"),
            "name": args.get("Name"),
            "ipAddress": args.get("ipaddress"),
            "groupId": "",
            "groupFullPath": "",
            "managedStatus": [args.get('managedstatus')],
            "isolationStatus": [args.get("isolationstatus")],
            "platform": [args.get("platform")],
            "issue": "",
            "onlineStatus": [],
            "tags": [],
            "version": "",
            "policy": "",
            "includedEndpointIds": [],
            "excludedEndpointIds": [],
            "organizationIds": [
                int(args.get("organizationsIds"))
            ]
        }
    }

    if args.get('tags') is None:
        payload["filter"]["tags"] = []
    else:
        payload["filter"]["tags"] = [args.get('tags')]

    if args.get('includedEndpointIds') is None:
        payload["filter"]["includedEndpointIds"] = []
    else:
        payload["filter"]["includedEndpointIds"] = [args.get("includedendpointids")]
    if args.get("triageruleids") is None:
        payload["triageruleids"]=[]
    else:
        payload["triageruleids"]= [args.get("triageruleids")]
    headers = {
        'Content-Type': 'application/json',
        'Authorization': api_token
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
    binalyze_assign_triage_task_by_filter = {"binalyze_assign_triage_by_filter": response.json()}
    result = CommandResults(outputs=binalyze_assign_triage_task_by_filter)
    return_results(result)


def binalyze_start_acquisition_webhook(api_token,args,params):
    webhookname=args.get('webhookname')
    ipaddress=args.get('ipaddress')
    webhooktoken=args.get('webhooktoken')
    if ipaddress is not None:
        url= params.get("url")+"/api/webhook/"+webhookname+"/"+ipaddress+"?token="+webhooktoken
    else:
        url= params.get("url")+"/api/webhook/"+webhookname+"/"+"?token="+webhooktoken
    response=requests.get(url,verify=False, allow_redirects=True)
    webhookresult={'binalyze_webhook_result':response.json()}
    result=CommandResults(outputs=webhookresult)
    return_results(result)

def binalyze_get_acquisition_profiles(api_token,args,params):
    o=str(args.get('organizationid'))
    url = params.get("url")+"/api/public/acquisitions/profiles?filter[organizationIds]="+o+"&filter[allOrganizations]=true"
    headers = {
        'Authorization': api_token,
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
        }

    response=requests.get(url,headers=headers,verify=False)
    acquisition_profiles={"binalyze_acquisition_profiles":response.json()}
    result=CommandResults(outputs=acquisition_profiles)
    return_results(result)



def binalyze_get_tasks(api_token,args,params):
    organization_id=args.get('organizationid')
    payload={}
    url=params.get("url")+"/api/public/tasks?filter[organizationIds]="+organization_id
    headers = {
        "Content-type": "application/json",
        "Authorization": api_token,
    }
    response = requests.get(url, headers=headers,data=payload,verify=False)
    tasks={"binalyze_tasks":response.json()}
    result=CommandResults(outputs=tasks)
    return_results(result)

def binalyze_get_assets(api_token,args,params):
    o=str(args.get('organizationid'))
    s=str(args.get('searchterm'))
    payload={}
    if args.get("searchterm") is not None:
        url = params.get("url")+"/api/public/assets?filter[searchTerm]="+s+"&filter[organizationIds]="+o
    else:
        url= params.get("url")+"/api/public/assets?filter[organizationIds]="+o
    headers = {
            'Authorization': api_token,
            'User-Agent': 'Binalyze AIR',
            'Content-type': 'application/json',
            'Accept-Charset': 'UTF-8'
            }

    response = requests.get(url, headers=headers,data=payload,verify=False)
    assets={"binalyze_assets":response.json()}
    result=CommandResults(outputs=assets)
    return_results(result)


def test_module(api_token, args, params):
    url = params.get("url")+"/api/public/assets?filter[organizationIds]=0"
    payload={}
    headers = {
        "Content-type": "application/json",
        "Authorization": api_token,
    }
    try:
        test = requests.get(url, headers=headers,data=payload, verify=False)
        if test.status_code == 200:
            return_results("ok")
        elif test.status_code == 401 or test.status_code == 403:
            return_results("Authorization Error: make sure API Key is correctly set")
        elif test.status_code ==400:
            return_results("Invalid URL: Make sure URL is correctly set")
        else:
            return_results(f"Unexpected error status code: {test.status_code}")
    except Exception as e:
        if "Forbidden" in str(e):
            return_results("Authorization Error: make sure API Key is correctly set")
        else:
            raise e

def binalyze_get_drone_analyzers(api_token,args,params):
    url=params.get("url")+"/api/public/params/drone/analyzers"
    headers = {
            'Authorization': api_token,
            'User-Agent': 'Binalyze AIR',
            'Content-type': 'application/json',
            'Accept-Charset': 'UTF-8'
            }

    response = requests.get(url, headers=headers,verify=False)
    drone_analyzers={"binalyze_drone_analyzers":response.json()}
    result=CommandResults(outputs=drone_analyzers)
    return_results(result)

def main():
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()
    api_token = params.get("credentials")

    try:
        if command=="test-module":
            test_module(api_token,args,params)
        elif command=="binalyze-get-assets":
            binalyze_get_assets(api_token,args,params)
        elif command=="binalyze-get-drone-analyzers":
            binalyze_get_drone_analyzers(api_token,args,params)
        elif command=="binalyze-get-tasks":
            binalyze_get_tasks(api_token,args,params)
        elif command=="binalyze-get-acquisition-profiles":
            binalyze_get_acquisition_profiles(api_token,args,params)
        elif command=="binalyze-start-acquisition-webhook":
            binalyze_start_acquisition_webhook(api_token,args,params)
        elif command=="binalyze-assign-triage-task-by-filter":
            binalyze_assign_triage_task_by_filter(api_token,args,params)
        elif command=="binalyze-get-users":
            binalyze_get_users(api_token,args,params)
        elif command=="binalyze-create-case":
            binalyze_create_case(api_token,args,params)
        elif command=="binalyze-get-cases":
            binalyze_get_cases(api_token,args,params)
        elif command=="binalyze-get-triage-rules":
            binalyze_get_triage_rules(api_token,args,params)
        elif command=="binalyze-assign-evidence-acquisition":
            binalyze_assign_evidence_acquisition(api_token,args,params)
        elif command=="binalyze-assign-shutdown-task":
            binalyze_assign_shutdown_task(api_token,args,params)
        elif command=="binalyze-assign-isolation-task":
            binalyze_assign_isolation_task(api_token,args,params)
        elif command=="binalyze-assign-log-retrieval-task":
            binalyze_assign_log_retrieval_task(api_token,args,params)
        elif command=="binalyze-assign-version-update-task":
            binalyze_assign_version_update_task(api_token,args,params)
        elif command=="binalyze-assign-reboot-task":
            binalyze_assign_reboot_task(api_token,args,params)
        elif command=="binalyze-assign-image-acquisition-task":
            binalyze_assign_image_acquisition_task(api_token,args,params)
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
