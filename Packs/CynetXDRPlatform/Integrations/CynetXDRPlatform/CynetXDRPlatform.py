import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# type: ignore

''' GLOBALS/PARAMS '''
CYNET_URL = demisto.params().get('url')
CYNET_PORT = demisto.params().get('port')
user_name = demisto.params().get('user_name')
CYNET_password = demisto.params().get('password')
USE_SSL = not demisto.params().get('insecure')
proxies = handle_proxy()  # type: ignore
args = demisto.args()


def get_hosts(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/hosts"
    querystring = {"LastSeen": args['LastSeen']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    # print(response1.text)
    hosts = response1.json()
    Entities = hosts['Entities']
    # print(Entities)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': hosts,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': hosts,
    })

    res = []
    for x in Entities:
        # print(x)
        res.append({
            "Hostname": x['HostName'],
            "ClientDbId": x['ClientDbId'],
            "HDSerial": x['HDSerial'],
            "LastIp": x['LastIp'],
            "RiskLevel": x['RiskLevel'],
            "LastScan": x['LastScan'],
            "DateIn": x['DateIn'],
            "OperatingSystem": x['OperatingSystem'],
            "LastUpdate": x['LastUpdate'],
            "EpsVersion": x['EpsVersion'],
            "UsersPath": x['UsersPath'],
        })

    demisto.results({
        'ContentsFormat': formats['table'],
        'Type': entryTypes['note'],
        'Contents': res
    })


def get_host_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/host"
    querystring = {"name": args['hostname']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    # print(response1.text)
    host_details = response1.json()

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': host_details,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': host_details,
    })


def get_host_full_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/full/host"
    querystring = {"name": args['hostname']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    # print(response1.text)
    host_full_details = response1.json()

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': host_full_details,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': host_full_details,
    })


def get_missing_windows_patches_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/va/patches/missing"
    querystring = {"fromDate": args['fromDate']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    missing_patches = response1.json()
    my_list = ["list"]
    res = {key: [] for key in my_list}

    for x in missing_patches:
        # print(x)
        res['list'].append(x)

    # print(res)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': res,
    })


def get_existing_windows_patches_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/va/patches/existing"
    querystring = {"fromDate": args['fromDate']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    existing_patches = response1.json()
    my_list = ["list"]
    res = {key: [] for key in my_list}

    for x in existing_patches:
        # print(x)
        res['list'].append(x)

    # print(res)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': res,
    })


def get_risky_application_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/va/riskyApps"
    querystring = {"fromDate": args['fromDate']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    risky_app = response1.json()
    my_list = ["list"]
    res = {key: [] for key in my_list}

    for x in risky_app:
        # print(x)
        res['list'].append(x)

    # print(res)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': res,
    })


def get_installed_softwares_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/va/installedSoftwares"
    querystring = {"fromDate": args['fromDate']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    installed_app = response1.json()
    my_list = ["list"]
    res = {key: [] for key in my_list}

    for x in installed_app:
        # print(x)
        res['list'].append(x)

    # print(res)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': res,
    })


def get_outdates_application_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/va/patchValidation"
    querystring = {"fromDate": args['fromDate']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    outdates_app = response1.json()
    my_list = ["list"]
    res = {key: [] for key in my_list}

    for x in outdates_app:
        # print(x)
        res['list'].append(x)

    # print(res)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': res,
    })


def get_agent_validation_details(api_token):
    url = CYNET_URL + ":" + CYNET_PORT + "/api/va/Agents"
    querystring = {"fromDate": args['fromDate']}

    payload = ""
    headers = api_token

    response1 = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=USE_SSL)

    agents = response1.json()
    my_list = ["list"]
    res = {key: [] for key in my_list}

    for x in agents:
        # print(x)
        res['list'].append(x)

    # print(res)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': res,
    })


def main():
    command = demisto.command()
    import requests
    url = CYNET_URL + ":" + CYNET_PORT + "/api/account/token"

    payload = {
        "user_name": user_name,
        "password": CYNET_password
    }
    headers = {
        "user_name": user_name,
        "password": CYNET_password,
        "Content-Type": "application/json"
    }

    response = requests.request("POST", url, json=payload, headers=headers, verify=USE_SSL)

    # print(response.text)
    api_token = response.json()

    try:
        if command == 'test-module':
            test()
        elif command == 'cynet-get-hosts':
            get_hosts(api_token)
        elif command == 'cynet-get-host-details':
            get_host_details(api_token)
        elif command == 'cynet-get-host-full-details':
            get_host_full_details(api_token)
        elif command == 'cynet-get-missing-windows-patches-details':
            get_missing_windows_patches_details(api_token)
        elif command == 'cynet-get-existing-windows-patches-details':
            get_existing_windows_patches_details(api_token)
        elif command == 'cynet-get-risky-application-details':
            get_risky_application_details(api_token)
        elif command == 'cynet-get-installed-softwares-details':
            get_installed_softwares_details(api_token)
        elif command == 'cynet-get-outdates-application-details':
            get_outdates_application_details(api_token)
        elif command == 'cynet-get-agent-validation-details':
            get_agent_validation_details(api_token)
    except Exception as e:
        error_message = str(e)
        return_error(error_message)


if __name__ in ('__main__', 'builtins'):
    main()
