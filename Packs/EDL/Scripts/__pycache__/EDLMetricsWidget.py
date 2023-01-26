import requests
import traceback
from requests.auth import HTTPBasicAuth
from datetime import date
from CommonServerPython import *


def get_edl(instance_name):

    url = str(DemistoException.args()['server_url'])
    if 'https://' not in url:
        url = 'https://' + url
    port = demisto.args()['edl_port']
    if port == "None":
        url = url + '/instance/execute/' +instance_name
        endpoint = str(url)
    else:
        endpoint = str(url) + ':' + port

    params = demisto.params()
    credentials = params.get('credentials') if params.get('credentials') else {}
    usern: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    if (usern and not password) or (password and not usern):
        err_msg: str = 'If using credentials, both username and password should be provided.'
        demisto.debug(err_msg)
        raise DemistoException(err_msg)

    payload = {}
    headers = {}
    verify_ssl = demisto.args()['verify_ssl']
    if eval(verify_ssl) is False:
        try:
            # ssl._create_default_https_context = ssl._create_unverified_context
            response = requests.get(endpoint, verify=False, auth=HTTPBasicAuth(username, password))
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
    else:
        response = requests.request("GET", endpoint, headers=headers, data=payload, auth=HTTPBasicAuth(username, password))
    return response.text


def record_edl_log(edl_name, edl_length):
    check_exists = demisto.executeCommand("getList", {"listName": "EDLMetrics_Size"})
    existing_list = check_exists[0]['HumanReadable']
    result = {
        "name": str(date.today()),
        "data": str(edl_length),
        "groups": {
            "name": str(edl_name),
            "data": str(edl_length)
        }
    }
    if existing_list is None:
        demisto.executeCommand("createList", {"listName": "EDLMetrics_Size", "listData": (json.dumps(result) + ';')})
    else:
        demisto.executeCommand("addToList", {"listName": "EDLMetrics_Size", "listData": (json.dumps(result) + ';')})


def build_widget():
    str_entries = demisto.executeCommand("getList", {"listName": "EDLMetrics_Size"})[0]['Contents']
    entries = str_entries.split(';,')
    entries[-1] = entries[-1].rstrip(';')
    builder = []
    for entry in entries:
        entry = json.loads(entry)
        date = entry['name']
        total = int(entry['data'])
        if len(builder) == 0:
            group_name = entry['groups']['name']
            group_total = int(entry['groups']['data'])
            builder.append({"name": date, "data": [total], "groups": [{"name": group_name, "data": [group_total]}]})
        else:
            found = False
            for b in builder:
                builder_total = int(b['data'][0])
                if b['name'] == date:
                    entry_count = int(entry['groups']['data'])
                    builder_total = builder_total + entry_count
                    b['data'] = [builder_total]
                    b['groups'].append({"name": entry['groups']['name'], "data": [int(entry['groups']['data'])]})
                    found = True
            if found is False:
                builder.append({"name": date, "data": [total], "groups": [{"name": str(entry['groups']['name']), "data": [int(entry['groups']['data'])]}]})
    return builder


def main():
    try:
        instances = demisto.executeCommand("GetInstanceName", {
            "integration_name": "EDL", "return_all_instances": "True"
        })[0]['Contents']
        for instance in instances:
            edl_name = instance['instanceName']
            edl_exclusions = demisto.args()['edl_exclusions'].split(',')
            if edl_exclusions is None or edl_name not in edl_exclusions:
                edl = get_edl(edl_name)
                edl_length = len(edl)
                record_edl_log(edl_name, edl_length)
        demisto.results(json.dumps(build_widget()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
