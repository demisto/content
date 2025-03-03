import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import json
import time
import re
from xml.dom.minidom import Node, Document, parseString
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
AUTH = ('super/' + USERNAME, PASSWORD)
VERIFY_SSL = not demisto.params().get('unsecure', False)
HOST = demisto.params()['host']
QUERY_URL = HOST + "/phoenix/rest/query/"
REST_ADDRESS = HOST + "/phoenix/rest/h5"

EXTENDED_KEYS = {}  # type: dict


def load_extended_keys():
    global EXTENDED_KEYS
    if demisto.command() == 'fetch-incidents':
        last_run = demisto.getLastRun()
        EXTENDED_KEYS = last_run.get('extended_keys', {})
    else:
        integration_context = demisto.getIntegrationContext()
        EXTENDED_KEYS = integration_context.get('extended_keys', {})

    if not EXTENDED_KEYS:
        session = login()
        url = REST_ADDRESS + '/eventAttributeType/all'
        response = session.get(url, verify=VERIFY_SSL, auth=AUTH)
        EXTENDED_KEYS = {attr['attributeId']: attr['displayName'] for attr in response.json()}

        if demisto.command() != 'fetch-incidents':
            demisto.setIntegrationContext({'extended_keys': EXTENDED_KEYS})


def parse_resource_type(resource_type):
    type_to_url_path = {
        'Reports': 'report',
        'Rules': 'rule',
        'Networks': 'resource/network',
        'Watch Lists': 'rule/wl',
        'Protocols': 'resource/port',
        'Event Type': 'eventType',
        'Malware IP': 'mal/ip',
        'Malware Domains': 'mal/site',
        'Malware Urls': 'mal/url',
        'Malware Hash': 'mal/hash',
        'Malware Processes': 'mal/proc',
        'Country Groups': 'resource/geo',
        'Default Password': 'mal/pwd',
        'Anonymity Network': 'mal/proxy',
        'User Agents': 'mal/agent',
        'Remediations': 'remediation',
    }
    return type_to_url_path.get(resource_type, resource_type)


@logger
def validateSuccessfulResponse(resp, error_text):
    if resp.status_code != 200:
        return_error(f'Got response status {resp.status_code} when {error_text}')


@logger
def login():
    session = requests.session()
    login_url = HOST + '/phoenix/login-html.jsf'

    response = session.get(login_url, verify=VERIFY_SSL)

    # get the VIEW_STATE from the xml returned in the UI login page.
    p = re.compile('(value=".{1046}==")')
    viewState = p.findall(response.text.encode('utf-8'))  # type: ignore[arg-type, call-overload]
    VIEW_STATE = viewState[0][len('value="'):][:-1]

    data = {
        'loginHtml': 'loginHtml',
        'loginHtml:username': USERNAME,
        'loginHtml:password': PASSWORD,
        'loginHtml:userDomain': 'Empty',
        'loginHtml:loginBtn': 'Log In',
        'loginHtml:domain': 'super',
        'javax.faces.ViewState': VIEW_STATE
    }

    headers = {
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9,pt-PT;q=0.8,pt;q=0.7'
    }

    response = session.post(login_url, headers=headers, data=data, verify=VERIFY_SSL)  # type: ignore
    return session


def clear_incident_command():
    args = demisto.args()
    incident_id = args['incident_id']
    reason = args.get('close_reason', '')

    raw_response = clear_incident(incident_id, reason)
    return_outputs("Incident cleared successfully.", {}, raw_response)


@logger
def clear_incident(incident_id, reason):
    session = login()
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json'
    }
    response = session.put(
        HOST + '/phoenix/rest/h5/incident/clear',
        params={'ids': [incident_id], 'user': USERNAME},
        headers=headers,
        data=reason,
        verify=VERIFY_SSL)
    validateSuccessfulResponse(response, "triggering events report")

    return response.text


@logger
def getEventsByIncident(incident_id, max_results, extended_data, max_wait_time):
    session = login()
    # response = session.get(HOST + '/phoenix/rest/h5/report/triggerEvent?rawMsg=' + incident_id)
    # validateSuccessfulResponse(response, "triggering events report")
    #
    # try:
    #     jsonRes = response.json()
    #     queryData = jsonRes[0]['right']
    # except (ValueError, KeyError):
    #     return_error("Got wrong response format when triggering events report. "
    #                  "Expected a json array but got:\n" + response.text)

    queryData = {
        "isReportService": True,
        "selectClause": "eventSeverityCat,incidentLastSeen,eventName,incidentRptDevName,incidentSrc,incidentTarget,"
                        "incidentDetail,incidentStatus,incidentReso,incidentId,eventType,incidentTicketStatus,"
                        "bizService,count,incidentClearedTime,incidentTicketUser,incidentNotiRecipients,"
                        "incidentClearedReason,incidentComments,eventSeverity,incidentFirstSeen,incidentRptIp,"
                        "incidentTicketId,customer,incidentNotiStatus,incidentClearedUser,incidentExtUser,"
                        "incidentExtClearedTime,incidentExtResoTime,incidentExtTicketId,incidentExtTicketState,"
                        "incidentExtTicketType,incidentViewStatus,rawEventMsg,phIncidentCategory,phSubIncidentCategory,"
                        "incidentRptDevStatus",
        "eventFilters": [{"name": "Filter_OVERALL_STATUS",
                          "singleConstraint": f"(phEventCategory = 1) AND incidentId = {incident_id}"}],
        "hints": "IgnoreTime",
    }

    return getEventsByQuery(session, queryData, max_results, extended_data, max_wait_time,
                            "FortiSIEM events for Incident " + incident_id, incident_id=incident_id)


@logger
def getEventsByQuery(session, queryData, max_results, extended_data, max_wait_time, tableTitle, incident_id=None):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json'
    }

    response = session.post(REST_ADDRESS + '/report/run', headers=headers, data=json.dumps(queryData),
                            verify=VERIFY_SSL)
    validateSuccessfulResponse(response, "running report")

    data = response.json()
    data["report"] = queryData
    data = json.dumps(data)

    # poll until report progress reaches 100
    response = session.post(REST_ADDRESS + '/report/reportProgress', headers=headers, data=data, verify=VERIFY_SSL)

    # response contain the percentage of the report loading
    while response.text != "100" and max_wait_time > 0:
        response = session.post(REST_ADDRESS + '/report/reportProgress', headers=headers, data=data, verify=VERIFY_SSL)
        max_wait_time = int(max_wait_time) - 1
        time.sleep(1)

    params = {
        'start': 0,
        'perPage': max_results,
        'allData': extended_data,
    }

    response = session.post(REST_ADDRESS + '/report/resultByReport', params=params, headers=headers, data=data,
                            verify=VERIFY_SSL)

    try:
        res = response.json()
        eventKeys = res["headerData"]["columnNames"]
    except (ValueError, KeyError):
        return_error("Got wrong response format when getting report results. "
                     "Expected a json object but got:\n" + response.text)

    # reformat results
    eventData = []
    md = ""
    for key in res["lightValueObjects"]:
        cur = {
            'Event ID': key.get("naturalId", ""),
            'Incident ID': incident_id,
        }
        for i in range(0, len(eventKeys)):
            if len(key["data"]) == 0 or key["data"][0] == "No report results found.":
                md = "No report results found."
                break
            else:  # noqa: RET508
                cur[eventKeys[i]] = key["data"][i]
        if md != "":
            # no results were found, not need to loop
            break
        cur["ExtendedData"] = {}
        for extItem in key["extData"]:
            if EXTENDED_KEYS.get(extItem["left"]) is not None:
                cur[EXTENDED_KEYS.get(extItem["left"]).replace(' ', '')] = extItem["right"]  # type: ignore
            else:
                cur["ExtendedData"][extItem["left"]] = extItem["right"]
        eventData.append(cur)
    md = tableToMarkdown(tableTitle, eventData, eventKeys) if md == "" else md

    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {'FortiSIEM.Events(val["Event ID"] && val["Event ID"] == obj["Event ID"])': eventData}
    })


@logger
def GetEventQuery():
    in_xml = create_query_xml("all", interval='1')
    url = QUERY_URL + "eventQuery"
    headers = {'Content-Type': 'text/xml'}
    resp = requests.request('POST', url, headers=headers, data=in_xml, verify=VERIFY_SSL, auth=AUTH)
    validateSuccessfulResponse(resp, "fetching event query")
    queryId = resp.text
    if 'error code="255"' in queryId:
        return_error("Got error code 255 while getting event query. Make sure the query has valid syntax")

    return queryId


@logger
def GetIncidentsByOrg(queryId):
    # The request will poll until the server completes the query.
    url = QUERY_URL + "progress/" + queryId
    resp = requests.request('GET', url, verify=VERIFY_SSL, auth=AUTH)

    while resp.text != '100':
        resp = requests.request('GET', url, verify=VERIFY_SSL, auth=AUTH)

    outXML = []
    if resp.text == '100':
        url = QUERY_URL + 'events/' + queryId + '/0/1000'
        resp = requests.request('GET', url, verify=VERIFY_SSL, auth=AUTH)
        content = resp.text
        if content != '':
            outXML.append(content)

        # this code is taken directly from their documentation.
        # get all results (last "page" has less than 1000 records)
        p = re.compile(r'totalCount="\d+"')
        mlist = p.findall(content)
        if mlist and mlist[0] != '':
            mm = mlist[0].replace('"', '')
            m = int(mm.split("=")[-1])
            num = 0
            if m > 1000:
                num = int(m / 1000)
                if m % 1000 > 0:
                    num += 1
            if num > 0:
                for i in range(num):
                    url = QUERY_URL + 'events/' + queryId + '/' + str(i * 1000 + 1) + '/1000'
                    resp = requests.request('GET', url, verify=VERIFY_SSL, auth=AUTH)
                    content = resp.text
                    if content != '':
                        outXML.append(content)
        else:
            sys.exit(0)
    phCustId = "all"
    param = dumpXML(outXML, phCustId)
    return param


@logger
def create_query_xml(include_value, interval="", single_evt_value="phEventCategory=1", interval_type="Minute",
                     attr_list=None, limit="All"):
    doc = Document()
    reports = doc.createElement("Reports")
    doc.appendChild(reports)
    report = doc.createElement("Report")
    report.setAttribute("id", "")
    report.setAttribute("group", "report")
    reports.appendChild(report)
    name = doc.createElement("Name")
    report.appendChild(name)
    doc.createTextNode("All Incidents")
    custScope = doc.createElement("CustomerScope")
    custScope.setAttribute("groupByEachCustomer", "true")
    report.appendChild(custScope)
    include = doc.createElement("Include")
    if include_value == "all":
        include.setAttribute("all", "true")
        custScope.appendChild(include)
    else:
        custScope.appendChild(include)
        include_text = doc.createTextNode(include_value)
        include.appendChild(include_text)
    exclude = doc.createElement("Exclude")
    custScope.appendChild(exclude)
    description = doc.createElement("description")
    report.appendChild(description)
    select = doc.createElement("SelectClause")
    select.setAttribute("numEntries", limit)
    report.appendChild(select)
    attrList = doc.createElement("AttrList")
    if attr_list:
        attr_text = doc.createTextNode(str(attr_list))
        attrList.appendChild(attr_text)
    select.appendChild(attrList)
    reportInterval = doc.createElement("ReportInterval")
    report.appendChild(reportInterval)
    window = doc.createElement("Window")
    window.setAttribute("unit", interval_type)
    window.setAttribute("val", interval)
    reportInterval.appendChild(window)
    pattern = doc.createElement("PatternClause")
    pattern.setAttribute("window", "3600")
    report.appendChild(pattern)
    subPattern = doc.createElement("SubPattern")
    subPattern.setAttribute("displayName", "Events")
    subPattern.setAttribute("name", "Events")
    pattern.appendChild(subPattern)
    single = doc.createElement("SingleEvtConstr")
    subPattern.appendChild(single)
    single_text = doc.createTextNode(single_evt_value)
    single.appendChild(single_text)
    _filter = doc.createElement("RelevantFilterAttr")
    report.appendChild(_filter)
    return doc.toxml()


@logger
def dumpXML(xmlList, phCustId):
    param = []
    for xml in xmlList:
        doc = parseString(xml.encode('utf-8'))
        for node in doc.getElementsByTagName("events"):
            for node1 in node.getElementsByTagName("event"):
                mapping = {}
                for node2 in node1.getElementsByTagName("attributes"):
                    for node3 in node2.getElementsByTagName("attribute"):
                        item_name = node3.getAttribute("name")
                        for node4 in node3.childNodes:
                            if node4.nodeType == Node.TEXT_NODE:
                                mapping[item_name] = node4.data
                    if phCustId == "all" or mapping['phCustId'] == phCustId:
                        param.append(mapping)
    return param


@logger
def buildQueryString(args):
    res_list = []
    for key in args:
        if 'IpAddr' not in key:
            res_list.append(f'{key} = "{args[key]}"')
        else:
            res_list.append(f"{key} = {args[key]}")
    return " AND ".join(res_list)


@logger
def getEventsByFilter(maxResults, extendedData, maxWaitTime, reportWindow, reportWindowUnit):
    session = login()

    args = demisto.args()
    del args["maxResults"]
    del args["extendedData"]
    del args["maxWaitTime"]
    del args["reportWindow"]
    del args["reportWindowUnit"]

    query_string = buildQueryString(args)
    query_data = {
        "isReportService": True,
        "selectClause": "phRecvTime,reptDevIpAddr,eventType,eventName,rawEventMsg,destIpAddr",
        "reportWindow": int(reportWindow),
        "reportWindowUnit": reportWindowUnit,
        "timeRangeRelative": True,
        "eventFilters": [{
            "groupBy": "",
            "singleConstraint": query_string
        }],
        "custId": 1
    }
    return getEventsByQuery(
        session,
        query_data,
        maxResults,
        extendedData,
        maxWaitTime,
        "FortiSIEM Event Results")


def parse_cmdb_list(cmdb_device):
    device_dict = {
        'DiscoverMethod': cmdb_device.get('discoverMethod', 'N/A'),
        'Approved': cmdb_device.get('approved', 'false'),
        'CreationMethod': cmdb_device.get('creationMethod', 'N/A'),
        'AccessIp': cmdb_device.get('accessIp', 'N/A'),
        'Name': cmdb_device.get('name', 'N/A'),
        'WinMachineGuid': cmdb_device.get('winMachineGuid', 'N/A'),
        'Unmanaged': cmdb_device.get('unmanaged', 'false'),
        'Version': cmdb_device.get('version', 'N/A'),
        'UpdateMethod': cmdb_device.get('updateMethod', 'N/A'),
    }
    timestamp = cmdb_device.get('discoverTime', None)

    if timestamp and timestamp.isdigit():
        device_dict['DiscoverTime'] = timestamp_to_datestring(timestamp)
    elif timestamp:
        device_dict['DiscoverTime'] = timestamp
    else:
        device_dict['DiscoverTime'] = 'N/A'

    device_type = cmdb_device.get('deviceType')
    if device_type:
        device_dict['DeviceType'] = "{} {}".format(device_type['model'], device_type['vendor'])
    else:
        device_dict['DeviceType'] = 'N/A'

    return device_dict


def get_cmdb_devices_command():
    args = demisto.args()
    device_ip = args.get('device_ip')
    limit = int(args.get('limit'))

    raw_response = get_cmdb_devices(device_ip, limit)
    list_of_devices = list(map(parse_cmdb_list, raw_response))

    return_outputs(
        tableToMarkdown("Devices", list_of_devices),
        {'FortiSIEM.CmdbDevices': list_of_devices},
        raw_response
    )


@logger
def get_cmdb_devices(device_ip=None, limit=100):
    cmdb_url = HOST + "/phoenix/rest/cmdbDeviceInfo/devices"

    if device_ip:
        cmdb_url += "?includeIps=" + device_ip

    response = requests.get(cmdb_url, verify=VERIFY_SSL, auth=AUTH)
    list_of_devices = json.loads(xml2json(response.text))

    if 'response' in list_of_devices:
        return_error(list_of_devices["response"]["error"]["description"])
    elif 'devices' in list_of_devices:
        list_of_devices = list_of_devices['devices']['device']
    elif 'device' in list_of_devices:
        list_of_devices = [list_of_devices['device']]

    return list_of_devices[:limit]


@logger
def get_events_by_query(query, report_window="60", interval_type="Minute", limit="20", extended_data='false',
                        max_wait_time=60):
    session = login()

    query_data = {
        "isReportService": True,
        "selectClause": "phRecvTime,reptDevIpAddr,eventType,eventName,rawEventMsg,destIpAddr",
        "reportWindow": int(report_window),
        "reportWindowUnit": interval_type,
        "timeRangeRelative": True,
        "eventFilters": [{
            "groupBy": "",
            "singleConstraint": query
        }],
        "custId": 1
    }
    return getEventsByQuery(
        session,
        query_data,
        limit,
        extended_data,
        max_wait_time,
        "FortiSIEM Event Results")


def get_lists_command():
    raw_resources = get_lists()

    resources = []
    for r in flatten_resources(raw_resources):
        resources.append({
            'DisplayName': r['displayName'],
            'NatualID': r['naturalId'],
            'ID': r['id'],
            'ResourceType': r['groupType']['displayName'],
            'Children': [c['displayName'] for c in r['children']],
        })

    return_outputs(
        tableToMarkdown('Lists:', resources, removeNull=True),
        {'FortiSIEM.ResourceList(val.ID && val.ID == obj.ID)': resources},
        raw_response=raw_resources)


@logger
def get_lists():
    session = login()
    url = REST_ADDRESS + '/group/resource'
    response = session.get(url, verify=VERIFY_SSL, auth=AUTH)

    return response.json()


def flatten_resources(raw_resources):
    for r in raw_resources:
        yield r
        # possible stackoverflow
        for sub_resource in flatten_resources(r['children']):
            yield sub_resource


def add_item_to_resource_list_command():
    args = demisto.args()
    resource_type = parse_resource_type(args['resource_type'])
    group_id = args['group_id']
    object_info = args.get('object-info', [])
    object_info = dict(object_property.strip().split('=', 1) for object_property in object_info.split(','))

    raw_response = add_item_to_resource_list(resource_type, group_id, object_info)
    outputs = {'FortiSIEM.Resource(val.id && val.id == obj.id)': createContext(raw_response, removeNull=True)}

    return_outputs(tableToMarkdown('Resource was added:', raw_response, removeNull=True), outputs, raw_response)


@logger
def add_item_to_resource_list(resource_type, group_id, object_info):
    session = login()
    url = f'{REST_ADDRESS}/{resource_type}/save'
    object_info['groupId'] = group_id
    object_info['active'] = True
    object_info['sysDefined'] = False

    response = session.post(url, data=json.dumps(object_info), verify=VERIFY_SSL, auth=AUTH)
    response = response.json()

    if response.get('code', 0) == -1:
        return_error(response['msg'])

    return response


def remove_item_from_resource_list_command():
    args = demisto.args()
    resource_type = parse_resource_type(args['resource_type'])
    deleted_ids = args.get('ids', '').split(',')

    raw_response = remove_item_from_resource_list(resource_type, deleted_ids)

    return_outputs(raw_response, {}, raw_response=raw_response)


@logger
def remove_item_from_resource_list(resource_type, deleted_ids):
    session = login()
    url = f'{REST_ADDRESS}/{resource_type}/del'

    response = session.delete(url, params={'ids': json.dumps(deleted_ids)}, verify=VERIFY_SSL, auth=AUTH)

    if response.text != '"OK"':
        return_error(response.text)

    return f'items with id {deleted_ids} were removed.'


def get_resource_list_command():
    args = demisto.args()
    resource_type = parse_resource_type(args['resource_type'])
    group_id = args['group_id']

    raw_response = get_resource_list(resource_type, group_id)
    headers = raw_response.get('headerData', {}).get('keys', [])
    ec = []
    for element in raw_response.get('lightValueObjects', []):
        e = dict(zip(headers, element.get('data', [])))
        e['id'] = element.get('objectId')
        ec.append(e)
    outputs = {'FortiSIEM.Resource(val.id && val.id == obj.id)': createContext(ec, removeNull=True)}

    return_outputs(tableToMarkdown('Resource list:', ec, headerTransform=pascalToSpace, removeNull=True),
                   outputs,
                   raw_response)


@logger
def get_resource_list(resource_type, group_id):
    session = login()
    url = f'{REST_ADDRESS}/{resource_type}/list'

    params = {
        'groupId': group_id,
        'start': 0,
        'size': 50,
    }

    response = session.get(url, params=params, verify=VERIFY_SSL, auth=AUTH)
    response = response.json()

    if response.get('code', 0) == -1:
        return_error(response['msg'])

    return response


def convert_keys_to_snake_case(d):
    d = {k.replace("-", "_"): v for k, v in d.items()}
    return d


def test():
    try:
        login()
    except Exception as e:
        if isinstance(e, requests.exceptions.SSLError):
            demisto.results("Not verified certificate")
        else:
            demisto.results(str(e))
    demisto.results('ok')


def fetch_incidents():
    query_id = GetEventQuery()
    res = GetIncidentsByOrg(query_id)
    known_ids = demisto.getLastRun().get('ids', None)
    if known_ids is None or not known_ids:
        known_ids = []

    incidents = []
    for inc in res:
        if inc.get('incidentId') not in known_ids:
            incidents.append({"name": inc.get('eventName', 'New FortiSIEM Event'), "rawJSON": json.dumps(inc)})
            if len(known_ids) >= 1000:
                known_ids.pop(0)
            known_ids.append(inc.get('incidentId'))

    demisto.setLastRun({
        'ids': known_ids,
        'extended_keys': EXTENDED_KEYS
    })
    demisto.incidents(incidents)
    sys.exit(0)


def main():
    try:
        handle_proxy()
        load_extended_keys()
        if demisto.command() == 'test-module':
            test()

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()

        elif demisto.command() == 'fortisiem-get-events-by-incident':
            args = demisto.args()
            getEventsByIncident(args['incID'], args['maxResults'], args['extendedData'], args['maxWaitTime'])

        elif demisto.command() == 'fortisiem-clear-incident':
            clear_incident_command()

        elif demisto.command() == 'fortisiem-get-events-by-filter':
            args = demisto.args()
            getEventsByFilter(args['maxResults'], args['extendedData'], args['maxWaitTime'], args['reportWindow'],
                              args['reportWindowUnit'])

        elif demisto.command() == 'fortisiem-get-events-by-query':
            args = convert_keys_to_snake_case(demisto.args())
            get_events_by_query(**args)

        elif demisto.command() == 'fortisiem-get-cmdb-devices':
            get_cmdb_devices_command()

        elif demisto.command() == 'fortisiem-get-lists':
            get_lists_command()

        elif demisto.command() == 'fortisiem-add-item-to-resource-list':
            add_item_to_resource_list_command()

        elif demisto.command() == 'fortisiem-remove-item-from-resource-list':
            remove_item_from_resource_list_command()

        elif demisto.command() == 'fortisiem-get-resource-list':
            get_resource_list_command()

    except Exception as e:
        if demisto.command() == 'fetch-incidents':
            LOG(str(e))
            LOG.print_log()
            raise
        else:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
