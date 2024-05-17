import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import requests

# Defining global variables
layouts = []
classifier = []
incoming_mapper = []
outgoing_mapper = []
incident_types = []
incident_fields = []
playbooks = []
automations = []
ignore_playbook = []
ignore_sub = []
auto_script = {}
configuration = None
autodata = False


def create_context(data, args):
    """
    This function accepts the raw data and creates new dict based on the values
    in args.

    Args:
    data: raw data to be filtered (can be list or dict)
    args: list of items to fetch from raw data

    Returns:
    list/dict : filtered data from the raw data

    """

    if isinstance(data, list):
        return [create_context(data_item, args) for data_item in data]

    filtered_data = {}
    for arg in args:
        filtered_data[arg] = data.get(arg)
    return filtered_data


def merge_data(instance, configuration):
    """
    This function accepts the integration instance and configuration data and populated the required fields into instance data

    Args:
    instance: integraiton instance data (can be list or dict)
    configuration: integration configuration data

    """

    for ins_data in instance:
        ins_data["incident_type"] = ins_data["configvalues"].get("incidentType")
        del ins_data["configvalues"]
        ins_data["instance_id"] = ins_data.pop("id")
        ins_data["instance_name"] = ins_data.pop("name")
        for conf_data in configuration:
            if ins_data["brand"] in (conf_data["id"], conf_data["name"]):
                ins_data.update(conf_data)
                break


def separate_classfier_mapper(data):
    """
    This function accepts the raw data and filters out classifer and mappers from it.

    Args:
    data: raw data to be filtered (can be list or dict)

    Returns:
    list : classifier data list
    list: incoming mapper data list
    list: outgoing mapper data list

    """

    c = []
    i_m = []
    o_m = []

    for data_item in data:
        if data_item["type"] == "mapping-outgoing":
            o_m.append(data_item)
        elif data_item["type"] == "mapping-incoming":
            i_m.append(data_item)
        else:
            c.append(data_item)
    return c, i_m, o_m


def post_api_request(url, body):
    """Post API request.

    Args:
        url (str): request url path
        body (Dict): integration command / script arguments

    Returns:
        Dict: dictionary representation of the response
    """
    api_args = {
        "uri": url,
        "body": body
    }
    raw_res = demisto.executeCommand("core-api-post", api_args)
    try:
        res = raw_res[0]['Contents']['response']
        return res
    except KeyError:
        return_error(f'API Request failed, no response from API call to {url}')
    except TypeError:
        return_error(f'API Request failed, failed to {raw_res}')


def get_api_request(url):
    """Get API request.

    Args:
        url (str): request url path

    Returns:
        Dict: dictionary representation of the response
    """
    api_args = {
        "uri": url
    }
    raw_res = demisto.executeCommand("core-api-get", api_args)
    # res = raw_res[0]
    # print("Response is", res)
    try:
        res = raw_res[0]['Contents']['response']
        # If it's a string and not an object response, means this command has failed.
        if type(res) is str:
            if autodata is True:
                return res
            return None
        return res
    except KeyError:
        return_error(f'API Request failed, no response from API call to {url}')


def get_all_incidents(days=60, size=1000):
    """Get all incidents from API request.

    Args:
        days (int): number of days. Defaults to 7.
        size (int): number of incidents. Defaults to 1000.

    Returns:
        Dict: incidents returned from the API request
    """
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": int(size),
            "query": "-category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": int(days)
            }
        }
    }

    r = post_api_request("/incidents/search", body)
    return r.get("data")

# def get_incident_data(days=30, size=1000):
#     layout_list = []
#     incident_layout = {
#         'Case Details': layout_list ,
#         'Evidence': None,
#         'Investigation': None,
#         'Indicator': None
#     }
#     body = {
#         "userFilter": False,
#         "filter": {
#             "page": 0,
#             "size": int(size),
#             "query": "-category:job",
#             "sort": [
#                 {
#                     "field": "id",
#                     "asc": False
#                 }
#             ],
#             "period": {
#                 "by": "day",
#                 "fromValue": int(days)
#             }
#         }
#     }
#     incident_data = post_api_request("/incidents/search", body).get("data")
#     g = post_api_request("/indicators/search", {})
#     f = post_api_request("/evidence/search", {"incidentID" : "6843"})
#     for i_d in incident_data:
#         case_value = {'name': None,
#             'id': None,
#             'occurred': None,
#             'type': None,
#             'severity': None,
#             'investigationId': None,
#             'playbookId': None,
#             'owner': None
#         }
#         # print(i_d)
#         case_value['name'] = i_d.get('name')
#         case_value['occurred'] = i_d.get('occurred')
#         case_value['id'] = i_d.get('id')
#         case_value['type'] = i_d.get('type')
#         case_value['severity'] = i_d.get('severity')
#         case_value['investigationId'] = i_d.get('investigationId')
#         case_value['details'] = i_d.get('details')
#         case_value['owner'] = i_d.get('owner')
#         case_value['playbookId'] = i_d.get('playbookId')
#         layout_list.append(case_value)
#     incident_layout['case details'] =
#     print(r.get("data"))
#     print("Indicator data", g)
#     for evidence in f.get("evidences"):
#         print(evidence)
#     print("INcident data is", incident_layout)
#     return r.get("data")


def get_open_incidents(days=7, size=1000):
    """Get open incidents from API.

    Args:
        days (int): number of days. Defaults to 7.
        size (int): number of incidents. Defaults to 1000.

    Returns:
        SingleFieldData: SingleFieldData object representing open incidents
    """
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": int(size),
            "query": "-status:closed -category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": int(days)
            }
        }
    }
    r = post_api_request("/incidents/search", body)
    return r


def get_closed_incidents(days=7, size=1000):
    """Get closed incidents from API.

    Args:
        days (int): number of days. Defaults to 7.
        size (int): number of incidents. Defaults to 1000.

    Returns:
        SingleFieldData: SingleFieldData object representing closed incidents
    """
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": int(size),
            "query": "status:closed -category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": int(days)
            }
        }
    }
    r = post_api_request("/incidents/search", body)
    return r


def get_enabled_integrations(max_request_size: int):
    """Retrieve all the running instances.

    Args:
        max_request_size (int): maximum number of instances to retrieve.

    Returns:
        SortedTableData: TableData object with the enabled instances.
    """
    r = post_api_request("/settings/integration/search", {"size": max_request_size})
    instances = r.get("instances")
    enabled_instances = []
    for instance in instances:
        if instance.get("enabled"):
            enabled_instances.append(instance)
    # print("INTEGRATIONS", r)
    return enabled_instances


def get_installed_packs():
    """Get all the installed Content Packs

    Returns:
        SortedTableData: TableData object with the installed Content Packs.
    """
    # if tis doesn't work, return nothing.
    r = get_api_request("/contentpacks/metadata/installed")
    if not r:
        return NoneTableData()
    else:
        return r


def get_custom_playbooks():
    resp = post_api_request("/playbook/search", {"query": "system:F AND hidden:F"}).get("playbooks")
    pb_names = [pb["name"] for pb in resp]
    return pb_names


def get_custom_reports():
    """
    Return all the custom reports installed in XSOAR.
    :return: TableData
    """
    # r = get_api_request("/report/6843/latest")
    r = get_api_request("/reports")
    reports = []
    for report in r:
        # Check it's not an inbuilt (system) report
        if not report.get("system"):
            reports.append(report)
    # print("Data for reports is", r)
    return reports


def get_custom_dashboards():
    """Return all the custom dashboards configured in XSOAR

    Returns:
        TableData: TableData object with the custom dashboards.
    """
    r = get_api_request("/dashboards")
    dashboards = []
    for dashboard in r.values():
        # Check it's not an inbuilt (system) dashboard
        if not dashboard.get("system"):
            dashboards.append(dashboard)
    return dashboards


def get_all_playbooks():
    """Return all the custom playbooks installed in XSOAR

    Returns:
        TableData: TableData object with the custom playbooks.
    """
    r = post_api_request("/playbook/search", {"query": "hidden:F"}).get("playbooks")
    for pb in r:
        pb["TotalTasks"] = len(pb.get("tasks", []))
    # print("all pb")
    # print(r)
    return r


def get_playbook_stats(playbooks, days=7, size=1000):
    """Pull all the incident types and associated playbooks,
    then join this with the incident stats to determine how often each playbook has been used.

    Args:
        playbooks (SortedTableData): TableData object with the custom playbooks.
        days (int, optional): max number of days. Defaults to 7.
        size (int, optional): max request size. Defaults to 1000.

    Returns:
        Dict: Dictionary of playbook stats.
    """
    # incident_types = get_api_request(DEMISTO_INCIDENT_TYPE_PATH)
    incidents = get_all_incidents(days, size)
    playbook_stats = {}
    for incident in incidents:
        playbook = incident.get("playbookId")
        if playbook not in playbook_stats:
            playbook_stats[playbook] = 0

        playbook_stats[playbook] = playbook_stats[playbook] + 1

    table = []
    for playbook, count in playbook_stats.items():
        # Try to join this with the playbooks we previously retrieved to populate
        # more info.
        playbook_data = playbooks.search("id", playbook)
        if playbook_data:
            table.append({
                "playbook": playbook_data.get("name"),
                "incidents": count
            })
        else:
            table.append({
                "playbook": playbook,
                "incidents": count
            })
    return table


def get_layouts():
    # d = []
    # final_data = []
    # items  = []
    # names = []
    # field_type = {}
    fields = ['description', 'details', 'detailsV2', 'group', 'id', 'modified', 'name', 'packID', 'packName', 'system']
    resp = get_api_request("/layouts")
    # print("Data in incident fields are", incident_fields)
    filtered_data = create_context(resp, fields)
    # for b in filtered_data:
    #     t = b.get('detailsV2')
    #     if t is not None:
    #         e = t.get("tabs")
    #         for test in e:
    #             if 'sections' in test.keys():
    #                 final_data = test.get("sections")
    #                 for l in final_data:
    #                     items = l.get('items')
    #                     if items is not None:
    #                         for j in items:
    #                             for a in incident_fields:
    #                                 if j.get("fieldId") == a.get('cliName'):
    #                                     if j.get("fieldId") not in field_type.keys():
    #                                         field_type[j.get("fieldId")] = a.get("type")
    # field_list.append(field_type)
    return filtered_data


def get_incident_types():
    fields = ['id', 'layout', 'modified', 'name', 'playbookId', 'system', 'packID', 'packName']
    resp = get_api_request("/incidenttype")
    filtered_data = create_context(resp, fields)
    return filtered_data


def get_incident_fields():
    # incident_field = []
    fields = ['associatedToAll', 'associatedTypes', 'cliName', 'description',
              'id', 'modified', 'name', 'type', 'system', 'locked', 'packID', 'packName']
    resp = get_api_request("/incidentfields")
    filtered_data = create_context(resp, fields)
    return filtered_data


def get_classifier_mapper():
    fields = ['description', 'id', 'modified', 'name', 'system', 'type',
              'defaultIncidentType', 'keyTypeMap', 'mapping', 'packID', 'packName']
    resp = post_api_request("/classifier/search", {}).get("classifiers")
    if resp:
        filtered_data = create_context(resp, fields)
        c, i_m, o_m = separate_classfier_mapper(filtered_data)
        return c, i_m, o_m
    else:
        return_error("No classifier and mapper data found.")


def get_playbooks():
    fields = ['commands', 'id', 'inputs', 'modified', 'name', 'outputs', 'packID', 'packName', 'tasks', 'system', 'comment']
    resp = post_api_request("/playbook/search", {"query": "hidden:F"}).get("playbooks")
    filtered_data = create_context(resp, fields)
    return filtered_data


def get_automations():
    global autod
    fields = ['arguments', 'comment', 'contextKeys', 'id', 'modified', 'name', 'system', 'tags', 'type']
    resp = post_api_request("/automation/search", {"query": "hidden:F"}).get("scripts")
    filtered_data = create_context(resp, fields)
    return filtered_data


def get_integrations():
    command_data = {}
    instance_fields = ['brand', 'category', 'id', 'incomingMapperId', 'isBuiltin', 'isSystemIntegration', 'mappingId', 'modified',
                       'name', 'outgoingMapperId', 'packID', 'packName', 'configvalues']
    configuration_fields = ['description', 'detailedDescription', 'display',
                            'id', 'name']  # if require script then add 'integrationScript'

    resp = post_api_request("/settings/integration/search", {})
    int_data = resp.get("configurations")
    for d in int_data:
        c = []
        command_value = {
            'id': None,
            'name': None,
            'display': None,
            'description': None,
            'commands': []
        }
        command_data[d['display']] = command_value
        if d is not None:
            a = d.get("integrationScript")
            if a is not None:
                comm = a.get("commands")
                if comm is not None:
                    for b in comm:
                        c.append(b.get("name"))
        command_value["id"] = d['id']
        command_value["name"] = d['name']
        command_value["display"] = d['display']
        command_value["description"] = d['description']
        command_value["commands"] = c
    instance_data = create_context(resp.get("instances"), instance_fields)
    configuration_data = create_context(resp.get("configurations"), configuration_fields)
    merge_data(instance_data, configuration_data)
    return instance_data, command_data


def get_playbook_data(playbook_name):
    for data_item in playbooks:
        if data_item["name"] == playbook_name:
            return dict(data_item)


def get_playbook_dependencies(playbook):
    pb_id = playbook["id"]
    body = {
        "items": [
            {
                "id": f"{pb_id}",
                "type": "playbook"
            }
        ],
        "dependencyLevel": "optional"
    }
    resp = post_api_request("/itemsdependencies", body).get("existing").get("playbook").get(pb_id)
    if not resp:
        print(f"Failed to retrieve dependencies for {pb_id}")

    dependencies = {
        "automation": [],
        "playbook": [],
        "integration": []
    }
    if resp:
        for resp_item in resp:
            if resp_item["type"] in dependencies:
                data = {
                    "name": resp_item["name"],
                    "system": resp_item["system"]
                }
                dependencies[resp_item["type"]].append(data)
    # print(type(json.dumps(dependencies["playbook"])))
    return dependencies


def get_playbook_automation(playbook, filter_auto):  # filter_auto
    # auto_name = []
    pb_automation = None
    # filter_auto = sub_data(playbook)[1]
    # print(filter_auto)
    # scripts = playbook["dependencies"]["automation"]
    if filter_auto:
        for script in filter_auto:
            # if not script["system"]:
            for automation_data in automations:
                if script in [automation_data["name"], automation_data["id"]] and not automation_data.get("system", False):
                    if not pb_automation:
                        pb_automation = {automation_data["name"]: dict(automation_data)}
                    else:
                        pb_automation[automation_data["name"]] = dict(automation_data)
                    break
    return pb_automation


def get_playbook_subplaybook(playbook, filter_play):
    pb_subplaybook = None
    test_d = []
    subplay_name = []
    # subplaybooks = playbook["dependencies"]["playbook"]
    if filter_play:
        # print("Subplaybooks:", subplaybooks)
        for subplaybook in filter_play:
            for pb in playbooks:
                if subplaybook in [pb["name"], pb["id"]] and not pb.get("system", False):
                    if not pb_subplaybook:
                        pb_subplaybook = {pb["name"]: dict(pb)}
                    else:
                        pb_subplaybook[pb["name"]] = dict(pb)
                    break
    return pb_subplaybook


def get_instance_classifier_incident_type(integration_instance, incident_types, classifiers):
    classifier_data = None
    incident_type_data = None

    if classifier_id := integration_instance["mappingId"]:
        for classifier in classifiers:
            if classifier_id == classifier["id"]:
                classifier_data = classifier
                classifier_incident_types = classifier["keyTypeMap"].values()
                for classifier_incident_type in classifier_incident_types:
                    for incident_type in incident_types:
                        if classifier_incident_type == incident_type["id"]:
                            if not incident_type_data:
                                incident_type_data = {incident_type["name"]: incident_type}
                            else:
                                incident_type_data[incident_type["name"]] = incident_type
                            break
                break

    elif inc_type_id := integration_instance["incident_type"]:
        for incident_type in incident_types:
            if inc_type_id == incident_type["id"]:
                incident_type_data = {incident_type["name"]: incident_type}
                break

    return classifier_data, incident_type_data


def get_instance_incoming_mapper(integration_instance, mappers):
    i_m = None
    if (mapper_id := integration_instance.get("incomingMapperId")):
        for mapper in mappers:
            if mapper["id"] == mapper_id:
                i_m = mapper
                break

    return i_m


def get_instance_outgoing_mapper(integration_instance, mappers):
    o_m = None
    if (mapper_id := integration_instance.get("outgoingMapperId")):
        for mapper in mappers:
            if mapper["id"] == mapper_id:
                o_m = mapper
                break

    return o_m


def get_instance_layout_fields(integration_instance, instance_incident_types, layouts, incident_fields):
    layout_data = None
    fields_data = None
    evidence_data = {}
    if incident_types := instance_incident_types:
        for type_name, type_data in incident_types.items():
            layout_id = type_data["layout"]
            for layout in layouts:
                if layout["id"] == layout_id:
                    l_d = {**layout}
                    l_d["incident_type"] = type_name
                    if not layout_data:
                        layout_data = {layout["name"]: l_d}
                    else:
                        layout_data[layout["name"]] = l_d
                    break

            for incident_field in incident_fields:
                _types = incident_field["associatedTypes"]
                associated_types = _types if _types else []
                # if (type_data["id"] in associated_types or incident_field["associatedToAll"]) #and not incident_field["system"]:
                if type_data["id"] in associated_types and not incident_field["locked"]:
                    if not fields_data:
                        fields_data = {incident_field["name"]: incident_field}
                    else:
                        fields_data[incident_field["name"]] = incident_field

    return layout_data, fields_data


def get_playbook_integration(playbook, filter_int):
    pb_integration = None
    d = []
    final_data = []
    items = []
    names = []
    field_t = None
    field_type = None
    field_list = None
    # integration_names = playbook["dependencies"]["integration"]
    # print("Integration names are", integration_names)
    if filter_int:
        int_names = [integration_item for integration_item in filter_int]
        for integration in integrations:
            if integration.get("name") in int_names or integration["brand"] in int_names or integration.get("id") in int_names:
                # get integration incident types
                classifier_data, incident_types_data = get_instance_classifier_incident_type(
                    integration, incident_types, classifiers)
                # get integration incoming mapper
                incoming_mapper_data = get_instance_incoming_mapper(integration, incoming_mappers)
                # get integration outgoing mapper
                outgoing_mapper_data = get_instance_outgoing_mapper(integration, outgoing_mappers)
                # get integration layouts and incident_fields
                layout_data, fields_data = get_instance_layout_fields(integration, incident_types_data, layouts, incident_fields)
                if not pb_integration:
                    pb_integration = {integration["display"]: {integration["instance_name"]: {**integration}}}
                else:
                    if integration["display"] not in pb_integration:
                        pb_integration[integration["display"]] = {integration["instance_name"]: {**integration}}
                    else:
                        pb_integration[integration["display"]][integration["instance_name"]] = {**integration}

                if layout_data is not None:
                    for k, v in layout_data.items():
                        field_t = {}
                        evidence_data = {}
                        field_list = []
                        # print(b)
                        t = v.get('detailsV2')
                        if t is not None:
                            e = t.get("tabs")
                            for test in e:
                                if 'sections' in test.keys():
                                    final_data = test.get("sections")
                                    for l in final_data:
                                        name = l.get('name')
                                        field_type = {}
                                        field_t[name] = field_type
                                        items = l.get('items')
                                        columns = l.get('columns')
                                        for a in incident_fields:
                                            if items is not None:
                                                for j in items:
                                                    if j.get("fieldId") == a.get('cliName') or j.get("fieldId") == a.get('name'):
                                                        if j.get("fieldId") not in field_type.keys():
                                                            field_type[j.get("fieldId")] = a.get("type")
                                            if columns is not None:
                                                for c_data in columns:
                                                    # i_list.append(c_data.get('key'))
                                                    if c_data.get('key') == a.get('name') or c_data.get('key') == a.get('cliName'):
                                                        field_type[c_data.get('key')] = a.get("type")
                                            if l.get('type') == 'evidence':
                                                if a.get("id").startswith("evidence_"):
                                                    evidence_data[a["name"]] = a["type"]
                                                    field_t[l.get('name')] = evidence_data
                    field_list.append(field_t)
                # adding additional data into integration
                pb_integration[integration["display"]][integration["instance_name"]]["classifier"] = classifier_data
                pb_integration[integration["display"]][integration["instance_name"]]["incident_type"] = incident_types_data
                pb_integration[integration["display"]][integration["instance_name"]]["layout"] = layout_data
                pb_integration[integration["display"]][integration["instance_name"]]["field_type"] = field_t
                pb_integration[integration["display"]][integration["instance_name"]]["fields"] = fields_data
                pb_integration[integration["display"]][integration["instance_name"]]["incoming_mapper"] = incoming_mapper_data
                pb_integration[integration["display"]][integration["instance_name"]]["outgoing_mapper"] = outgoing_mapper_data

    return pb_integration


def get_custom_automations():
    r = post_api_request("/automation/search", {"query": "system:F AND hidden:F"}).get("scripts")
    # print("AUTOMATION", r)
    return r


def get_system_config():
    r = get_api_request("/system/config").get("defaultMap")
    return r

# def get_auto():

#     resp = get_api_request("/automation/export/fac8164a-92ab-4816-88a8-a60d69113de9")
#     print("Response data is", resp)

# def playbook_use_case(playbook: str, author: str, customer: str):
#     """Given a playbook, generate a use case document.

#     Args:
#         playbook (str): playbook name
#         author (str): author name
#         customer (str): company name
#     """
#     r = get_playbook_dependencies(playbook)
#     print(r)


def platform_as_built_use_case(max_request_size: int, max_days: int, author: str, customer: str):
    """Generate a platform as built use case document.

    Args:
        max_request_size (int): max request size
        max_days (int): max number of days
        author (str): author name
        customer (str): company name
    """
    open_incidents = get_open_incidents(max_days, max_request_size)
    closed_incidents = get_closed_incidents(max_days, max_request_size)

    system_config = get_system_config()
    integrations = get_enabled_integrations(max_request_size)
    installed_packs = get_installed_packs()
    playbooks = get_custom_playbooks()
    automations = get_custom_automations()
    playbook_stats = get_playbook_stats(playbooks, max_days, max_request_size)

    reports = get_custom_reports()
    dashboards = get_custom_dashboards()


def sub_data(playbook):
    # playbook = get_playbook_data(pb_name)
    test_d = set()
    task_name = set()
    int_data = []
    # int_name = []
    task_dict = {}
    for data_key, data_value in playbook.items():
        if data_key == "tasks":
            task_data = playbook.get('tasks')
            for data in task_data:
                task_dict = task_data.get(data)
                # print(data)
                # print(task_dict)
                for k in task_dict:
                    if k == 'task':
                        new = task_dict.get(k)
                        # print(new)
                        if new.get('type') == 'playbook':
                            test_d.add(new.get('playbookId'))
                        # if 'brand' in new.keys():
                        #     int_name.add(new.get('brand'))
                        if 'scriptId' in new.keys():
                            task_name.add(new.get('scriptId'))

    command_list = playbook.get("commands")
    if configuration is not None:
        for c in command_list:
            for k, v in configuration.items():
                if c in v["commands"]:
                    int_data.append(k)
    return test_d, task_name, int_data


def create_config_file(pb_name, ignore_playbook):
    global autodata
    playbook = get_playbook_data(pb_name)
    filter_play, filter_auto, filter_int = sub_data(playbook)
    playbook["dependencies"] = get_playbook_dependencies(playbook)
    # print("Playbook dependencies", playbook["dependencies"])
    playbook["automation"] = get_playbook_automation(playbook, filter_auto)  # filter_auto
    playbook["integration"] = get_playbook_integration(playbook, filter_int)
    playbook["subplaybook"] = get_playbook_subplaybook(playbook, filter_play)
    del playbook["dependencies"]
    if playbook["automation"] is not None:
        autodata = True
        for k, v in playbook["automation"].items():
            auto_id = v.get("id")
            resp = json.dumps(get_api_request(f"/automation/export/{auto_id}"))
            resp = (resp.split("script: |")[1])
            resp = (resp.split("type: python")[0])
            resp = resp.lstrip("\\n ")
            resp = resp.rstrip("\\n")
            auto_script[auto_id] = resp
            # print(auto_id)
            # print("Dictionary for automation code",auto_script)
        playbook["scripts"] = auto_script
    if playbook["subplaybook"] is not None:
        # playbook["automation"] = {k: v for k, v in playbook["automation"].items() if v.get('id') in ig_list[1]}
        # playbook["integration"] = {k: v for k, v in playbook["integration"].items() if k in ig_list[2]}
        # playbook["subplaybook"] = {k: v for k, v in playbook["subplaybook"].items() if v.get('id') in ig_list[0]}
        for subplaybook_name in playbook["subplaybook"]:
            if not playbook["subplaybook"][subplaybook_name]["system"]:
                ignore_playbook.append(subplaybook_name)
                playbook["subplaybook"][subplaybook_name] = create_config_file(subplaybook_name, ignore_playbook)
        return dict(playbook)
    else:
        return dict(playbook)


def create_as_built(playbook_names, ignore_playbook):
    configuration_data = []
    for pb_name in playbook_names:
        playbook = create_config_file(pb_name, ignore_playbook)
        configuration_data.append(playbook)
    # asbuilt = json.dumps(configuration_data, indent=4)
    # print("type",type(asbuilt))
    return configuration_data


def main():  # pragma: no cover
    args = demisto.args()
    author = args.get("author")
    customer = args.get("customer")
    global layouts, incident_types, incident_fields, classifiers, incoming_mappers, outgoing_mappers, playbooks, automations, integrations, ignore_playbook, configuration
    incident_fields = get_incident_fields()
    layouts = get_layouts()
    incident_types = get_incident_types()
    classifiers, incoming_mappers, outgoing_mappers = get_classifier_mapper()
    playbooks = get_playbooks()
    automations = get_automations()
    integrations, configuration = get_integrations()

    """Given a playbook is passed, we generate a use case document, instead of the platform as build."""
    if args.get("playbook"):
        pb_names = argToList(args.get("playbook"))
        asbuilt = json.dumps(create_as_built(pb_names, ignore_playbook), indent=4)
    else:
        pb_names = get_custom_playbooks()
        asbuilt1 = create_as_built(pb_names, ignore_playbook)
        play_data = []

        for data in range(len(asbuilt1)):
            if asbuilt1[data] is not None and asbuilt1[data].get("name") not in ignore_playbook:
                # print(asbuilt1[data].get("name"))
                play_data.append(asbuilt1[data])
                asbuilt = json.dumps(play_data, indent=4)
        # asbuilt = [data for data in create_as_built(pb_names, ignore_playbook) if data["name"] not in ignore_playbook]

    if asbuilt:
        fr = fileResult("asbuilt.json", asbuilt, file_type=EntryType.ENTRY_INFO_FILE)
        return_results(fr)
    else:
        return_error("No playbooks found. Please ensure that playbooks are present to generate the asbuilt configuration file.")


if __name__ in ('__builtin__', 'builtins'):
    main()
