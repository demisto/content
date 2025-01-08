import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Defining global variables
layouts: list = []
integrations: list = []
classifiers: list = []
incoming_mappers: list = []
outgoing_mappers: list = []
incident_types: list = []
incident_fields: list = []
playbooks: list = []
automations: list = []
ignore_playbook: list = []
ignore_sub: list = []
auto_script: dict = {}
configuration: dict = {}
autodata: bool = False


def create_context(data: Any, args: list) -> dict | list:
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


def merge_data(instance: list, configuration: list) -> None:
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


def separate_classfier_mapper(data: list) -> tuple:
    """
    This function accepts the raw data and filters out classifer and mappers from it.

    Args:
    data: raw data to be filtered (can be list or dict)

    Returns:
    list : classifier data list
    list: incoming mapper data list
    list: outgoing mapper data list

    """

    classifier_list = []
    incoming_mapper_list = []
    outgoing_mapper_list = []

    for data_item in data:
        if data_item["type"] == "mapping-outgoing":
            outgoing_mapper_list.append(data_item)
        elif data_item["type"] == "mapping-incoming":
            incoming_mapper_list.append(data_item)
        else:
            classifier_list.append(data_item)
    return classifier_list, incoming_mapper_list, outgoing_mapper_list


def post_api_request(url: str, body: dict) -> dict:
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
    except (TypeError, KeyError):
        demisto.debug(f'error with "core-api-post" {api_args=}')
        return_error(f'API Request failed, unable to parse: {raw_res}')
    return res


def get_api_request(url: str) -> list | str | None:
    """Get API request.

    Args:
        url (str): request url path

    Returns:
        Dict: dictionary representation of the response
    """
    raw_res = demisto.executeCommand("core-api-get", {"uri": url})
    try:
        res = raw_res[0]['Contents']['response']
        # If it's a string and not an object response, means this command has failed.
        if isinstance(res, str):
            return res if autodata is True else None
    except KeyError:
        demisto.debug(f'error with "core-api-get" {url=}')
        return_error(f'API Request failed, no response from API call to {url}')
    return res


def get_custom_playbooks() -> list[str]:
    """Return all the custom playbooks installed in XSOAR

    Returns:
        TableData: TableData object with the custom playbooks.
    """
    res: list = post_api_request("/playbook/search", {"query": "system:F AND hidden:F"}).get("playbooks", [])
    return [pb["name"] for pb in res]


def get_layouts() -> list:
    """Return the data for the custom Layouts.

    Returns:
        dict: Filtered data for the custom layouts having the data only for the fields mentioned.
    """
    fields = ['description', 'details', 'detailsV2', 'group', 'id', 'modified', 'name', 'packID', 'packName', 'system']
    resp = get_api_request("/layouts")
    filtered_data = create_context(resp, fields)
    return cast(list, filtered_data)


def get_incident_types() -> list:
    """Return the data for the incident types.

    Returns:
        dict: Filtered data for the incident types having the data only for the fields mentioned.
    """
    fields = ['id', 'layout', 'modified', 'name', 'playbookId', 'system', 'packID', 'packName']
    resp = get_api_request("/incidenttype")
    filtered_data = create_context(resp, fields)
    return cast(list, filtered_data)


def get_incident_fields() -> list:
    """Return the data for the custom incident fields.

    Returns:
        dict: Filtered data for the custom incident fields having the data only for the fields mentioned.
    """
    fields = ['associatedToAll', 'associatedTypes', 'cliName', 'description',
              'id', 'modified', 'name', 'type', 'system', 'locked', 'packID', 'packName']
    resp = get_api_request("/incidentfields")
    filtered_data = create_context(resp, fields)
    return cast(list, filtered_data)


def get_classifier_mapper() -> tuple[Any, Any, Any]:
    """Return the data for the custom classifers, incoming mapper and outgoing mapper.

    Returns:
        dict: Filtered data for the custom classifers, incoming mapper and outgoing mapper only for the fields mentioned.
    """
    fields = ['description', 'id', 'modified', 'name', 'system', 'type',
              'defaultIncidentType', 'keyTypeMap', 'mapping', 'packID', 'packName']
    resp: list = post_api_request("/classifier/search", {}).get("classifiers", [])
    if resp:
        filtered_data = cast(list, create_context(resp, fields))
        class_data, i_mapper_data, o_mapper_data = separate_classfier_mapper(filtered_data)
    else:
        return_error("No classifier and mapper data found.")
    return class_data, i_mapper_data, o_mapper_data


def get_playbooks() -> list:
    """Return the data for the custom Playbooks

    Returns:
        dict: Filtered data for the custom playbooks having the data only for the fields mentioned.
    """
    fields = ['commands', 'id', 'inputs', 'modified', 'name', 'outputs', 'packID', 'packName', 'tasks', 'system', 'comment']
    resp = post_api_request("/playbook/search", {"query": "hidden:F"}).get("playbooks")
    filtered_data = create_context(resp, fields)
    return cast(list, filtered_data)


def get_automations() -> list:
    """Return the data for the custom automation

    Returns:
        dict: Filtered data for the custom automation, having the data only for the fields mentioned.
    """
    fields = ['arguments', 'comment', 'contextKeys', 'id', 'modified', 'name', 'system', 'tags', 'type']
    resp = post_api_request("/automation/search", {"query": "hidden:F"}).get("scripts")
    filtered_data = create_context(resp, fields)
    return cast(list, filtered_data)


def get_integrations() -> tuple[list, dict]:
    """
    This function provides the filtered integration data and the filtered instance data for that particular integration.

    Returns:
    instance_data : dictionary containing the integration instance data
    command_data : dictionary containing filtered configuration data
    """
    command_data = {}
    instance_fields = ['brand', 'category', 'id', 'incomingMapperId', 'isBuiltin', 'isSystemIntegration', 'mappingId', 'modified',
                       'name', 'outgoingMapperId', 'packID', 'packName', 'configvalues']
    configuration_fields = ['description', 'detailedDescription', 'display',
                            'id', 'name']  # if require script then add 'integrationScript'

    resp = post_api_request("/settings/integration/search", {})
    int_data: list = resp.get("configurations", [])
    for data in int_data:
        command_list = []
        command_value: dict[str, Union[str, list[str], None]] = {
            'id': None,
            'name': None,
            'display': None,
            'description': None,
            'commands': []
        }
        command_data[data['display']] = command_value
        if data is not None:
            int_script = data.get("integrationScript")
            if int_script is not None:
                commands = int_script.get("commands")
                if commands is not None:
                    for i_name in commands:
                        command_list.append(i_name.get("name"))
        command_value["id"] = data['id']
        command_value["name"] = data['name']
        command_value["display"] = data['display']
        command_value["description"] = data['description']
        command_value["commands"] = command_list
    instance_data = cast(list, create_context(resp.get("instances", []), instance_fields))
    configuration_data = cast(list, create_context(resp.get("configurations", []), configuration_fields))
    merge_data(instance_data, configuration_data)
    return instance_data, command_data


def get_playbook_data(playbook_name: str) -> dict:
    """
    This function accepts the playbook name and and provides the data for that specific playbook.

    Args:
    playbook_name: Playbook name

    Returns:
    dict : Playbook data dictionary
    """
    for data_item in playbooks:
        if data_item["name"] == playbook_name:
            return dict(data_item)
    demisto.debug(f'playbook {playbook_name} not found')
    return {}


def get_playbook_dependencies(playbook: dict) -> dict:
    """
    This function accepts the playbook and provides the subplaybook, integrations and automations for that particular playbook.

    Args:
    playbook (dict): Playbook data for which the dependencies to be fetched

    Returns:
    dependencies : Dictionary having subplaybooks, integrations and automations data for playbooks
    """
    pb_id = playbook["id"]
    pb_name = playbook["name"]
    body = {
        "items": [
            {
                "id": f"{pb_id}",
                "type": "playbook"
            }
        ],
        "dependencyLevel": "optional"
    }
    resp = cast(list, dict_safe_get(post_api_request("/itemsdependencies", body), ("existing", "playbook", pb_id)))
    if not resp:
        raise DemistoException(f"Failed to retrieve dependencies for {pb_name}")

    dependencies: Dict[str, List] = {
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
    return dependencies


def get_playbook_automation(playbook: dict, filter_auto: set) -> dict:
    """
    This function accepts the playbook data and fetches the automation linked to that particular playbook.

    Args:
    playbook (dict): playbook data
    filter_auto (list): list having automation names that are configured for that specific playbook

    Returns:
    pb_automation : dictionary having custom automation data for a specific playbook
    """
    pb_automation = {}
    if filter_auto:
        for script in filter_auto:
            for automation_data in automations:
                if script in [automation_data["name"], automation_data["id"]] and not automation_data.get("system", False):
                    pb_automation[automation_data["name"]] = dict(automation_data)
                    break
    return pb_automation


def get_playbook_subplaybook(playbook: dict, filter_play: set) -> dict:
    """
    This function accepts the playbook data and fetches the subplaybooks for that particular playbook.

    Args:
    playbook (dict): playbook data
    filter_play (list): list having subplaybook names for that specific playbook

    Returns:
    pb_subpplaybook : dictionary having subplaybook data for a specific playbook
    """
    pb_subplaybook = {}
    if filter_play:
        for subplaybook in filter_play:
            for pb in playbooks:
                if subplaybook in [pb["name"], pb["id"]] and not pb.get("system", False):
                    pb_subplaybook[pb["name"]] = pb
                    break
    return pb_subplaybook


def get_instance_classifier_incident_type(integration_instance: dict, incident_types: list, classifiers: list) -> tuple:
    """
    This function accepts the integration instance, incident types and classifers and then establishes the mapping for the
    classifier and incident type data for an interation instance and returns data only for those classifers and incident types.

    Args:
    integration_instance (dict): integration instance data
    incident_types (list): list containg incident types
    classifiers (list): list containg classifiers

    Returns:
    classifier_data : dictionary having classifier data mapped to an integration
    incident_type_data : dictionary having incident types data mapped to an integration
    """
    classifier_data = None
    incident_type_data = {}
    classifier_id = integration_instance.get("mappingId", None)
    inc_type_id = integration_instance.get("incident_type", None)
    if classifier_id:
        for classifier in classifiers:
            if classifier_id == classifier["id"]:
                classifier_data = classifier
                classifier_incident_types = classifier["keyTypeMap"].values()
                for classifier_incident_type in classifier_incident_types:
                    for incident_type in incident_types:
                        if classifier_incident_type == incident_type["id"]:
                            incident_type_data[incident_type["name"]] = incident_type
                            break
                break

    elif inc_type_id:
        for incident_type in incident_types:
            if inc_type_id == incident_type["id"]:
                incident_type_data = {incident_type["name"]: incident_type}
                break

    return classifier_data, incident_type_data


def get_instance_incoming_mapper(integration_instance: dict, mappers: list) -> dict | None:
    """
    This function accepts the integration instance data and incomig mapper data, then establishes the mapping for the
    incoming mapper for an interation instance and returns data only for those incoming mappers.

    Args:
    integration_instance (dict): integration instance data
    mappers (list): list containg incoming mappers data

    Returns:
    in_mapper : dictionary having incoming mapper data mapped to an integration
    """
    in_mapper = None
    mapper_id = integration_instance.get("incomingMapperId", None)
    if mapper_id:
        for mapper in mappers:
            if mapper["id"] == mapper_id:
                in_mapper = mapper
                break

    return in_mapper


def get_instance_outgoing_mapper(integration_instance: dict, mappers: list) -> dict | None:
    """
    This function accepts the integration instance data and outgoing mapper data, then establishes the mapping for the
    outgoing mapper for an interation instance and returns data only for those outgoing mappers.

    Args:
    integration_instance (dict): integration instance data
    mappers (list): list containg outgoing mappers data

    Returns:
    out_mapper : dictionary having outgoing mapper data mapped to an integration
    """
    out_mapper = None
    mapper_id = integration_instance.get("outgoingMapperId", None)
    if mapper_id:
        for mapper in mappers:
            if mapper["id"] == mapper_id:
                out_mapper = mapper
                break

    return out_mapper


def get_instance_layout_fields(
    integration_instance: dict, instance_incident_types: dict, layouts: list, incident_fields: list
) -> tuple[dict | None, dict | None]:
    """
    This function accepts the integration instance,  incident types for that particular instance, layouts and incident fields,
    then establishes the mapping for the layouts and the incident fields for an interation instance and returns data only for
    those layouts and incident fields.

    Args:
    integration_instance (dict): integration instance data
    instance_incident_types (dict): incident types data for specific instance
    layouts (list): list having layouts data
    incident_fields (list): list having incident fields data

    Returns:
    layouts_data : dictionary having layouts data mapped to an incident type
    fields_data : dictionary having custom incident field data mapped to an incident type
    """
    layout_data = {}
    fields_data = {}
    incident_types = instance_incident_types
    if incident_types:
        for type_name, type_data in incident_types.items():
            layout_id = type_data["layout"]
            for layout in layouts:
                if layout["id"] == layout_id:
                    l_d = {**layout}
                    l_d["incident_type"] = type_name
                    layout_data[layout["name"]] = l_d
                    break

            for incident_field in incident_fields:
                _types = incident_field["associatedTypes"]
                associated_types = _types if _types else []
                # if (type_data["id"] in associated_types or incident_field["associatedToAll"]) #and not incident_field["system"]:
                if type_data["id"] in associated_types and not incident_field["locked"]:
                    fields_data[incident_field["name"]] = incident_field

    return layout_data, fields_data


def get_playbook_integration(playbook: dict, filter_int: list) -> dict:
    """
    This function accepts the playbook data and fetches the integration for that particular playbook.

    Args:
    playbook (dict): playbook data
    filter_int (list): list having integration names for that specific playbook

    Returns:
    pb_integration : dictionary having complete integration data for a specific playbook, containing classifiers,
    incident types, field types, layout, incident fields, incoming mapper and outgoing mapper.
    """
    pb_integration: dict = {}
    section_data: list = []
    items: list = []
    field_t: dict = {}
    field_type: dict = {}
    field_list: list = []
    if filter_int:
        int_names = list(filter_int)
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
                if integration["display"] not in pb_integration:
                    pb_integration[integration["display"]] = {integration["instance_name"]: integration.copy()}
                else:
                    pb_integration[integration["display"]][integration["instance_name"]] = integration.copy()

                if layout_data is not None:
                    for _k, v in layout_data.items():
                        field_t = {}
                        evidence_data = {}
                        field_list = []
                        t = v.get('detailsV2')
                        if t is not None:
                            e = t.get("tabs")
                            for test in e:
                                if 'sections' in test:
                                    section_data = test.get("sections")
                                    for tab in section_data:
                                        name = tab.get('name')
                                        field_type = {}
                                        field_t[name] = field_type
                                        items = tab.get('items')
                                        columns = tab.get('columns')
                                        for a in incident_fields:
                                            if items is not None:
                                                for j in items:
                                                    if (
                                                        j.get("fieldId") in (a.get("cliName"), a.get("name"))
                                                    ) and (
                                                        j.get("fieldId") not in field_type.keys()
                                                    ):
                                                        field_type[j.get("fieldId")] = a.get("type")
                                            if columns is not None:
                                                for c_data in columns:
                                                    if c_data.get("key") == a.get(
                                                        "name"
                                                    ) or c_data.get("key") == a.get(
                                                        "cliName"
                                                    ):
                                                        field_type[c_data.get('key')] = a.get("type")
                                            if tab.get('type') == 'evidence' and a.get("id").startswith("evidence_"):
                                                evidence_data[a["name"]] = a["type"]
                                                field_t[tab.get('name')] = evidence_data
                    field_list.append(field_t)
                # adding additional data into integration
                pb_integration[integration["display"]][integration["instance_name"]] |= {
                    "classifier": classifier_data,
                    "incident_type": incident_types_data,
                    "layout": layout_data,
                    "field_type": field_t,
                    "fields": fields_data,
                    "incoming_mapper": incoming_mapper_data,
                    "outgoing_mapper": outgoing_mapper_data
                }

    return pb_integration


def sub_data(playbook: dict) -> tuple:
    """
    This function accepts the playbook data and fetches the subplaybooks, automations and integrations for that playbook.

    Args:
    playbook (dict): playbook data

    Returns:
    test_d : set containing the subplaybook names
    task_name : set containing the automation and integration names
    int_data : list containing the integration names
    """
    test_d = set()
    task_name = set()
    int_data: list = []
    task_dict: dict = {}
    for data_key in playbook:
        if data_key == "tasks":
            task_data: dict = playbook.get('tasks', [])
            for data in task_data:
                task_dict = task_data[data]
                for k in task_dict:
                    if k == 'task':
                        new = task_dict.get(k)
                        if new is not None and new.get('type') == 'playbook':
                            test_d.add(new.get('playbookId'))
                        # if 'brand' in new.keys():
                        #     int_name.add(new.get('brand'))
                        if new is not None and 'scriptId' in new:
                            task_name.add(new.get('scriptId'))

    command_list = playbook.get("commands", [])
    if configuration is not None:
        for command in command_list:
            for k, v in configuration.items():
                if command in v["commands"]:
                    int_data.append(k)
    return test_d, task_name, int_data


def create_config_file(pb_name: str, ignore_playbook: list) -> dict:
    """
    This function accepts the playbook names and the name of the playbooks to be ignored to avoid the data repetition, as they
    are already covered in the subplaybooks, and then create complete configuration data for those playbooks and subplaybooks

    Args:
    pb_name: playbook name
    ignore_playbook: list having the playbook names to be ignored

    Returns:
    playbook : dictionary containing the complete data for playbooks, that is automtion, subplaybook and all the
    configuration data of integration for that particular playbook
    """
    global autodata
    playbook = get_playbook_data(pb_name)
    filter_play, filter_auto, filter_int = sub_data(playbook)
    playbook["dependencies"] = get_playbook_dependencies(playbook)
    playbook["automation"] = get_playbook_automation(playbook, filter_auto)  # filter_auto
    playbook["integration"] = get_playbook_integration(playbook, filter_int)
    playbook["subplaybook"] = get_playbook_subplaybook(playbook, filter_play)
    del playbook["dependencies"]
    if playbook["automation"] is not None:
        autodata = True
        for _k, v in playbook["automation"].items():
            auto_id = v.get("id")
            resp = json.dumps(get_api_request(f"/automation/export/{auto_id}"))
            resp = (resp.split("script: |")[1])
            resp = (resp.split("type: python")[0])
            resp = resp.lstrip("\\n ")
            resp = resp.rstrip("\\n")
            auto_script[auto_id] = resp
        playbook["scripts"] = auto_script
    if playbook["subplaybook"] is not None:
        for subplaybook_name in playbook["subplaybook"]:
            if not playbook["subplaybook"][subplaybook_name]["system"]:
                ignore_playbook.append(subplaybook_name)
                playbook["subplaybook"][subplaybook_name] = create_config_file(subplaybook_name, ignore_playbook)
        return dict(playbook)
    else:
        return dict(playbook)


def create_as_built(playbook_names: list, ignore_playbook: list) -> list:
    """
    This function accepts the playbook names and the names of the playbook to be ignored and then append all the data for those
    palybook that are not to be ignored, in a list.

    Args:
    playbook_names (list): playbook names
    ignore_playbook (list): playbooks to be ignored to avoid data repetition

    Returns:
    configuration_data : list containing complete configuration data for all the playbooks

    """
    configuration_data = []
    for pb_name in playbook_names:
        playbook = create_config_file(pb_name, ignore_playbook)
        configuration_data.append(playbook)
    return configuration_data


def main() -> None:  # pragma: no cover
    """
    This function creates a json file file for the complete configuration data.
    """
    try:
        args = demisto.args()
        global layouts, incident_types, incident_fields, classifiers, incoming_mappers, outgoing_mappers
        global playbooks, automations, integrations, ignore_playbook, configuration
        incident_fields = get_incident_fields()
        layouts = get_layouts()
        incident_types = get_incident_types()
        classifiers, incoming_mappers, outgoing_mappers = get_classifier_mapper()
        playbooks = get_playbooks()
        automations = get_automations()
        integrations, configuration = get_integrations()

        # Given a playbook is passed, we generate a use case document, instead of the platform as build.
        if args.get("playbook"):
            pb_names = argToList(args.get("playbook"))
            asbuilt = json.dumps(create_as_built(pb_names, ignore_playbook), indent=4)
        else:
            pb_names = get_custom_playbooks()
            asbuilt_all = create_as_built(pb_names, ignore_playbook)
            play_data = []

            for data in range(len(asbuilt_all)):
                if asbuilt_all[data] is not None and asbuilt_all[data].get("name") not in ignore_playbook:
                    play_data.append(asbuilt_all[data])
                    asbuilt = json.dumps(play_data, indent=4)

        if asbuilt:
            fr = fileResult("asbuilt.json", asbuilt, file_type=EntryType.ENTRY_INFO_FILE)
            return_results(fr)
        else:
            return_error("No playbooks found. Please ensure that playbooks are present to generate the configuration file.")
    except Exception as ex:
        return_error(f'Failed to execute Script. Error: {ex}')


if __name__ in ('__builtin__', 'builtins'):
    main()
