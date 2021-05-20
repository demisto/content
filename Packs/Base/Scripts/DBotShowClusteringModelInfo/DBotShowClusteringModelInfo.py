from CommonServerPython import *

# CONSTS
BASE_INCIDENT_COLUMNS = ['id', 'created', 'name', 'Group name', 'Group id']


def show_model_info(model_name):
    success = False
    start = datetime.now()
    model = None

    while not success and datetime.now() - start < timedelta(minutes=10):
        res = demisto.executeCommand("getMLModel", {"modelName": model_name})
        if is_error(res):
            time.sleep(5)
        else:
            success = True
            model = res[0]['Contents']

    if model:
        md = model['model']['extra']['modelSummaryMarkdown']
        return_outputs(md)
    else:
        return_outputs("Cannot find model " + model_name)


def show_incidents_in_cluster(model_name, query, display_fields):
    res = demisto.executeCommand("DBotTrainClustering", {'modelName': model_name})
    data = res[0]['Contents']['data']
    id_to_cluster = {}
    id_to_cluster_name = {}
    incidents = []  # type: ignore
    for row in data:
        if row['pivot'] in query.split(" "):
            incidents_in_cluster = json.loads(row['incidents'])
            incidents += incidents_in_cluster
            for inc in incidents_in_cluster:
                id_to_cluster[inc['id']] = re.sub('\D', '', row['pivot'])
                id_to_cluster_name[inc['id']] = row['name']

    incidents_to_show = []
    for inc in incidents:
        incident_to_show = {k: v for k, v in inc.items() if k in display_fields}
        incident_to_show['Id'] = "[{0}](#/Details/{0})".format(inc['id'])
        incident_to_show['Name'] = incident_to_show['name'].replace("#", "")
        incident_to_show['Created'] = incident_to_show['created'][:incident_to_show['created'].find(".")]
        incident_to_show['Group id'] = id_to_cluster[inc['id']]
        incident_to_show['Group name'] = id_to_cluster_name[inc['id']]
        incidents_to_show.append(incident_to_show)

    headers = BASE_INCIDENT_COLUMNS + [x for x in display_fields if x not in BASE_INCIDENT_COLUMNS]
    headers = [x.capitalize() for x in headers]
    title = 'Incidents In Clusters ' + ", ".join(set(id_to_cluster.values()))
    return_outputs(tableToMarkdown(title, incidents_to_show, headers))


def main():
    query = demisto.args().get('searchQuery')
    model_name = demisto.args()['modelName']
    return_type = demisto.args()['returnType']
    if return_type == 'incidents':
        if not query:
            return_outputs("## Please select a specific cluster to show incidents")
        else:
            display_fields = demisto.args().get('fieldsToDisplay', '').split(',')
            display_fields = [x.strip() for x in display_fields if x]
            display_fields = list(set(BASE_INCIDENT_COLUMNS + display_fields))
            display_fields = list(dict.fromkeys(display_fields))
            show_incidents_in_cluster(model_name, query, display_fields)
    else:
        show_model_info(model_name)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
