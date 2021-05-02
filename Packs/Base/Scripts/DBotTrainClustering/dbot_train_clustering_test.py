import json

from DBotTrainClustering import demisto, main, MESSAGE_INCORRECT_FIELD, MESSAGE_INVALID_FIELD, \
    preprocess_incidents_field, PREFIXES_TO_REMOVE, MESSAGE_CLUSTERING_NOT_VALID

PARAMETERS_DICT = {
    'fromDate': '',
    'toDate': '',
    'limit': '1000',
    'query': '',
    'maxNumberOfCluster': '1000',
    'minNumberofIncidentPerCluster': '2',
    'modelName': 'model ',
    'storeModel': 'False',
    'minHomogeneityCluster': 0.6,
    'incidentType': 'Phishing',
    'maxRatioOfMissingValue': 0.5
}

FETCHED_INCIDENT_NOT_EMPTY = [
    {'id': '1', 'created': "2021-01-30", 'field_1': 'powershell IP=1.1.1.1', 'field_2': 'powershell.exe',
     'entityname': 'powershell'},
    {'id': '2', 'created': "2021-01-30", 'field_1': 'nmap port 1', 'field_2': 'nmap.exe',
     'entityname': 'nmap'},
    {'id': '3', 'created': "2021-01-30", 'field_1': 'powershell IP=1.1.1.2', 'field_2': 'powershell',
     'entityname': 'powershell'},
    {'id': '4', 'created': "2021-01-30", 'field_1': 'nmap port 2', 'field_2': 'nmap',
     'entityname': 'nmap'},
]

FETCHED_INCIDENT_NOT_EMPTY_WITH_NOT_ENOUGH_VALUES = [
    {'id': '1', 'created': "2021-01-30", 'field_1': 'powershell IP=1.1.1.1', 'field_2': '',
     'entityname': 'powershell'},
    {'id': '2', 'created': "2021-01-30", 'field_1': 'nmap port 1', 'field_2': '',
     'entityname': 'nmap'},
    {'id': '3', 'created': "2021-01-30", 'field_1': 'powershell IP=1.1.1.2', 'field_2': '',
     'entityname': 'powershell'},
    {'id': '4', 'created': "2021-01-30", 'field_1': 'nmap port 2', 'field_2': 'nmap',
     'entityname': 'nmap'},
]

FETCHED_INCIDENT_EMPTY = []


def executeCommand(command, args):
    global FETCHED_INCIDENT
    if command == 'GetIncidentsByQuery':
        return [{'Contents': json.dumps(FETCHED_INCIDENT), 'Type': 'note'}]


def test_preprocess_incidents_field():
    assert preprocess_incidents_field('incident.commandline', PREFIXES_TO_REMOVE) == 'commandline'
    assert preprocess_incidents_field('commandline', PREFIXES_TO_REMOVE) == 'commandline'


def test_main_regular(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    PARAMETERS_DICT.update({'fieldsForClustering': 'field_1, field_2, wrong_field', 'fieldForClusterName': 'entityname'})
    mocker.patch.object(demisto, 'args',
                        return_value=PARAMETERS_DICT
                        )
    sub_dict_0 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['1', '3'],
                 'name': 'powershell',
                 'query': 'type:Phishing'
    }
    sub_dict_1 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['2', '4'],
                 'name': 'nmap',
                 'query': 'type:Phishing'
    }

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json['data'][0]
    cluster_1 = output_json['data'][1]
    assert MESSAGE_INCORRECT_FIELD % 'wrong_field' in msg
    assert (all(item in cluster_0.items() for item in sub_dict_0.items())
            and all(item in cluster_1.items() for item in sub_dict_1.items())) \
            or (all(item in cluster_0.items() for item in sub_dict_1.items())
            and all(item in cluster_1.items() for item in sub_dict_0.items()))


# Test if wrong cluster name
def test_wrong_cluster_name(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    PARAMETERS_DICT.update({'fieldsForClustering': 'field_1, field_2', 'fieldForClusterName': 'wrong_cluster_name_field'})
    mocker.patch.object(demisto, 'args',
                        return_value=PARAMETERS_DICT)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert MESSAGE_INCORRECT_FIELD % 'wrong_cluster_name_field' in msg
    assert not output_clustering_json
    assert not model


# Test if empty cluster name
def test_empty_cluster_name(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    PARAMETERS_DICT.update(
        {'fieldsForClustering': 'field_1, field_2', 'fieldForClusterName': ''})
    mocker.patch.object(demisto, 'args',
                        return_value=PARAMETERS_DICT)
    sub_dict_0 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['1', '3'],
                 'name': 'Cluster 0',
                 'query': 'type:Phishing'
        }
    sub_dict_1 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['2', '4'],
                 'name': 'Cluster 1',
                 'query': 'type:Phishing'
        }
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json['data'][0]
    cluster_1 = output_json['data'][1]
    assert (all(item in cluster_0.items() for item in sub_dict_0.items()) and
            all(item in cluster_1.items() for item in sub_dict_1.items())) or \
            (all(item in cluster_0.items() for item in sub_dict_1.items()) and
            all(item in cluster_1.items() for item in sub_dict_0.items()))


# Test if incorrect all incorrrect field name
def test_all_incorrect_fields(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    PARAMETERS_DICT.update(
        {'fieldsForClustering': 'field_1_wrong, field_2_wrong', 'fieldForClusterName': 'name'})
    mocker.patch.object(demisto, 'args',
                        return_value=PARAMETERS_DICT)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert MESSAGE_INCORRECT_FIELD % ' , '.join(['field_1_wrong', 'field_2_wrong', 'name']) in msg

    assert not output_clustering_json
    assert not model


# Test if one field has no enough value
def test_missing_too_many_values(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY_WITH_NOT_ENOUGH_VALUES
    PARAMETERS_DICT.update(
        {'fieldsForClustering': 'field_1, field_2', 'fieldForClusterName': 'entityname'})
    mocker.patch.object(demisto, 'args',
                        return_value=PARAMETERS_DICT)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert MESSAGE_INVALID_FIELD % 'field_2' in msg
    assert output_clustering_json
    assert model


def test_main_incident_nested(mocker):
    """
    Test if fetched incident truncated  -  Should return MESSAGE_WARNING_TRUNCATED in the message
    :param mocker:
    :return:
    """
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    nested_field = 'xdralerts.cmd'
    PARAMETERS_DICT.update(
        {'fieldsForClustering': nested_field, 'fieldForClusterName': 'entityname'})
    mocker.patch.object(demisto, 'args',
                        return_value=PARAMETERS_DICT)
    mocker.patch.object(demisto, 'dt', return_value=['nested_val_1', 'nested_val_2'])
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert not model
    assert not output_clustering_json
    assert MESSAGE_CLUSTERING_NOT_VALID in msg
