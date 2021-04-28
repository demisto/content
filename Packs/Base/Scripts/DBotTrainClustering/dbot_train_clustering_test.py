# from CommonServerPython import *
# import pytest
import json
import numpy as np
import pandas as pd

from DBotTrainClustering import demisto, main, HDBSCAN_PARAMS, MESSAGE_INCORRECT_FIELD, MESSAGE_INVALID_FIELD


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

def executeCommand(command, args):
    global FETCHED_INCIDENT
    if command == 'GetIncidentsByQuery':
        #return [{'Contents': json.dumps(json.load(open('incidents.json', 'rb'))), 'Type': 'note'}]
        return [{'Contents': json.dumps(FETCHED_INCIDENT), 'Type': 'note'}]



def test_main_regular(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'fieldsForClustering': 'field_1, field_2, wrong_field',
                            'fieldForClusterName': 'entityname',
                            'fromDate':'',
                            'toDate':'',
                            'limit': '1000',
                            'query': '',
                            'maxNumberOfCluster': '1000',
                            'minNumberofIncidentPerCluster': '2',
                            'modelName': 'model',
                            'storeModel': 'False',
                            'minHomogeneityCluster': 0.6,
                            'incidentType': 'Phishing',
                            'maxPercentageOfMissingValue': 0.5
                        })
    sub_dict_0 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['id: 1', 'id: 3'],
                 'name': 'powershell',
                 'query': 'type:Phishing'
    }
    sub_dict_1 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['id: 2', 'id: 4'],
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
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'fieldsForClustering': 'field_1, field_2',
                            'fieldForClusterName': 'wrong_cluster_name_field',
                            'fromDate':'',
                            'toDate':'',
                            'limit': '1000',
                            'query': '',
                            'maxNumberOfCluster': '1000',
                            'minNumberofIncidentPerCluster': '2',
                            'modelName': 'model',
                            'storeModel': 'False',
                            'minHomogeneityCluster': 0.6,
                            'incidentType': 'Phishing',
                            'maxPercentageOfMissingValue': 0.5
                        })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert MESSAGE_INCORRECT_FIELD % 'wrong_cluster_name_field' in msg
    assert not output_clustering_json
    assert not model


# Test if empty cluster name
def test_empty_cluster_name(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'fieldsForClustering': 'field_1, field_2',
                            'fieldForClusterName': '',
                            'fromDate':'',
                            'toDate':'',
                            'limit': '1000',
                            'query': '',
                            'maxNumberOfCluster': '1000',
                            'minNumberofIncidentPerCluster': '2',
                            'modelName': 'model',
                            'storeModel': 'False',
                            'minHomogeneityCluster': 0.6,
                            'incidentType': 'Phishing',
                            'maxPercentageOfMissingValue': 0.5
                        })
    sub_dict_0 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['id: 1', 'id: 3'],
                 'name': 'Cluster 0',
                 'query': 'type:Phishing'
    }
    sub_dict_1 = {
                 'data': [2],
                 'dataType': 'incident',
                 'incidents_ids': ['id: 2', 'id: 4'],
                 'name': 'Cluster 1',
                 'query': 'type:Phishing'
    }
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json['data'][0]
    cluster_1 = output_json['data'][1]
    assert (all(item in cluster_0.items() for item in sub_dict_0.items())
            and all(item in cluster_1.items() for item in sub_dict_1.items())) \
            or (all(item in cluster_0.items() for item in sub_dict_1.items())
            and all(item in cluster_1.items() for item in sub_dict_0.items()))

# Test if incorrect all incorrrect field name
def test_all_incorrect_fields(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'fieldsForClustering': 'field_1_wrong, field_2_wrong',
                            'fieldForClusterName': 'name',
                            'fromDate':'',
                            'toDate':'',
                            'limit': '1000',
                            'query': '',
                            'maxNumberOfCluster': '1000',
                            'minNumberofIncidentPerCluster': '2',
                            'modelName': 'model',
                            'storeModel': 'False',
                            'minHomogeneityCluster': 0.6,
                            'incidentType': 'Phishing',
                            'maxPercentageOfMissingValue': 0.5
                        })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert MESSAGE_INCORRECT_FIELD % ' , '.join(['field_1_wrong', 'field_2_wrong', 'name']) in msg

    assert not output_clustering_json
    assert not model

# Test if one field has no enough value
def test_missing_too_many_values(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY_WITH_NOT_ENOUGH_VALUES
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'fieldsForClustering': 'field_1, field_2',
                            'fieldForClusterName': 'entityname',
                            'fromDate':'',
                            'toDate':'',
                            'limit': '1000',
                            'query': '',
                            'maxNumberOfCluster': '1000',
                            'minNumberofIncidentPerCluster': '2',
                            'modelName': 'model',
                            'storeModel': 'False',
                            'minHomogeneityCluster': 0.6,
                            'incidentType': 'Phishing',
                            'maxPercentageOfMissingValue': 0.5
                        })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert MESSAGE_INVALID_FIELD %'field_2' in msg
    assert  output_clustering_json
    assert  model


