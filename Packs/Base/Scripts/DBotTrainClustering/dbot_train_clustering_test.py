# from CommonServerPython import *
# import pytest
import json
import numpy as np
import pandas as pd

from DBotTrainClustering import demisto, main, HDBSCAN_PARAMS


FETCHED_INCIDENT_NOT_EMPTY = [
    {'id': '1', 'created': "2021-01-30", 'field1': 'powershell IP=1.1.1.1', 'field2': 'powershell IP=1.1.1.1',
     'entityname': 'powershell'},
    {'id': '2', 'created': "2021-01-30", 'field1': 'powershell IP=1.1.1.1', 'field2': 'powershell IP=1.1.1.1',
     'entityname': 'nmap'},
    {'id': '3', 'created': "2021-01-30", 'field1': 'powershell IP=1.1.1.1', 'field2': 'powershell IP=1.1.1.1',
     'entityname': 'nmap'},
    {'id': '4', 'created': "2021-01-30", 'field1': 'powershell IP=1.1.1.1', 'field2': 'powershell IP=1.1.1.1',
     'entityname': 'powershell'},
    {'id': '5', 'created': "2021-01-30", 'field1': 'powershell IP=1.1.1.1',
     'commandline1': 'powershell IP=1.1.1.1',
     'entityname': 'powershell'},
]

def executeCommand(command, args):
    global FETCHED_INCIDENT_NOT_EMPTY
    if command == 'GetIncidentsByQuery':
        return [{'Contents': json.dumps(json.load(open('incidents.json', 'rb'))), 'Type': 'note'}]
        #return [{'Contents': json.dumps(FETCHED_INCIDENT_NOT_EMPTY), 'Type': 'note'}]



def test_main_regular(mocker):
    global FETCHED_INCIDENT_NOT_EMPTY
    FETCHED_INCIDENT_NOT_EMPTY = FETCHED_INCIDENT_NOT_EMPTY
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'fieldsForClustering': 'entityname, wrong_field',
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
    res, msg = main()
    a = 1





# Test if wrong cluster name

# Test if empty cluster name

# Test if incorrect all incorrrect field name

# Test if one incorrect field name

# Test if multiple fields

#

