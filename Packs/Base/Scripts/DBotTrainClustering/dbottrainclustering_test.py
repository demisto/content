import json
from freezegun import freeze_time
import pytest

from DBotTrainClustering import (
    demisto,
    main,
    MESSAGE_INCORRECT_FIELD,
    MESSAGE_INVALID_FIELD,
    preprocess_incidents_field,
    MESSAGE_CLUSTERING_NOT_VALID,
    check_list_of_dict,
    base64,
    datetime,
    MESSAGE_NO_FIELD_NAME_OR_CLUSTERING,
    get_model_if_not_expired
)
import dill as pickle

PARAMETERS_DICT = {
    "fromDate": "",
    "toDate": "",
    "limit": "1000",
    "query": "",
    "minNumberofIncidentPerCluster": "2",
    "modelName": "model_name",
    "storeModel": "False",
    "minHomogeneityCluster": 0.6,
    "type": "Phishing",
    "maxRatioOfMissingValue": 0.5,
    "modelExpiration": 24,
    "forceRetrain": "True",
    "modelHidden": "False",
    "numberOfFeaturesPerField": 500,
    "analyzer": "char",
}

FETCHED_INCIDENT_NOT_EMPTY = [
    {
        "id": "1",
        "created": "2021-01-30",
        "name": "name_1",
        "field_1": "powershell IP=1.1.1.1",
        "field_2": "powershell.exe",
        "entityname": "powershell",
    },
    {
        "id": "2",
        "created": "2021-01-30",
        "name": "name_2",
        "field_1": "nmap port 1",
        "field_2": "nmap.exe",
        "entityname": "nmap",
    },
    {
        "id": "3",
        "created": "2021-01-30",
        "name": "name_3",
        "field_1": "powershell IP=1.1.1.2",
        "field_2": "powershell",
        "entityname": "powershell",
    },
    {
        "id": "4",
        "created": "2021-01-30",
        "name": "name_4",
        "field_1": "nmap port 2",
        "field_2": "nmap",
        "entityname": "nmap",
    },
    {
        "id": "5",
        "created": "2021-01-30",
        "name": "name_3",
        "field_1": "powershell IP=1.1.1.3",
        "field_2": "powershell",
        "entityname": "powershell",
    },
    {
        "id": "6",
        "created": "2021-01-30",
        "name": "name_4",
        "field_1": "nmap port 3",
        "field_2": "nmap",
        "entityname": "nmap",
    },
]

FETCHED_INCIDENT_NOT_EMPTY_MULTIPLE_NAME = [
    {
        "id": "1",
        "created": "2021-01-30",
        "name": "name_1",
        "field_1": "powershell IP=1.1.1.1",
        "field_2": "powershell.exe",
        "entityname": ["powershell", "powershell", "nmap"],
    },
    {
        "id": "2",
        "created": "2021-01-30",
        "name": "name_2",
        "field_1": "nmap port 1",
        "field_2": "nmap.exe",
        "entityname": ["powershell", "nmap", "nmap"],
    },
    {
        "id": "3",
        "created": "2021-01-30",
        "name": "name_3",
        "field_1": "powershell IP=1.1.1.2",
        "field_2": "powershell",
        "entityname": ["powershell", "powershell", "nmap"],
    },
    {
        "id": "4",
        "created": "2021-01-30",
        "name": "name_4",
        "field_1": "nmap port 2",
        "field_2": "nmap",
        "entityname": ["powershell", "nmap", "nmap"],
    },
    {
        "id": "5",
        "created": "2021-01-30",
        "name": "name_3",
        "field_1": "powershell IP=1.1.1.3",
        "field_2": "powershell",
        "entityname": ["powershell", "powershell", "nmap"],
    },
    {
        "id": "6",
        "created": "2021-01-30",
        "name": "name_4",
        "field_1": "nmap port 3",
        "field_2": "nmap",
        "entityname": ["powershell", "nmap", "nmap"],
    },
]

FETCHED_INCIDENT_NOT_EMPTY_WITH_NOT_ENOUGH_VALUES = [
    {
        "id": "1",
        "created": "2021-01-30",
        "field_1": "powershell IP=1.1.1.1",
        "field_2": "",
        "entityname": "powershell",
    },
    {
        "id": "2",
        "created": "2021-01-30",
        "field_1": "nmap port 1",
        "field_2": "",
        "entityname": "nmap",
    },
    {
        "id": "3",
        "created": "2021-01-30",
        "field_1": "powershell IP=1.1.1.2",
        "field_2": "",
        "entityname": "powershell",
    },
    {
        "id": "4",
        "created": "2021-01-30",
        "field_1": "nmap port 2",
        "field_2": "nmap",
        "entityname": "nmap",
    },
    {
        "id": "5",
        "created": "2021-01-30",
        "field_1": "powershell IP=1.1.1.3",
        "field_2": "",
        "entityname": "powershell",
    },
    {
        "id": "6",
        "created": "2021-01-30",
        "field_1": "nmap port 3",
        "field_2": "nmap",
        "entityname": "nmap",
    },
]

FETCHED_INCIDENT_NOT_EMPTY_SAME_CLUSTER_NAME = [
    {
        "id": "1",
        "created": "2021-01-30",
        "name": "name_1",
        "field_1": "powershell IP=1.1.1.1",
        "field_2": "powershell.exe",
        "entityname": "powershell",
    },
    {
        "id": "2",
        "created": "2021-01-30",
        "name": "name_2",
        "field_1": "nmap port 1",
        "field_2": "nmap.exe",
        "entityname": "nmap",
    },
    {
        "id": "3",
        "created": "2021-01-30",
        "name": "name_3",
        "field_1": "powershell IP=1.1.1.2",
        "field_2": "powershell.exe",
        "entityname": "powershell",
    },
    {
        "id": "4",
        "created": "2021-01-30",
        "name": "name_4",
        "field_1": "nmap port 2",
        "field_2": "nmap.exe",
        "entityname": "nmap",
    },
    {
        "id": "5",
        "created": "2021-01-30",
        "name": "name_3",
        "field_1": "powershell IP=1.1.1.3",
        "field_2": "powershell.exe",
        "entityname": "powershell",
    },
    {
        "id": "6",
        "created": "2021-01-20",
        "name": "name_4",
        "field_1": "nmap port 3",
        "field_2": "nmap.exe",
        "entityname": "nmap",
    },
]

FETCHED_INCIDENT_EMPTY = []

sub_dict_0 = {
    "data": [3],
    "dataType": "incident",
    "incidents_ids": ["1", "3", "5"],
    "name": "powershell",
    "query": "type:Phishing",
}

sub_dict_1 = {
    "data": [3],
    "dataType": "incident",
    "incidents_ids": ["2", "4", "6"],
    "name": "nmap",
    "query": "type:Phishing",
}


class PostProcessing:
    def __init__(self, date_training):
        self.date_training = date_training
        self.json = '{"data": [{"name": "name", "incidents_ids": []}]}'


def executeCommand(command, args):

    match command:
        case "GetIncidentsByQuery":
            return [{"Contents": json.dumps(FETCHED_INCIDENT), "Type": "note"}]
        case "getMLModel":
            model = PostProcessing(datetime.now().strftime("%m/%d/%Y %H:%M:%S"))
            model_data = base64.b64encode(pickle.dumps(model)).decode("utf-8")  # guardrails-disable-line
            return [
                {
                    "Contents": {"modelData": model_data},
                    "Type": "note",
                }
            ]
        case _:
            return None


def test_preprocess_incidents_field():
    assert preprocess_incidents_field("incident.commandline") == "commandline"
    assert preprocess_incidents_field("commandline") == "commandline"


def test_check_list_of_dict():
    assert check_list_of_dict([{"test": "value_test"}, {"test1": "value_test1"}]) is True
    assert check_list_of_dict({"test": "value_test"}) is False


# Test regular training
def test_main_regular(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2, wrong_field",
        "fieldForClusterName": "entityname",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    _, output_clustering_json, msg = main()

    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json["data"][0]
    cluster_1 = output_json["data"][1]
    assert MESSAGE_INCORRECT_FIELD % "wrong_field" in msg
    assert cluster_0['incidents_ids'] == ['1', '3', '5']
    assert cluster_1['incidents_ids'] == ['2', '4', '6']
    assert all(item in cluster_0.items() for item in sub_dict_0.items())
    assert all(item in cluster_1.items() for item in sub_dict_1.items())
    assert not all(item in cluster_0.items() for item in sub_dict_1.items())
    assert not all(item in cluster_1.items() for item in sub_dict_0.items())


# Test if wrong cluster name
def test_wrong_cluster_name(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2",
        "fieldForClusterName": "wrong_cluster_name_field",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    model, output_clustering_json, msg = main()

    assert MESSAGE_INCORRECT_FIELD % "wrong_cluster_name_field" in msg
    assert not output_clustering_json
    assert not model


# Test if empty cluster name
def test_empty_cluster_name(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    args = PARAMETERS_DICT | {"fieldsForClustering": "field_1, field_2", "fieldForClusterName": ""}
    mocker.patch.object(demisto, "args", return_value=args)
    sub_dict_0 = {
        "data": [3],
        "dataType": "incident",
        "incidents_ids": ["1", "3", "5"],
        "name": "Cluster 0",
        "query": "type:Phishing",
    }
    sub_dict_1 = {
        "data": [3],
        "dataType": "incident",
        "incidents_ids": ["2", "4", "6"],
        "name": "Cluster 1",
        "query": "type:Phishing",
    }
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    model, output_clustering_json, msg = main()

    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json["data"][0]
    cluster_1 = output_json["data"][1]
    assert cluster_0['incidents_ids'] == ['1', '3', '5']
    assert cluster_1['incidents_ids'] == ['2', '4', '6']
    assert all(item in cluster_0.items() for item in sub_dict_0.items())
    assert all(item in cluster_1.items() for item in sub_dict_1.items())
    assert not all(item in cluster_0.items() for item in sub_dict_1.items())
    assert not all(item in cluster_1.items() for item in sub_dict_0.items())


# Test if incorrect all incorrrect field name
def test_all_incorrect_fields(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1_wrong, field_2_wrong",
        "fieldForClusterName": "name",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    assert (
        MESSAGE_INCORRECT_FIELD % " , ".join(["field_1_wrong", "field_2_wrong"]) in msg
    )
    assert MESSAGE_NO_FIELD_NAME_OR_CLUSTERING in msg

    assert not output_clustering_json
    assert not model


# Test if one field has no enough value
def test_missing_too_many_values(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY_WITH_NOT_ENOUGH_VALUES
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2", "fieldForClusterName": "entityname"
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    model, output_clustering_json, msg = main()

    assert MESSAGE_INVALID_FIELD % "field_2" in msg
    assert output_clustering_json
    assert model


# Test for nested fields
def test_main_incident_nested(mocker):
    """
    Test if fetched incident truncated  -  Should return MESSAGE_WARNING_TRUNCATED in the message
    :param mocker:
    :return:
    """
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    nested_field = "xdralerts.cmd"
    args = PARAMETERS_DICT | {"fieldsForClustering": nested_field, "fieldForClusterName": nested_field}
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "dt", return_value=["nested_val_1", "nested_val_2"])
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    model, output_clustering_json, msg = main()

    assert model is None
    assert output_clustering_json == {}
    assert MESSAGE_CLUSTERING_NOT_VALID in msg


# Test to validate that if the model is still valid then it won't train again
def test_model_exist_and_valid(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2, wrong_field",
        "fieldForClusterName": "entityname",
        "forceRetrain": "False",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    _, output_clustering_json, msg = main()
    assert not msg
    assert output_clustering_json == PostProcessing(None).json


# Test to validate that if the model has expired then it will train again
def test_model_exist_and_expired(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    time = "1e-20"
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2",
        "fieldForClusterName": "entityname",
        "forceRetrain": "False",
        "modelExpiration": time,
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    _, output_clustering_json, _ = main()
    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json["data"][0]
    cluster_1 = output_json["data"][1]
    assert all(item in cluster_0.items() for item in sub_dict_0.items())
    assert all(item in cluster_1.items() for item in sub_dict_1.items())
    assert not all(item in cluster_0.items() for item in sub_dict_1.items())
    assert not all(item in cluster_1.items() for item in sub_dict_0.items())


# Test if cluster name field has value of type list
def test_main_name_cluster_is_list(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY_MULTIPLE_NAME
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2, wrong_field",
        "fieldForClusterName": "entityname",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    model, output_clustering_json, msg = main()
    output_json = json.loads(output_clustering_json)
    cluster_0 = output_json["data"][0]
    cluster_1 = output_json["data"][1]
    assert MESSAGE_INCORRECT_FIELD % "wrong_field" in msg
    assert all(item in cluster_0.items() for item in sub_dict_0.items())
    assert all(item in cluster_1.items() for item in sub_dict_1.items())
    assert not all(item in cluster_0.items() for item in sub_dict_1.items())
    assert not all(item in cluster_1.items() for item in sub_dict_0.items())


# Test same cluster name should created prefixes
def test_same_cluster_name(mocker):
    global FETCHED_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY_SAME_CLUSTER_NAME
    args = PARAMETERS_DICT | {
        "fieldsForClustering": "field_1, field_2, wrong_field",
        "fieldForClusterName": "entityname",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    model, *_ = main()
    cluster_names = [x["clusterName"] for x in model.selected_clusters.values()]
    assert cluster_names == ['', 'powershell', 'nmap']


@pytest.mark.parametrize("force_retrain, model_expiration, model, expected_result_obj", [
    (True, 48, PostProcessing(datetime(2023, 1, 1)), type(None)),
    (False, 48, None, type(None)),
    (False, 48, PostProcessing(datetime(2023, 1, 1)), type(None)),
    (False, 48, PostProcessing(datetime(2023, 2, 1)), PostProcessing),
])
@freeze_time("2023-02-02")
def test_get_model_if_not_expired(mocker, force_retrain, model_expiration, model, expected_result_obj):
    # Mock get_model function
    mocker.patch("DBotTrainClustering.get_model", return_value=model)

    result = get_model_if_not_expired(force_retrain, model_expiration, 'name')

    assert isinstance(result, expected_result_obj)
