import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


response_data = util_load_json('./test_data/response_data.json')
response_pagination_incident = util_load_json('./test_data/test_data_pagination_incident.json')
response_pagination_investigate = util_load_json('./test_data/test_data_pagination_investigate.json')

dedup_by_id_test_case: list = [
    ({}, [], "Investigate_logs", 100, 0, "2023-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59'}, []),
    ({}, [], "Incident_logs", 100, 100, "2023-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59'}, []),
    ({}, [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
          {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 0, "2023-01-02T23:23:59",
     {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ['_id1', '_id2']},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59',
       'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-02T23:23:59',
       'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({}, [{"_id": "_id1", "incident_start_time": "2023-01-03T23:23:59"},
          {"_id": "_id2", "incident_start_time": "2023-01-04T23:23:59"}],
     "Incident_logs", 100, 0, "2023-01-02T23:23:59",
     {'last_run': '2023-01-04T23:23:59', 'Incident_logs-ids': ['_id1', '_id2']},
     [{'_id': '_id1', '_time': '2023-01-03T23:23:59',
       'incident_start_time': '2023-01-03T23:23:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-04T23:23:59',
       'incident_start_time': '2023-01-04T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2024-01-02T23:23:59'}, [], "Investigate_logs", 100,
     0, "2023-01-02T23:23:59", {'last_run': '2024-01-02T23:23:59'}, []),
    ({'last_run': '2023-01-02T23:23:59'}, [], "Investigate_logs", 100,
     0, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59'}, []),
    ({'last_run': '2023-01-02T23:23:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"}], "Incident_logs",
     100, 100, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': []}, []),
    ({'last_run': '2023-01-02T23:23:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"}], "Incident_logs",
     100, 99, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id1"]},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T22:23:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 99, "2022-01-02T22:22:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id1"]},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T22:22:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T22:22:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id2"]},
     [{'_id': '_id1', '_time': '2023-01-02T22:22:59', 'incident_start_time': '2023-01-02T22:22:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T23:22:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59",
     {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id1", "_id2"]},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1", "_id2"]},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:22:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:22:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59",
     {'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1", "_id2"]}, []),
    ({'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1"]},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:22:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:22:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1", "_id2"]},
     [{'_id': '_id2', '_time': '2023-01-02T23:22:59', 'incident_start_time': '2023-01-02T23:22:59', 'type': 'Detect incident'}]),
]

get_first_fetch_time_params = [({'first_fetch': "7 months"}, "2022-06-01T23:23:59", "2022-07-05T23:23:59"),
                               ({'first_fetch': "5 months"}, "2022-08-01T23:23:59", "2022-08-01T23:23:59")]

get_all_events_for_log_type_test_case_with_pagination: list = [
    (1500, "Incident_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_incident["expected_event_list"][:1500], {
     'Incident_logs-ids': response_pagination_incident["expected_ids_list"][:1500], 'last_run': '2021-06-01T00:00:00'}),
    (1500, "Investigate_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_investigate["expected_event_list"][:1500], {
     'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][:1500], 'last_run': '2021-06-01T00:00:00'}),
    (1574, "Investigate_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_investigate["expected_event_list"][:1574], {
     'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][1504:1574], 'last_run': '2021-07-02T09:07:43'}),
]

get_all_events_for_log_type_test_case_without_pagination: list = [
    (3, "Investigate_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_investigate["expected_event_list"][0:3], {
     'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][0:3], 'last_run': '2021-06-01T00:00:00'}),
]

test_main_params = [
    (3, {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     {'Investigate_logs': {
         'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][0:3], 'last_run': '2021-06-01T00:00:00'},
        'Incident_logs': {
         'Incident_logs-ids': response_pagination_incident["expected_ids_list"][0:3], 'last_run': '2021-06-01T00:00:00'}},
     [{'_id': 'id0', 'created_timestamp': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Investigate'},
      {'_id': 'id1', 'created_timestamp': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Investigate'},
      {'_id': 'id2', 'created_timestamp': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Investigate'},
      {'_id': 'id0', 'incident_start_time': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Detect incident'},
      {'_id': 'id1', 'incident_start_time': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Detect incident'},
      {'_id': 'id2', 'incident_start_time': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Detect incident'}
      ])
]
