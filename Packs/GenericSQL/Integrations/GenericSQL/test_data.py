import datetime


# ------------------------------------ test_fetch_incident_by_id_simple_query (1) -------------------------------

HEADERS_1 = "['incident_id', 'timestamp', 'incident_name', 'incident_data']"
RESPONSE_1 = [(1000, datetime.datetime(2022, 11, 8, 8, 30, 42, 423000), 'incident_1', 'incident data for incident 1'),
              (1001, datetime.datetime(2022, 11, 8, 8, 32, 53, 177000), 'incident_2', 'incident data for incident 2'),
              (1002, datetime.datetime(2022, 11, 8, 8, 33, 11, 680000), 'incident_3', 'incident data for incident 3'),
              (1003, datetime.datetime(2022, 11, 8, 8, 33, 28, 13000), 'incident_4', 'incident data for incident 4'),
              (1004, datetime.datetime(2022, 11, 8, 8, 38, 57, 723000), 'incident_5', 'incident data for incident 5'),
              (1005, datetime.datetime(2022, 11, 8, 9, 51, 34, 420000), 'incident_6', 'incident data for incident 6'),
              (1006, datetime.datetime(2022, 11, 8, 9, 51, 49, 887000), 'incident_6', 'incident data for incident 6'),
              (1007, datetime.datetime(2022, 11, 8, 9, 52, 33, 670000), 'incident_8', 'incident data for incident 8'),
              (1009, datetime.datetime(2022, 11, 8, 9, 52, 52, 150000), 'incident_9', 'incident data for incident 9'),
              (1010, datetime.datetime(2022, 11, 8, 9, 53, 11, 620000), 'incident_10', 'incident data for incident 10'),
              (1011, datetime.datetime(2022, 11, 8, 9, 53, 26, 993000), 'incident_11', 'incident data for incident 11'),
              (1012, datetime.datetime(2022, 11, 8, 9, 53, 45, 190000), 'incident_12', 'incident data for incident 12')]
EXPECTED_INCIDENTS_1 = [{'name': 'incident_1', 'occurred': '2022-12-21T11:02:03Z', 'rawJSON':
    '{"incident_id": "1000", "timestamp": "2022-11-08 08:30:42.423000", "incident_name": "incident_1", "incident_data": "incident data for incident 1"}'},
                      {'name': 'incident_2', 'occurred': '2022-12-21T11:02:03Z', 'rawJSON': '{"incident_id": "1001", "timestamp": "2022-11-08 08:32:53.177000", "incident_name": "incident_2", "incident_data": "incident data for incident 2"}'},
                      {'name': 'incident_3', 'occurred': '2022-12-21T11:02:03Z', 'rawJSON': '{"incident_id": "1002", "timestamp": "2022-11-08 08:33:11.680000", "incident_name": "incident_3", "incident_data": "incident data for incident 3"}'}]
EXPECTED_LAST_RUN_1 = {'last_timestamp': False, 'last_id': '1002', 'ids': []}
PARAMS_1 = {'column_name': 'incident_id', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False, 'modified': '0001-01-01T00:00:00Z',
           'name': '', 'password': '', 'sshkey': '', 'sshkeyPass': '', 'user': '',
           'vaultInstanceId': '', 'version': 0, 'workgroup': ''},
            'identifier': 'admin', 'password': 'P809rxRbYU', 'passwordChanged': False},
            'dbname': 'Test_db', 'dialect': 'Microsoft SQL Server - MS ODBC Driver',
            'fetchQuery': 'select * from incidents', 'fetch_limit': '3',
            'fetch_parameters': 'Unique sequence ID or unique timestamp',
            'host': 'demistodev-microsoftsqlserver.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com',
            'id_column': None,
            'incidentFetchInterval': '1', 'incidentType': None,
            'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '1433', 'ssl_connect': False, 'start_id': '-1',
            'start_timestamp': '', 'use_pool': False}
TABLE_1 = [{'incident_id': '1000', 'timestamp': '2022-11-08 08:30:42.423000', 'incident_name': 'incident_1',
          'incident_data': 'incident data for incident 1'},
         {'incident_id': '1001', 'timestamp': '2022-11-08 08:32:53.177000',
          'incident_name': 'incident_2', 'incident_data': 'incident data for incident 2'},
         {'incident_id': '1002', 'timestamp': '2022-11-08 08:33:11.680000',
          'incident_name': 'incident_3', 'incident_data': 'incident data for incident 3'},
         {'incident_id': '1003', 'timestamp': '2022-11-08 08:33:28.013000', 'incident_name':
             'incident_4', 'incident_data': 'incident data for incident 4'},
         {'incident_id': '1004', 'timestamp': '2022-11-08 08:38:57.723000',
          'incident_name': 'incident_5', 'incident_data': 'incident data for incident 5'},
         {'incident_id': '1005', 'timestamp': '2022-11-08 09:51:34.420000',
          'incident_name': 'incident_6', 'incident_data': 'incident data for incident 6'},
         {'incident_id': '1006', 'timestamp': '2022-11-08 09:51:49.887000',
          'incident_name': 'incident_6', 'incident_data': 'incident data for incident 6'},
         {'incident_id': '1007', 'timestamp': '2022-11-08 09:52:33.670000',
          'incident_name': 'incident_8', 'incident_data': 'incident data for incident 8'},
         {'incident_id': '1009', 'timestamp': '2022-11-08 09:52:52.150000',
          'incident_name': 'incident_9', 'incident_data': 'incident data for incident 9'},
         {'incident_id': '1010', 'timestamp': '2022-11-08 09:53:11.620000',
          'incident_name': 'incident_10', 'incident_data': 'incident data for incident 10'},
         {'incident_id': '1011', 'timestamp': '2022-11-08 09:53:26.993000',
          'incident_name': 'incident_11', 'incident_data': 'incident data for incident 11'},
         {'incident_id': '1012', 'timestamp': '2022-11-08 09:53:45.190000',
          'incident_name': 'incident_12', 'incident_data': 'incident data for incident 12'}]

# ------------------------------------ test_fetch_incident_without_incidents (2) -------------------------------

HEADERS_2 = "['incident_id', 'timestamp', 'incident_name', 'incident_data']"
RESPONSE_2 = []
LAST_RUN_BEFORE_FETCH_2 = {'last_timestamp': False, 'last_id': '1012', 'ids': []}
PARAMS_2 = {'column_name': 'incident_id', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False, 'modified': '0001-01-01T00:00:00Z',
           'name': '', 'password': '', 'sshkey': '', 'sshkeyPass': '', 'user': '',
           'vaultInstanceId': '', 'version': 0, 'workgroup': ''},
             'identifier': 'admin', 'password': 'P809rxRbYU', 'passwordChanged': False},
            'dbname': 'Test_db', 'dialect': 'Microsoft SQL Server - MS ODBC Driver',
            'fetchQuery': 'select * from incidents', 'fetch_limit': '3',
            'fetch_parameters': 'Unique sequence ID or unique timestamp',
            'host': 'demistodev-microsoftsqlserver.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com',
            'id_column': None,
            'incidentFetchInterval': '1', 'incidentType': None,
            'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '1433', 'ssl_connect': False, 'start_id': '1012',
            'start_timestamp': '', 'use_pool': False}
TABLE_2 = []

# ------------------------------------ test_fetch_incident_avoiding_duplicates (3) -------------------------------

HEADERS_3 = "['incident_id', 'timestamp', 'incident_name', 'incident_data']"
PARAMS_3 = {'column_name': 'timestamp', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False,
                                               'modified': '0001-01-01T00:00:00Z', 'name': '', 'password': '',
                                               'sshkey': '', 'sshkeyPass': '', 'user': '', 'vaultInstanceId': '',
                                               'version': 0, 'workgroup': ''},
             'identifier': 'admin', 'password': 'ICYq7L3S21', 'passwordChanged': False},
            'dbname': 'test_db_1', 'dialect': 'MySQL', 'feed': False, 'fetchQuery': 'call Test_MySQL_5',
            'fetch_limit': '2', 'fetch_parameters': 'ID and timestamp',
            'host': 'demistodev-mysql.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com', 'id_column': 'incident_id',
            'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '3306', 'ssl_connect': False, 'start_id': '', 'start_timestamp': '2 months',
            'use_pool': False}
RESPONSE_3 = [{'incident_id': '1001', 'timestamp': '2022-11-24 13:10:12', 'incident_name': 'incident_2',
               'incident_data': 'incident data for incident 2'},
              {'incident_id': '1002', 'timestamp': '2022-11-24 13:10:31', 'incident_name': 'incident_3',
               'incident_data': 'incident data for incident 3'}]
LAST_RUN_BEFORE_SECOND_FETCH_3 = {'ids': ['1001'], 'last_id': False, 'last_timestamp': '2022-11-24 13:10:12'}
EXPECTED_INCIDENTS_3 = [{'name': 'incident_3', 'occurred': '2022-11-24T13:10:31Z', 'rawJSON':
                        '{"incident_id": "1002", "timestamp": "2022-11-24 13:10:31", "incident_name": "incident_3",'
                         ' "incident_data": "incident data for incident 3"}'}]
TABLE_3 = [{'incident_id': '1001', 'timestamp': '2022-11-24 13:10:12', 'incident_name': 'incident_2',
            'incident_data': 'incident data for incident 2'},
           {'incident_id': '1002', 'timestamp': '2022-11-24 13:10:31', 'incident_name': 'incident_3',
            'incident_data': 'incident data for incident 3'}]

# ------------------------------------ test_fetch_incident_update_last_run (4) -------------------------------

HEADERS_4 = "['incident_id', 'timestamp', 'incident_name', 'incident_data']"
RESPONSE_4_1 = [{'incident_id': '1001', 'timestamp': '2022-11-24 13:10:12', 'incident_name': 'incident_2',
                'incident_data': 'incident data for incident 2'}]
RESPONSE_4_2 = [{'incident_id': '1002', 'timestamp': '2022-11-24 13:10:31', 'incident_name': 'incident_3',
                'incident_data': 'incident data for incident 3'}]
TABLE_4_1 = [{'incident_id': '1001', 'timestamp': '2022-11-24 13:10:12', 'incident_name': 'incident_2',
             'incident_data': 'incident data for incident 2'}]
TABLE_4_2 = [{'incident_id': '1002', 'timestamp': '2022-11-24 13:10:31', 'incident_name': 'incident_3',
             'incident_data': 'incident data for incident 3'}]
PARAMS_4 = {'column_name': 'timestamp', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False,
                                               'modified': '0001-01-01T00:00:00Z', 'name': '', 'password': '',
                                               'sshkey': '', 'sshkeyPass': '', 'user': '', 'vaultInstanceId': '',
                                               'version': 0, 'workgroup': ''},
             'identifier': 'admin', 'password': 'ICYq7L3S21', 'passwordChanged': False},
            'dbname': 'test_db_1', 'dialect': 'MySQL', 'feed': False, 'fetchQuery': 'call Test_MySQL_3',
            'fetch_limit': '2', 'fetch_parameters': 'Unique ascending ID or unique timestamp',
            'host': 'demistodev-mysql.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com', 'id_column': '',
            'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '3306', 'ssl_connect': False, 'start_id': '', 'start_timestamp': '2 months',
            'use_pool': False}

EXPECTED_LAST_RUN_4_1 = {'last_timestamp': '2022-11-24 13:10:12', 'last_id': False, 'ids': []}
EXPECTED_LAST_RUN_4_2 = {'last_timestamp': '2022-11-24 13:10:31', 'last_id': False, 'ids': []}
