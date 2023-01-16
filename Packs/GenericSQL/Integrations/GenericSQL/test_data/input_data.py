import datetime


# ------------------------------------ test_fetch_incident_by_id_simple_query (1) -------------------------------

HEADERS_1 = ['incident_id', 'timestamp', 'incident_name', 'incident_data']
RESPONSE_1 = [(1000, datetime.datetime(2022, 11, 8, 8, 30, 42, 423000), 'incident_1', 'incident data for incident 1'),
              (1001, datetime.datetime(2022, 11, 8, 8, 32, 53, 177000), 'incident_2', 'incident data for incident 2'),
              (1002, datetime.datetime(2022, 11, 8, 8, 33, 11, 680000), 'incident_3', 'incident data for incident 3')]
EXPECTED_INCIDENTS_1 = [{'name': 'incident_1', 'occurred': '2023-01-04T12:57:05Z',
                         'rawJSON': '{"incident_id": "1000", "timestamp": "2022-11-08 08:30:42.423000",'
                                    ' "incident_name": "incident_1", "incident_data": "incident data for incident 1",'
                                    ' "type": "GenericSQL Record"}'},
                        {'name': 'incident_2', 'occurred': '2023-01-04T12:57:05Z',
                         'rawJSON': '{"incident_id": "1001", "timestamp": "2022-11-08 08:32:53.177000",'
                                    ' "incident_name": "incident_2", "incident_data": "incident data for incident 2",'
                                    ' "type": "GenericSQL Record"}'},
                        {'name': 'incident_3', 'occurred': '2023-01-04T12:57:05Z',
                         'rawJSON': '{"incident_id": "1002", "timestamp": "2022-11-08 08:33:11.680000",'
                                    ' "incident_name": "incident_3", "incident_data": "incident data for incident 3",'
                                    ' "type": "GenericSQL Record"}'}]
EXPECTED_LAST_RUN_1 = {'last_timestamp': False, 'last_id': '1002', 'ids': []}
PARAMS_1 = {'column_name': 'incident_id', 'connect_parameters': None,
            'credentials': {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False, 'modified':
                            '0001-01-01T00:00:00Z', 'name': '', 'password': '', 'sshkey': '', 'sshkeyPass': '',
                                                              'user': '', 'vaultInstanceId': '', 'version': 0,
                                                              'workgroup': ''},
                            'identifier': 'admin', 'password': 'admin', 'passwordChanged': False},
            'dbname': 'Test_db', 'dialect': 'Microsoft SQL Server', 'max_fetch': '3',
            'fetch_parameters': 'Unique ascending ID',
            'host': 'demistodev-microsoftsqlserver.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com',
            'id_column': '', 'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name',
            'isFetch': True, 'pool_ttl': '600', 'port': '1433',
            'query': 'select * from incidents where incident_id >:incident_id order by incident_id',
            'ssl_connect': False, 'first_fetch': '-1', 'use_pool': False}
TABLE_1 = [{'incident_id': '1000', 'timestamp': '2022-11-08 08:30:42.423000', 'incident_name': 'incident_1',
            'incident_data': 'incident data for incident 1'},
           {'incident_id': '1001', 'timestamp': '2022-11-08 08:32:53.177000', 'incident_name': 'incident_2',
            'incident_data': 'incident data for incident 2'}, {'incident_id': '1002',
                                                               'timestamp': '2022-11-08 08:33:11.680000',
                                                               'incident_name': 'incident_3',
                                                               'incident_data': 'incident data for incident 3'}]

# ------------------------------------ test_fetch_incident_without_incidents (2) -------------------------------

HEADERS_2 = []
RESPONSE_2 = []
LAST_RUN_BEFORE_FETCH_2 = {'last_timestamp': False, 'last_id': '1012', 'ids': []}
PARAMS_2 = {'column_name': 'incident_id', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False,
                                               'modified': '0001-01-01T00:00:00Z',
                                               'name': '', 'password': '', 'sshkey': '', 'sshkeyPass': '', 'user': '',
                                               'vaultInstanceId': '', 'version': 0, 'workgroup': ''},
             'identifier': 'admin', 'password': 'admin', 'passwordChanged': False},
            'dbname': 'Test_db', 'dialect': 'Microsoft SQL Server', 'max_fetch': '3',
            'fetch_parameters': 'Unique ascending ID',
            'host': 'demistodev-microsoftsqlserver.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com', 'id_column': '',
                    'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name', 'isFetch': True,
                    'pool_ttl': '600', 'port': '1433',
                    'query': 'select * from incidents where incident_id >:incident_id order by incident_id',
                    'ssl_connect': False, 'first_fetch': '1012', 'use_pool': False}
TABLE_2 = []

# ------------------------------------ test_fetch_incident_avoiding_duplicates (3) -------------------------------

HEADERS_3 = ['incident_id', 'timestamp', 'incident_name', 'incident_data']
PARAMS_3 = {'column_name': 'timestamp', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False, 'modified': '0001-01-01T00:00:00Z',
             'name': '', 'password': '', 'sshkey': '', 'sshkeyPass': '', 'user': '', 'vaultInstanceId': '',
                                               'version': 0, 'workgroup': ''},
             'identifier': 'admin', 'password': 'admin', 'passwordChanged': False}, 'dbname': 'test_db_1',
            'dialect': 'MySQL', 'max_fetch': '2', 'fetch_parameters': 'ID and timestamp',
            'host': 'demistodev-mysql.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com', 'id_column': 'incident_id',
            'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '3306', 'query': 'call Test_MySQL_6', 'ssl_connect': False,
            'first_fetch': '2022-11-24 13:09:56', 'use_pool': False}
RESPONSE_3 = [(1000, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_1', 'incident data for incident 1'),
              (1001, datetime.datetime(2022, 11, 24, 13, 10, 12), 'incident_2', 'incident data for incident 2')]
LAST_RUN_BEFORE_SECOND_FETCH_3 = {'last_timestamp': '2022-11-24 13:09:56', 'last_id': False, 'ids': ['1000']}
EXPECTED_INCIDENTS_3 = [{'name': 'incident_2', 'occurred': '2022-11-24T13:10:12Z',
                         'rawJSON': '{"incident_id": "1001", "timestamp": "2022-11-24 13:10:12",'
                                    ' "incident_name": "incident_2", "incident_data": "incident data for incident 2",'
                                    ' "type": "GenericSQL Record"}'}]
TABLE_3 = [{'incident_id': '1000', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_1',
            'incident_data': 'incident data for incident 1'},
           {'incident_id': '1001', 'timestamp': '2022-11-24 13:10:12', 'incident_name': 'incident_2',
            'incident_data': 'incident data for incident 2'}]

# ------------------------------------ test_fetch_incident_update_last_run (4) -------------------------------

HEADERS_4 = ['incident_id', 'timestamp', 'incident_name', 'incident_data']
RESPONSE_4_1 = [(1000, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_1', 'incident data for incident 1'),
                (1001, datetime.datetime(2022, 11, 24, 13, 10, 12), 'incident_2', 'incident data for incident 2')]
RESPONSE_4_2 = [(1002, datetime.datetime(2022, 11, 24, 13, 10, 31), 'incident_3', 'incident data for incident 3'),
                (1003, datetime.datetime(2022, 11, 24, 13, 10, 43), 'incident_4', 'incident data for incident 4')]
TABLE_4_1 = [{'incident_id': '1000', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_1',
              'incident_data': 'incident data for incident 1'},
             {'incident_id': '1001', 'timestamp': '2022-11-24 13:10:12', 'incident_name': 'incident_2',
              'incident_data': 'incident data for incident 2'}]
TABLE_4_2 = [{'incident_id': '1002', 'timestamp': '2022-11-24 13:10:31', 'incident_name': 'incident_3',
              'incident_data': 'incident data for incident 3'},
             {'incident_id': '1003', 'timestamp': '2022-11-24 13:10:43', 'incident_name': 'incident_4',
              'incident_data': 'incident data for incident 4'}]
PARAMS_4 = {'column_name': 'timestamp', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False,
                                               'modified': '0001-01-01T00:00:00Z', 'name': '', 'password': '',
                                               'sshkey': '', 'sshkeyPass': '', 'user': '',
             'vaultInstanceId': '', 'version': 0, 'workgroup': ''}, 'identifier': 'admin', 'password': 'admin',
             'passwordChanged': False}, 'dbname': 'test_db_1', 'dialect': 'MySQL', 'max_fetch': '2',
            'fetch_parameters': 'Unique timestamp',
            'host': 'demistodev-mysql.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com', 'id_column': '',
            'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '3306', 'query': 'call Test_MySQL_3', 'ssl_connect': False,
            'first_fetch': '2020-01-01 01:01:01', 'use_pool': False}

EXPECTED_LAST_RUN_4_1 = {'last_timestamp': '2022-11-24 13:10:12', 'last_id': False, 'ids': []}
EXPECTED_LAST_RUN_4_2 = {'ids': [], 'last_id': False, 'last_timestamp': '2022-11-24 13:10:43'}


# ------------------------------------ test_fetch_incidents_de_duplication (5) -------------------------------

HEADERS_5 = ['incident_id', 'timestamp', 'incident_name', 'incident_data']
RESPONSE_5_1 = [(1000, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_1', 'incident data for incident 1')]
RESPONSE_5_2 = [(1000, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_1', 'incident data for incident 1'),
                (1001, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_2', 'incident data for incident 2')]
RESPONSE_5_3 = [(1000, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_1', 'incident data for incident 1'),
                (1001, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_2', 'incident data for incident 2'),
                (1002, datetime.datetime(2022, 11, 24, 13, 9, 56), 'incident_3', 'incident data for incident 3')]
TABLE_5_1 = [{'incident_id': '1000', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_1',
              'incident_data': 'incident data for incident 1'}]
TABLE_5_2 = [{'incident_id': '1000', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_1',
              'incident_data': 'incident data for incident 1'},
             {'incident_id': '1001', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_2',
              'incident_data': 'incident data for incident 2'}]
TABLE_5_3 = [{'incident_id': '1000', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_1',
              'incident_data': 'incident data for incident 1'},
             {'incident_id': '1001', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_2',
              'incident_data': 'incident data for incident 2'},
             {'incident_id': '1002', 'timestamp': '2022-11-24 13:09:56', 'incident_name': 'incident_3',
              'incident_data': 'incident data for incident 3'}]
PARAMS_5 = {'column_name': 'timestamp', 'connect_parameters': None, 'credentials':
            {'credential': '', 'credentials': {'cacheVersn': 0, 'id': '', 'locked': False,
                                               'modified': '0001-01-01T00:00:00Z', 'name': '', 'password': '',
                                               'sshkey': '', 'sshkeyPass': '', 'user': '',
             'vaultInstanceId': '', 'version': 0, 'workgroup': ''}, 'identifier': 'admin', 'password': 'admin',
             'passwordChanged': False}, 'dbname': 'test_db_1', 'dialect': 'MySQL', 'max_fetch': '1',
            'fetch_parameters': 'ID and timestamp',
            'host': 'demistodev-mysql.cb1lbinsdk4m.eu-central-1.rds.amazonaws.com', 'id_column': 'incident_id',
            'incidentFetchInterval': '1', 'incidentType': None, 'incident_name': 'incident_name', 'isFetch': True,
            'pool_ttl': '600', 'port': '3306', 'query': 'call Test_MySQL_6', 'ssl_connect': False,
            'first_fetch': '2020-01-01 01:01:01', 'use_pool': False}

EXPECTED_LAST_RUN_5_1 = {'last_timestamp': '2022-11-24 13:09:56', 'last_id': False, 'ids': ['1000']}
EXPECTED_LAST_RUN_5_2 = {'ids': ['1000', '1001'], 'last_id': False, 'last_timestamp': '2022-11-24 13:09:56'}
EXPECTED_LAST_RUN_5_3 = {'ids': ['1000', '1001', '1002'], 'last_id': False, 'last_timestamp': '2022-11-24 13:09:56'}
