import pytest
import Endace
from CommonServerPython import *

APPLIANCEURL = "https://probe-1"
USERNAME = 'admin'
PASSWORD = 'password'
INSECURE = False
HOSTNAME = 'probehost'

'''HELPER FUNCTIONS'''


@staticmethod
def mock_login_session():
    return requests.Session()


@staticmethod
def mock_logout_session():
    return True


class MockRequestsResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


def mocked_requests_post(*args):
    # Register mock responses for post requests
    mock_responses = [
        {
            "url": args[0] + args[1],
            "status_code": args[2],
            "resp": {"meta": {"error": args[3], "error_data": args[4], "paging": False, "history": False},
                     "payload": args[1]}
        }
    ]
    for resp in mock_responses:
        if args[0] + args[1] == resp["url"]:
            return MockRequestsResponse(json.loads(json.dumps(resp["resp"])), resp["status_code"])
    return MockRequestsResponse(None, 404)


def mocked_requests_delete(*args):
    # Register mock responses for post requests
    mock_responses = [
        {
            "url": args[0],
            "status_code": args[1],
            "resp": {"meta": {"error": args[2], "error_data": args[3], "paging": False, "history": False},
                     "payload": "18360fb0-72f7-442a-9e9c-fb1be462e037"}
        }
    ]
    for resp in mock_responses:
        if args[0] == resp["url"]:
            return MockRequestsResponse(json.loads(json.dumps(resp["resp"])), resp["status_code"])
    return MockRequestsResponse(None, 404)


def mock_requests_get(*args):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

        def status_code(self):
            return self.status_code

        def content(self):
            return b'0122445'

    if args[0] == 'https://probe-1/vision2/data/files':
        if args[2] == 1:
            return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                                 'payload': [{'id': '18360fb0-72f7-442a-9e9c-fb1be462e037', 'user': 'admin',
                                              'name': 'Main', 'probeName': 'probe1',
                                              'probeSerialNumber': 'NNG0123456789', 'type': 'rotation_file_v2',
                                              'size': '2.00TB', 'usage': '1.82TB', 'visionEnabled': True,
                                              'status': {'inUse': False}},
                                             {'id': '81fa5812-92b0-586a-770c-80fc44f19343',
                                              'name': 'archived_1234567890', 'probeName': 'probe1',
                                              'probeSerialNumber': 'NNG0123456789', 'size': '28.61MB',
                                              'status': {'inUse': False}, 'type': 'archive_file', 'usage': '28.60MB',
                                              'user': 'admin', 'visionEnabled': True}
                                             ]}, args[1])
        elif args[2] == 2:
            return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                                 'payload': [{'id': '18360fb0-72f7-442a-9e9c-fb1be462e037',
                                              'name': 'archived_1234567890', 'probeName': 'probe1',
                                              'probeSerialNumber': 'NNG0123456789', 'size': '28.61MB',
                                              'status': {'inUse': True}, 'type': 'archive_file', 'usage': '28.60MB',
                                              'user': 'admin', 'visionEnabled': True},
                                             ]}, args[1])
        elif args[2] == 3:
            return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                                 'payload': [{'id': '18360fb0-72f7-442a-9e9c-fb1be462e037', 'user': 'admin',
                                              'name': 'Main', 'probeName': 'probe1',
                                              'probeSerialNumber': 'NNG0123456789', 'type': 'rotation_file_v2',
                                              'size': '2.00TB', 'usage': '1.82TB', 'visionEnabled': True,
                                              'status': {'inUse': False}}
                                             ]}, args[1])
        elif args[2] == 4:
            return MockResponse({'meta': {'error': "Error", 'error_data': None, 'paging': False,
                                          'history': False}, 'payload': []}, args[1])

    elif args[0] == 'https://probe-1/vision2/data/files/698a82fc-e954-c5f7-f691-19afe609bb18/stream?format=pcap':
        return MockResponse(b'1234567', args[1])

    elif args[0] == 'https://probe-1/vision2/data/datasources':
        return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                             'payload': [{'id': '18360fb0-72f7-442a-9e9c-fb1be462e037', 'type': 'archive_file',
                                          'name': 'archivedfile_1234567890', 'probeName': 'probe1',
                                          'vision': True, 'status': {'inUse': False}, 'tags': ['all', 'archive']},
                                         {'id': '698a82fc-e954-c5f7-f691-19afe609bb18', 'type': 'rotation_file_v2',
                                          'name': 'Main', 'probeName': 'probe1', 'vision': True,
                                          'status': {'inUse': True}, 'tags': ['all', 'rotation-file']}]}, args[1])

    elif args[0] == 'https://probe-1/vision2/data/queries/18360fb0-72f7-442a-9e9c-fb1be462e037':
        if args[2] == 1:
            return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                                'payload': {'state': 'running', 'progress': 40,
                                            'data': [{'id': 'OTHER', 'name': 'other'}], 'top_keys': [],
                                            'top_values': []}}, args[1])
        elif args[2] == 2:
            return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                                'payload': {'state': 'running', 'progress': 40,
                                            'data': [{'id': 'OTHER', 'name': 'other'}], 'top_keys': [],
                                            'top_values': []}}, args[1])
        else:
            return MockResponse({'meta': {'error': False, 'error_data': None, 'paging': False, 'history': False},
                                'payload': {'state': 'complete', 'progress': 100,
                                            'data': [{'id': '18360fb0-72f7-442a-9e9c-fb1be462e037',
                                                      'name': 'probe-1:Main'}],
                                            'top_keys': ['18360fb0-72f7-442a-9e9c-fb1be462e037'],
                                            'top_values': [10000]}}, args[1])

    return MockResponse(None, 404)


'''Input Parameters and Arguments'''


@pytest.mark.parametrize("arg", ['http://probe-1.test.com', 'http://probe-1', 'http://10.0.0.1',
                                 'https://probe-1'])
def test_applianceurl_arg(arg, monkeypatch):

    monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
    monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

    applianceurl = arg
    with pytest.raises(ValueError) as excinfo:
        Endace.endace_test_command(applianceurl, USERNAME, PASSWORD, INSECURE)
    assert "Wrong" in str(excinfo.value)


@pytest.mark.parametrize(
    "args", [{'start': '', 'end': '', 'search_window': '', 'src_host_list': '', 'dest_host_list': '',
              'src_port_list': '', 'dest_port_list': ''},
             {'start': '2020-03-23', 'end': '', 'search_window': '3600', 'src_host_list': 'a.b.c.d',
              'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''},
             {'start': '2020-03-23T18:31:25+000', 'end': '', 'search_window': '3600',
              'src_host_list': 'a.b.c.d', 'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''},
             {'start': '2020-03-23T18:31:25Z', 'end': '', 'search_window': '3600', 'src_host_list': 'a.b.c.d',
              'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''},
             {'start': '', 'end': '2020-03-23', 'search_window': '3600', 'src_host_list': 'a.b.c.d',
              'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''},
             {'start': '', 'end': '2020-03-23T18:31:25+000', 'search_window': '3600', 'src_host_list': 'a.b.c.d',
              'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''},
             {'start': '', 'end': '2020-03-23T18:31:25Z', 'search_window': '3600', 'src_host_list': 'a.b.c.d',
              'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''},
             {'start': '2020-03-23T18:31:25', 'end': '2020-03-23T18:32:25', 'search_window': '3600',
              'src_host_list': '', 'dest_host_list': '', 'src_port_list': '', 'dest_port_list': ''}])
def test_endace_get_input_arguments(args):
    app = Endace.EndaceApp(APPLIANCEURL, USERNAME, PASSWORD, INSECURE, HOSTNAME)
    with pytest.raises(ValueError) as excinfo:
        app.endace_get_input_arguments(args)
    assert "Wrong" or "match" in str(excinfo.value)


@pytest.mark.parametrize(
    "args", [{'jobid': '18360fb0'}, {'jobid': '18360fb0-72f7-442a-9e9c'},
             {'jobid': ' 18360fb0-72f7-442a-9e9cfb1be462e037'}])
def test_endace_get_search_status_args(args, monkeypatch):
    def mock_endaceapp_get_search_status():
        return {}
    monkeypatch.setattr(Endace.EndaceApp, "get_search_status", mock_endaceapp_get_search_status)
    monkeypatch.setattr(Endace.EndaceApp, "delta_time", 1)
    monkeypatch.setattr(Endace.EndaceApp, "wait_time", 1)

    app = Endace.EndaceApp(APPLIANCEURL, USERNAME, PASSWORD, INSECURE, HOSTNAME)
    with pytest.raises(ValueError) as excinfo:
        Endace.endace_get_search_status_command(app, args)
    assert "Wrong" or "match" in str(excinfo.value)


'''COMMAND TEST FUNCTIONS'''


def test_endace_test_command(monkeypatch):

    monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
    monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

    result = Endace.endace_test_command("https://probe-1.fqdn.com", USERNAME, PASSWORD, INSECURE)
    assert result == 'ok'


class TestEndaceAPPSearch:
    APPLIANCEURL = "https://probe-1"
    USERNAME = 'admin'
    PASSWORD = 'password'
    INSECURE = False
    HOSTNAME = 'probehost'

    search_args = {'start': '2020-02-28T16:15:02', 'end': '2020-02-28T16:16:02', 'timeframe': '1h',
                   'src_host_list': 'a.b.c.3,a.b.c.4,a.b.c.5', 'dest_host_list': '',
                   'src_port_list': '', 'dest_port_list': '', 'protocol': ''}

    @pytest.mark.parametrize(
        "input_var, expected", [(('https://probe-1/vision2/data/files', 200, 1),
                                 ("NoError", "18360fb0-72f7-442a-9e9c-fb1be462e037", 'Started'))])
    def test_endace_create_search_command_files(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get(input_var[0], input_var[1], input_var[2])

        def mock_post(*args, **kwargs):
            return mocked_requests_post('https://probe-1/vision2/data/queries/',
                                        '18360fb0-72f7-442a-9e9c-fb1be462e037', 200, False, None)

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)
        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "post", mock_post)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)

        _, output, _ = Endace.endace_create_search_command(app, self.search_args)
        assert (output['Endace.Search.Task(val.JobID == obj.JobID)']['Error']) == expected[0]
        assert (output['Endace.Search.Task(val.JobID == obj.JobID)']['JobID']) == expected[1]
        assert (output['Endace.Search.Task(val.JobID == obj.JobID)']['Status']) == expected[2]

    @pytest.mark.parametrize(
        "input_var, expected", [(('https://probe-1/vision2/data/queries/',
                                  '18360fb0-72f7-442a-9e9c-fb1be462e037', 200, False, None),
                                 ("NoError", "18360fb0-72f7-442a-9e9c-fb1be462e037", 'Started'))])
    def test_endace_create_search_command(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get('https://probe-1/vision2/data/files', 200, 1)

        def mock_post(*args, **kwargs):
            return mocked_requests_post(input_var[0], input_var[1], input_var[2], input_var[3], input_var[4])

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)
        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "post", mock_post)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)

        _, output, _ = Endace.endace_create_search_command(app, self.search_args)
        assert (output['Endace.Search.Task(val.JobID == obj.JobID)']['Error']) == expected[0]
        assert (output['Endace.Search.Task(val.JobID == obj.JobID)']['JobID']) == expected[1]
        assert (output['Endace.Search.Task(val.JobID == obj.JobID)']['Status']) == expected[2]

    @pytest.mark.parametrize(
        "input_var, expected", [(('18360fb0-72f7-442a-9e9c-fb1be462e037', 200),
                                 ("NoError", "18360fb0-72f7-442a-9e9c-fb1be462e037", 'Deleted'))])
    def test_endace_delete_search_task_command(self, input_var, expected, monkeypatch):

        def mock_get(*args):
            return mock_requests_get('https://probe-1/vision2/data/files', 200, 1)

        def mock_delete(*args):
            return mocked_requests_delete(f'https://probe-1/vision2/data/queries/{input_var[0]}',
                                          input_var[1], False, None)

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get)
        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "delete", mock_delete)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)
        _, output, _ = Endace.endace_delete_search_task_command(app, {"jobid": input_var[0]})
        assert (output['Endace.Search.Delete(val.JobID == obj.JobID)']['Error']) == expected[0]
        assert (output['Endace.Search.Delete(val.JobID == obj.JobID)']['JobID']) == expected[1]
        assert (output['Endace.Search.Delete(val.JobID == obj.JobID)']['Status']) == expected[2]

        # input_vars: "jobid, http post statuscode, delta_time, payload types"
        # output: "query error, jobid, query status, progress, [rotfilename], bytes"
    @pytest.mark.parametrize(
        "input_var, expected", [(('18360fb0-72f7-442a-9e9c-fb1be462e037', 200, 1, 0),
                                 ("NoError", "18360fb0-72f7-442a-9e9c-fb1be462e037", 'complete', '100',
                                  ["probe-1:Main"], 10000))])
    def test_endace_get_search_status_command(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get('https://probe-1/vision2/data/files', 200, 1)

        def mock_get_queries(*args):
            return mock_requests_get(f'https://probe-1/vision2/data/queries/{input_var[0]}',
                                     input_var[1], input_var[3])

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)
        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_queries)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)
        monkeypatch.setattr(Endace.EndaceApp, "delta_time", input_var[2])
        monkeypatch.setattr(Endace.EndaceApp, "wait_time", 1)

        _, output, _ = Endace.endace_get_search_status_command(app, {"jobid": input_var[0]})
        assert (output['Endace.Search.Response(val.JobID == obj.JobID)']['Error']) == expected[0]
        assert (output['Endace.Search.Response(val.JobID == obj.JobID)']['JobID']) == expected[1]
        assert (output['Endace.Search.Response(val.JobID == obj.JobID)']['Status']) == expected[2]
        assert (output['Endace.Search.Response(val.JobID == obj.JobID)']['JobProgress']) == expected[3]
        assert (output['Endace.Search.Response(val.JobID == obj.JobID)']['DataSources']) == expected[4]
        assert (output['Endace.Search.Response(val.JobID == obj.JobID)']['TotalBytes']) == expected[5]


class TestEndaceAPPArchive:
    APPLIANCEURL = "https://probe-1"
    USERNAME = 'admin'
    PASSWORD = 'password'
    INSECURE = False
    HOSTNAME = 'probehost'

    search_args = {'start': '2020-02-28T16:15:02', 'end': '2020-02-28T16:16:02', 'timeframe': '1h',
                   'src_host_list': 'a.b.c.3,a.b.c.4', 'dest_host_list': '', 'src_port_list': '', 'dest_port_list': '',
                   'protocol': '', 'archive_filename': "eventid_1234567890", }

    @pytest.mark.parametrize(
        "input_var", [{'archive_filename': "eventid_1234567890"}, {'archive_filename': "'%@filename"},
                      {'archive_filename': "file&8827name"}, {'archive_filename': ''}])
    def test_archive_filename(self, input_var, monkeypatch):
        def mock_endaceapp_create_archive_task(*args):
            return {}
        monkeypatch.setattr(Endace.EndaceApp, "create_archive_task", mock_endaceapp_create_archive_task)

        app = Endace.EndaceApp(APPLIANCEURL, USERNAME, PASSWORD, INSECURE, HOSTNAME)
        with pytest.raises(ValueError or TypeError) as excinfo:
            Endace.endace_create_archive_command(app, input_var)
        assert "Wrong" or "match" in str(excinfo.value)

    @pytest.mark.parametrize(
        "input_var, expected", [(('https://probe-1/vision2/data/archive/',
                                  '18360fb0-72f7-442a-9e9c-fb1be462e037', 200, False, None),
                                 ("NoError", "18360fb0-72f7-442a-9e9c-fb1be462e037", 'Started', 'eventid'))])
    def test_endace_create_archive_command(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get('https://probe-1/vision2/data/datasources', 200)

        def mock_post(*args, **kwargs):
            return mocked_requests_post(input_var[0], input_var[1], input_var[2], input_var[3], input_var[4])

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)
        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "post", mock_post)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)

        _, output, _ = Endace.endace_create_archive_command(app, self.search_args)
        assert (output['Endace.Archive.Task(val.JobID == obj.JobID)']['Error']) == expected[0]
        assert (output['Endace.Archive.Task(val.JobID == obj.JobID)']['JobID']) == expected[1]
        assert (output['Endace.Archive.Task(val.JobID == obj.JobID)']['Status']) == expected[2]
        assert (expected[3] in output['Endace.Archive.Task(val.JobID == obj.JobID)']['FileName'])

    # input_vars: "archive_filename, http post statuscode, delta_time, payload types"
    @pytest.mark.parametrize(
        "input_var, expected", [(('archived_1234567890', 200, 1, 1), ("NoError", "archived_1234567890", 'Finished')),
                                (('archived_1234567890', 200, 1, 2), ("NoError", 'archived_1234567890', 'InProgress')),
                                (('archived', 200, 1, 3), ("NoError", 'archived', 'InProgress'))])
    def test_endace_get_archive_status_command(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get('https://probe-1/vision2/data/files', 200, input_var[3])

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)
        monkeypatch.setattr(Endace.EndaceApp, "delta_time", input_var[2])
        monkeypatch.setattr(Endace.EndaceApp, "wait_time", 1)

        _, output, _ = Endace.endace_get_archive_status_command(app, {"archive_filename": input_var[0]})
        assert (output['Endace.Archive.Response(val.FileName == obj.FileName)']['Error']) == expected[0]
        assert (output['Endace.Archive.Response(val.FileName == obj.FileName)']['FileName']) == expected[1]
        assert (output['Endace.Archive.Response(val.FileName == obj.FileName)']['Status']) == expected[2]

    # input_vars: "filename, http del statuscode, delete status, delete error "
    @pytest.mark.parametrize(
        "input_var, expected",
        [(('18360fb0-72f7-442a-9e9c-fb1be462e037', 200, False, False, "archived_1234567890", 1),
          ('NoError', 'archived_1234567890', 'FileDeleted')),
         (('18360fb0-72f7-442a-9e9c-fb1be462e037', 400, False, False, "archived_1234567890", 1),
          ('ServerError - HTTP 200 to /files', 'archived_1234567890', 'FileNotFound')),
         (('18360fb0-72f7-442a-9e9c-fb1be462e037', 200, False, False, "archived", 1),
          ('NoError', 'archived', 'FileNotFound')),
         (('18360fb0-72f7-442a-9e9c-fb1be462e037', 200, None, False, "archived", 3),
          ('NoError', 'archived', 'FileNotFound')),
         (('18360fb0-72f7-442a-9e9c-fb1be462e037', 200, None, "ServerError - HTTP 200 to /files", "archived", 1),
          ('NoError', 'archived', 'FileNotFound'))])
    def test_endace_delete_archived_file_command(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get('https://probe-1/vision2/data/files', 200, input_var[5])

        def mock_delete(*args):
            return mocked_requests_delete(f'https://probe-1/vision2/data/files?_=01234567890'
                                          f'&files={input_var[0]}', input_var[1], input_var[2], input_var[3])

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)
        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "delete", mock_delete)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)
        monkeypatch.setattr(Endace.EndaceApp, "delta_time", input_var[2])
        monkeypatch.setattr(Endace.EndaceApp, "wait_time", 1)

        _, output, _ = Endace.endace_delete_archived_file_command(app, {"archived_filename": input_var[4]})
        assert (output['Endace.ArchivedFile.Delete(val.FileName == obj.FileName)']['Error']) == expected[0]
        assert (output['Endace.ArchivedFile.Delete(val.FileName == obj.FileName)']['FileName']) == expected[1]
        assert (output['Endace.ArchivedFile.Delete(val.FileName == obj.FileName)']['Status']) == expected[2]


class TestEndaceAppDownload:
    APPLIANCEURL = "https://probe-1"
    USERNAME = 'admin'
    PASSWORD = 'password'
    INSECURE = False
    HOSTNAME = 'probehost'

    # (('archived_1234567890', 1, '28.61MB', '100000'),
    # input_vars: "filename, http del statuscode, delete status, delete error "
    # ('NoError', '28.61MB', 'DownloadFinished', 'archived_1234567890', 'admin'))
    @pytest.mark.parametrize(
        "input_var, expected", {(('archived_1234567890', 1, '28.61MB', '1'),
                                 ('NoError', 0, 'FileExceedsSizeLimit', 'archived_1234567890', 'admin'))
                                })
    def test_endace_download_pcap_command(self, input_var, expected, monkeypatch):

        def mock_get_files(*args):
            return mock_requests_get('https://probe-1/vision2/data/files', 200, input_var[1])

        def mock_get_pcap(*args, **kwargs):
            return mock_requests_get('https://probe-1/vision2/data/files/'
                                     '698a82fc-e954-c5f7-f691-19afe609bb18/stream?format=pcap', 200, 5)

        def mock_fileresult(*args, **kwargs):
            return {}

        def mock_demisto_results(*args, **kwargs):
            return ''

        monkeypatch.setattr(Endace.EndaceWebSession, "_create_login_session", mock_login_session)
        monkeypatch.setattr(Endace.EndaceWebSession, "logout", mock_logout_session)

        monkeypatch.setattr(Endace.EndaceVisionAPIAdapter, "get", mock_get_files)

        app = Endace.EndaceApp(self.APPLIANCEURL, self.USERNAME, self.PASSWORD, self.INSECURE, self.HOSTNAME)
        monkeypatch.setattr(Endace.EndaceApp, "delta_time", input_var[2])
        monkeypatch.setattr(Endace.EndaceApp, "wait_time", 1)
        monkeypatch.setattr(demisto, "results", mock_demisto_results)

        _, output, _ = Endace.endace_download_pcap_command(app, {"filename": input_var[0],
                                                                 'filesizelimit': input_var[3]})
        assert (output['Endace.Download.PCAP(val.FileName == obj.FileName)']['Error']) == expected[0]
        assert (output['Endace.Download.PCAP(val.FileName == obj.FileName)']['Status']) == expected[2]
        assert (output['Endace.Download.PCAP(val.FileName == obj.FileName)']['FileSize']) == expected[1]
