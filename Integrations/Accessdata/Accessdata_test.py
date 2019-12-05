import demistomock as demisto
from CommonServerPython import *
from Accessdata import Client, create_jobstate_context, create_contents, wrap_jobstate_context, main
from test_data.constants import MOCK_URL, FAKE_SITESERVER_TOKEN, JOB_JUST_WITHOUT_CASEJOBID, JOB_JUST_WITH_CASEJOBID, \
    MOCK_PARAMS, MOCK_TEST_MODULE_RESPONSE, MOCK_GET_STATUS_ARGS, MOCK_GET_JOBSTATUS_PROCESSLIST_RESPONSE, MOCK_BASE_URL, \
    MOCK_GET_JOBSTATUS_MEMORYDUMP_RESPONSE, MOCK_ADD_JOB_ARGS, MOCK_READ_CASEFILE_ARGS, MOCK_READ_CASEFILE_RESPONSE


def create_client():
    return Client(base_url=MOCK_URL, verify=None, proxy=None, token=FAKE_SITESERVER_TOKEN)


def test_create_jobstate_context_WITHOUT_CASEJOBID():
    assert create_jobstate_context(JOB_JUST_WITHOUT_CASEJOBID) == {
        'Accessdata.Job(val.ID == obj.ID)': {
            'CaseID': 1,
            'ID': 2,
            'Type': 'JobType',
            'State': 'Unknown',
            'Result': 'Some result'
        }
    }


def test_create_jobstate_context_WITH_CASEJOBID():
    assert create_jobstate_context(JOB_JUST_WITH_CASEJOBID) == {
        'Accessdata.Job(val.CaseJobID == obj.CaseJobID)': {
            'CaseID': 1,
            'ID': 2,
            'CaseJobID': '1_2',
            'Type': 'JobType',
            'State': 'Unknown',
            'Result': 'Some result'
        }
    }


def test_create_contents():
    assert create_contents(1, 2) == {
        'CaseID': 1,
        'ID': 2,
        'CaseJobID': '1_2'
    }
    assert create_contents(1, 2, state='Unknown') == {
        'CaseID': 1,
        'ID': 2,
        'CaseJobID': '1_2',
        'State': 'Unknown'
    }
    assert create_contents(1, 2, result='Some result') == {
        'CaseID': 1,
        'ID': 2,
        'CaseJobID': '1_2',
        'Result': 'Some result'
    }


def test_wrap_jobstate_context():
    assert wrap_jobstate_context(JOB_JUST_WITH_CASEJOBID) == {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {
            'CaseID': 1,
            'ID': 2,
            'CaseJobID': '1_2',
            'Type': 'JobType',
            'State': 'Unknown',
            'Result': 'Some result'
        },
        'HumanReadable': "",
        'EntryContext': {
            'Accessdata.Job(val.CaseJobID == obj.CaseJobID)': {
                'CaseID': 1,
                'ID': 2,
                'CaseJobID': '1_2',
                'Type': 'JobType',
                'State': 'Unknown',
                'Result': 'Some result'
            }
        }
    }


def mock_demisto(mocker, mock_args, command):
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'results')


def test_command_test_module(mocker, requests_mock):
    mock_demisto(mocker, None, 'test-module')
    test_route = 'api/v2/enterpriseapi/statuscheck'
    requests_mock.get(MOCK_URL + test_route, text=MOCK_TEST_MODULE_RESPONSE)
    main()
    results = demisto.results.call_args[0]
    assert results[0] == 'ok'


def test_command_accessdata_get_jobstatus_processlist(mocker, requests_mock):
    mock_demisto(mocker, MOCK_GET_STATUS_ARGS, 'accessdata-get-jobstatus-processlist')
    status_route = 'api/v2/enterpriseapi/core/' + str(MOCK_GET_STATUS_ARGS["caseID"]) + \
        '/getjobstatus/' + str(MOCK_GET_STATUS_ARGS["jobID"])
    requests_mock.get(MOCK_URL + status_route, json=MOCK_GET_JOBSTATUS_PROCESSLIST_RESPONSE)
    main()
    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['Accessdata.Job(val.CaseJobID == obj.CaseJobID)']
    assert entry_context['CaseID'] == MOCK_GET_STATUS_ARGS["caseID"]
    assert entry_context['ID'] == MOCK_GET_STATUS_ARGS["jobID"]
    assert entry_context['CaseJobID'] == str(MOCK_GET_STATUS_ARGS["caseID"]) + "_" + str(MOCK_GET_STATUS_ARGS["jobID"])
    assert entry_context['State'] == 'Success'
    assert entry_context['Result'] == '\\\\' + MOCK_BASE_URL + '\\D$\\Program Files\\AccessData\\' + \
        'QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_967\\' + \
        'eb849680-2e81-4416-b1b5-5047fd1bc4b1\\1\\snapshot.xml'


def test_command_accessdata_get_jobstatus_memorydump(mocker, requests_mock):
    mock_demisto(mocker, MOCK_GET_STATUS_ARGS, 'accessdata-get-jobstatus-memorydump')
    status_route = 'api/v2/enterpriseapi/core/' + str(MOCK_GET_STATUS_ARGS["caseID"]) + \
        '/getjobstatus/' + str(MOCK_GET_STATUS_ARGS["jobID"])
    requests_mock.get(MOCK_URL + status_route, json=MOCK_GET_JOBSTATUS_MEMORYDUMP_RESPONSE)
    main()
    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['Accessdata.Job(val.CaseJobID == obj.CaseJobID)']

    assert entry_context['CaseID'] == MOCK_GET_STATUS_ARGS["caseID"]
    assert entry_context['ID'] == MOCK_GET_STATUS_ARGS["jobID"]
    assert entry_context['CaseJobID'] == str(MOCK_GET_STATUS_ARGS["caseID"]) + "_" + str(MOCK_GET_STATUS_ARGS["jobID"])
    assert entry_context['State'] == 'Success'
    assert entry_context['Result'] == '\\\\' + MOCK_BASE_URL + '\\data\\SiteServer\\storage\\' + \
        '8ffafb2e-d077-4165-9aa7-f00cda29cce2\\1\\memdump.mem'


def test_command_accessdata_jobstatus_scan(mocker, requests_mock):
    mock_demisto(mocker, MOCK_GET_STATUS_ARGS, 'accessdata-jobstatus-scan')
    status_route = 'api/v2/enterpriseapi/core/' + str(MOCK_GET_STATUS_ARGS["caseID"]) + \
        '/getjobstatus/' + str(MOCK_GET_STATUS_ARGS["jobID"])
    requests_mock.get(MOCK_URL + status_route, json=MOCK_GET_JOBSTATUS_MEMORYDUMP_RESPONSE)
    main()
    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['Accessdata.Job(val.CaseJobID == obj.CaseJobID)']

    assert results[0]['HumanReadable'] == 'Current job state: Success'
    assert entry_context['CaseID'] == str(MOCK_GET_STATUS_ARGS["caseID"])
    assert entry_context['ID'] == str(MOCK_GET_STATUS_ARGS["jobID"])
    assert entry_context['CaseJobID'] == str(MOCK_GET_STATUS_ARGS["caseID"]) + "_" + str(MOCK_GET_STATUS_ARGS["jobID"])
    assert entry_context['State'] == 'Success'


def test_command_accessdata_legacyagent_get_processlist(mocker, requests_mock):
    mock_demisto(mocker, MOCK_ADD_JOB_ARGS, 'accessdata-legacyagent-get-processlist')
    add_job_route = 'api/v2/enterpriseapi/agent/' + str(MOCK_ADD_JOB_ARGS['caseid']) + '/volatile'
    requests_mock.post(MOCK_URL + add_job_route, text="333")
    main()
    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['Accessdata.Job(val.CaseJobID == obj.CaseJobID)']

    assert results[0]['HumanReadable'] == 'JobID: 333'
    assert entry_context['CaseID'] == MOCK_GET_STATUS_ARGS["caseID"]
    assert entry_context['ID'] == 333
    assert entry_context['CaseJobID'] == str(MOCK_GET_STATUS_ARGS["caseID"]) + "_333"
    assert entry_context['Type'] == 'Volatile'
    assert entry_context['State'] == 'Unknown'


def test_command_accessdata_legacyagent_get_memorydump(mocker, requests_mock):
    mock_demisto(mocker, MOCK_ADD_JOB_ARGS, 'accessdata-legacyagent-get-memorydump')
    add_job_route = 'api/v2/enterpriseapi/agent/' + str(MOCK_ADD_JOB_ARGS['caseid']) + '/memoryacquistion'
    requests_mock.post(MOCK_URL + add_job_route, text="333")
    main()
    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['Accessdata.Job(val.CaseJobID == obj.CaseJobID)']

    assert results[0]['HumanReadable'] == 'JobID: 333'
    assert entry_context['CaseID'] == MOCK_GET_STATUS_ARGS["caseID"]
    assert entry_context['ID'] == 333
    assert entry_context['CaseJobID'] == str(MOCK_GET_STATUS_ARGS["caseID"]) + "_333"
    assert entry_context['Type'] == 'LegacyMemoryDump'
    assert entry_context['State'] == 'Unknown'


def test_command_accessdata_read_casefile(mocker, requests_mock):
    mock_demisto(mocker, MOCK_READ_CASEFILE_ARGS, 'accessdata-read-casefile')
    read_casefile_route = 'api/v2/enterpriseapi/core/readfilecontents'
    requests_mock.post(MOCK_URL + read_casefile_route, text=MOCK_READ_CASEFILE_RESPONSE)
    main()
    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['Accessdata.File.Contents']
    assert entry_context == MOCK_READ_CASEFILE_RESPONSE
