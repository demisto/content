import demistomock as demisto
import jwt

from Pcysys import Client, pentera_run_template_command, pentera_get_task_run_status_command, \
    pentera_get_task_run_full_action_report_command, pentera_authentication


MOCK_PENTERA_FULL_ACTION_REPORT = 'penterascan-5e4530961deb8eda82b08730.csv'
MOCK_CSV = open('TestData/mock_csv_file').read()
MOCK_AUTHENTICATION = {
    "token": "TOKEN",
    "tgt": "TGT"
}
MOCK_AUTHENTICATION_EXP = 1579763364
MOCK_RUN_TEMPLATE = {
    "taskRuns": [
        {
            "status": "Running",
            "taskRunId": "5e41923cf24e1f99979b1cb4",
            "taskRunName": "Test mock task run name",
            "startTime": 1581348380358.0,
            "endTime": 1581349123973.0,
        }
    ],
}
MOCK_TASK_RUN_STATS = {
    "taskRuns": [
        {
            "taskRunId": "5e41923cf24e1f99979b1cb4",
            "taskRunName": "Test mock task run name",
            "startTime": 1581348380358.0,
            "endTime": 1581349123973.0,
            "status": "Warning"
        }
    ]
}


def test_pentera_get_task_run_full_action_report(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://pentera.com',
        'port': '8181'
    })
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        'base_url': 'https://pentera.com',
        'tgt': 'omgNewTGT',
        'accessToken': 'omgNewSecret',
        'expiry': MOCK_AUTHENTICATION_EXP
    })
    mocker.patch.object(demisto, 'args', return_value={
        'task_run_id': '5e4530961deb8eda82b08730'
    })
    requests_mock.get('https://pentera.com:8181/api/v1/taskRun/5e4530961deb8eda82b08730/fullActionReportCSV',
                      text=MOCK_CSV)
    client_id = demisto.params().get('clientId')
    tgt = demisto.params().get('tgt')
    base_url = demisto.params()['url'].rstrip('/') + ':' + demisto.params()['port']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    args = demisto.args()
    client = Client(
        base_url=base_url,
        tgt=tgt,
        verify=verify_certificate,
        client_id=client_id,
        proxy=proxy,
        headers={'Accept': 'application/json'})
    entries = pentera_get_task_run_full_action_report_command(client, args)
    raw_csv_file_name = entries[0]['File']
    assert raw_csv_file_name == MOCK_PENTERA_FULL_ACTION_REPORT
    task_run_id = entries[1]['EntryContext']['Pentera.TaskRun(val.ID == obj.ID)']['ID']
    assert task_run_id == '5e4530961deb8eda82b08730'
    operation_type = entries[1]['EntryContext']['Pentera.TaskRun(val.ID == obj.ID)']['FullActionReport'][0][
        'Operation Type']
    assert operation_type == 'BlueKeep (CVE-2019-0708) Vulnerability Discovery'


def test_pentera_get_task_run_stats(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://pentera.com',
        'port': '8181'
    })
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        'base_url': 'https://pentera.com',
        'tgt': 'omgNewTGT',
        'accessToken': 'omgNewSecret',
        'expiry': MOCK_AUTHENTICATION_EXP
    })
    mocker.patch.object(demisto, 'args', return_value={
        'task_run_id': '5e41923cf24e1f99979b1cb4'
    })
    requests_mock.get('https://pentera.com:8181/api/v1/taskRun/5e41923cf24e1f99979b1cb4',
                      json=MOCK_RUN_TEMPLATE)
    client_id = demisto.params().get('clientId')
    tgt = demisto.params().get('tgt')
    base_url = demisto.params()['url'].rstrip('/') + ':' + demisto.params()['port']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    args = demisto.args()
    client = Client(
        base_url=base_url,
        tgt=tgt,
        verify=verify_certificate,
        client_id=client_id,
        proxy=proxy,
        headers={'Accept': 'application/json'})
    readable, parsed, raw = pentera_get_task_run_status_command(client, args)

    assert parsed['Pentera.TaskRun(val.ID == obj.ID)']['ID'] == MOCK_TASK_RUN_STATS['taskRuns'][0]['taskRunId']


def test_pentera_run_template(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://pentera.com',
        'port': '8181'
    })
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        'base_url': 'https://pentera.com',
        'tgt': 'omgNewTGT',
        'accessToken': 'omgNewSecret',
        'expiry': MOCK_AUTHENTICATION_EXP
    })
    mocker.patch.object(demisto, 'args', return_value={
        'template_name': 'omgRunThisTemplate'
    })
    requests_mock.post('https://pentera.com:8181/api/v1/template/runBulk', json=MOCK_RUN_TEMPLATE)
    client_id = demisto.params().get('clientId')
    tgt = demisto.params().get('tgt')
    base_url = demisto.params()['url'].rstrip('/') + ':' + demisto.params()['port']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    args = demisto.args()
    client = Client(
        base_url=base_url,
        tgt=tgt,
        verify=verify_certificate,
        client_id=client_id,
        proxy=proxy,
        headers={'Accept': 'application/json'})
    readable, parsed, raw = pentera_run_template_command(client, args)
    assert parsed['Pentera.TaskRun(val.ID == obj.ID)']['Status'] == MOCK_RUN_TEMPLATE['taskRuns'][0]['status']


def test_pentera_authentication(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'clientId': 'mmtzv',
        'tgt': 'omgSecretsWow',
        'url': 'https://pentera.com',
        'port': '8181'
    })
    mocker.patch.object(jwt, 'get_unverified_header',
                        return_value={'alg': 'HS256', 'exp': 1579763364, 'iat': 1579762464})

    requests_mock.post('https://pentera.com:8181/auth/token', json=MOCK_AUTHENTICATION)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'setIntegrationContext')

    client_id = demisto.params().get('clientId')
    tgt = demisto.params().get('tgt')
    base_url = demisto.params()['url'].rstrip('/') + ':' + demisto.params()['port']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    client = Client(
        base_url=base_url,
        tgt=tgt,
        verify=verify_certificate,
        client_id=client_id,
        proxy=proxy,
        headers={'Accept': 'application/json'})
    pentera_authentication(client)

    assert demisto.setIntegrationContext.call_count == 1
    integration_context = demisto.setIntegrationContext.call_args[0][0]
    assert isinstance(integration_context, dict)
    assert integration_context['expiry'] == MOCK_AUTHENTICATION_EXP
    assert integration_context['accessToken'] == MOCK_AUTHENTICATION['token']
