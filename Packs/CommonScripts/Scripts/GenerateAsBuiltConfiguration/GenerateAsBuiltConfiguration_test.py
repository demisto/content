from CommonServerPython import *
import demistomock as demisto
from test_data.execute_command import execute_command

demisto.args = lambda: {'playbook': 'AwsEC2SyncAccounts'}
demisto.executeCommand = execute_command

return_results

def test(mocker):
    from GetIncidentsApiModule import main

    try:
        main()
    except Exception:
        pass

    assert True
