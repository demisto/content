import pytest
import demistomock as demisto
from IncidentsCheck_Widget_IncidentsErrorsInfo import main


@pytest.mark.parametrize('list_, expected', [
    ([{"Type": "note",
       'Contents': '''[{"incidentid": "7", "numberoferrors": 2, "owner": "", "playbookname": "AutoFocusPolling",
       "taskid": "3", "taskname": "RunPollingCommand", "commandname": "RunPollingCommand",
       "creationdate": "2020-09-29 16:48:30.261438285Z"},
      {"playbookname": "JOB - Integrations and Playbooks Health Check", "taskid": "132",
       "taskname": "Creates failed Integrations grid", "commandname": "SetGridField",
       "creationdate": "2020-09-29 14:02:45.82647067Z", "incidentid": "3", "numberoferrors": 2, "owner": "admin"},
      {"incidentid": "3", "numberoferrors": 2, "owner": "admin",
       "playbookname": "JOB - Integrations and Playbooks Health Check", "taskid": "131",
       "taskname": "Set empty fields to incident grid", "commandname": "SetGridField",
       "creationdate": "2020-09-29 14:02:45.82647067Z"},
      {"taskname": "Get account info from Active Directory", "commandname": "ad-get-user",
       "creationdate": "2020-09-30 15:44:06.930751906Z", "incidentid": "48", "numberoferrors": 2, "owner": "admin",
       "playbookname": "Account Enrichment - Generic v2.1", "taskid": "5"}]'''}],
     {'data': [{'Command Name': 'RunPollingCommand',
                'Incident Creation Date': '2020-09-29 16:48:30',
                'Incident ID': '7',
                'Incident Owner': '',
                'Number of Errors': 2,
                'Playbook Name': 'AutoFocusPolling',
                'Task ID': '3',
                'Task Name': 'RunPollingCommand'},
               {'Command Name': 'SetGridField',
                'Incident Creation Date': '2020-09-29 14:02:45',
                'Incident ID': '3',
                'Incident Owner': 'admin',
                'Number of Errors': 2,
                'Playbook Name': 'JOB - Integrations and Playbooks Health Check',
                'Task ID': '132',
                'Task Name': 'Creates failed Integrations grid'},
               {'Command Name': 'SetGridField',
                'Incident Creation Date': '2020-09-29 14:02:45',
                'Incident ID': '3',
                'Incident Owner': 'admin',
                'Number of Errors': 2,
                'Playbook Name': 'JOB - Integrations and Playbooks Health Check',
                'Task ID': '131',
                'Task Name': 'Set empty fields to incident grid'},
               {'Command Name': 'ad-get-user',
                'Incident Creation Date': '2020-09-30 15:44:06',
                'Incident ID': '48',
                'Incident Owner': 'admin',
                'Number of Errors': 2,
                'Playbook Name': 'Account Enrichment - Generic v2.1',
                'Task ID': '5',
                'Task Name': 'Get account info from Active Directory'}],
      'total': 4}),
    ([{'Type': 'error'}], {'data': [{'Command Name': 'N/A',
                                     'Incident Creation Date': 'N/A',
                                     'Incident ID': 'N/A',
                                     'Incident Owner': 'N/A',
                                     'Number of Errors': 'N/A',
                                     'Playbook Name': 'N/A',
                                     'Task ID': 'N/A',
                                     'Task Name': 'N/A'}],
                           'total': 1})
])
def test_script(mocker, list_, expected):
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected
