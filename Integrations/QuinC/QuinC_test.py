# import demistomock as demisto
from CommonServerPython import *
from QuinC import Client, create_jobstate_context, create_contents, wrap_jobstate_context
from test_data.constants import MOCK_URL, FAKE_SITESERVER_TOKEN, JOB_JUST_WITHOUT_CASEJOBID, JOB_JUST_WITH_CASEJOBID


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
