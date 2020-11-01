import pytest
import demistomock as demisto
import importlib

integration_params = {
    'insecure': 'False',
    'version': '10.2',
    'credentials': {
        'identifier': 'Test',
        'password': 'my_password'
    },
    'time_format': 'auto-discovery',
    'timezone': 0,
    'ip': '0.0.0.0',
    'port': '0000'
}

Cases = [
    {u'openTime': u'07/27/2020 08:07:26',
     u'severity': 1,
     u'deviceList': None,
     u'eventList': [],
     u'notes': u'------- Open: 2020/07/27 08:07:26(GMT)   test -------\n\n------- Closed: 08/02/2020 14:34:31(GMT)'
               u'   test -------\n',
     u'dataSourceList': None,
     u'closeTime': u'08/02/2020 14:34:31',
     u'id': {u'value': 108598},
     u'summary': u'VPN - Multiple Failed Login',
     u'statusId': 2,
     u'history': u'\n------- Viewed: 07/27/2020 08:08:05(GMT) -------\n\n------- Viewed: 07/27/2020 08:09:50(GMT)'
                 u'  ------\n\n------- Viewed: 08/04/2020 09:47:27(GMT)   -------'
     },
    {u'openTime': u'07/27/2020 08:07:26',
     u'severity': 1,
     u'deviceList': None,
     u'eventList': [],
     u'notes': u'------- Open: 2020/07/27 08:07:26(GMT)   test -------\n\n------- Closed: 08/02/2020 14:34:31(GMT)'
               u'   test -------\n',
     u'dataSourceList': None,
     u'closeTime': u'08/02/2020 14:34:31',
     u'id': {u'value': 108598},
     u'summary': u'VPN - Multiple Failed Login',
     u'statusId': {'value': 1},
     u'history': u'\n------- Viewed: 07/27/2020 08:08:05(GMT) -------\n\n------- Viewed: 07/27/2020 08:09:50(GMT)'
                 u'  ------\n\n------- Viewed: 08/04/2020 09:47:27(GMT)   -------'
     }
]


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


@pytest.mark.parametrize('Cases', [(Cases)])
def test_cases_to_entry(Cases, mocker):
    """Unit test
            Given
            - List of cases from response one case with statusID value as int and another as dict
            When
            - mock the esm case status id to name Function.
            Then
            - run the cases to entry Function
            - Check that both statusID were parsed correctly with no exeptions.
            """
    mcafee = importlib.import_module("McAfee_ESM-v10")
    esm = mcafee.NitroESM("Test", "Test", "Test")
    mocker.patch.object(esm, 'case_status_id_to_name', return_value='Open')
    try:
        mcafee.cases_to_entry(esm, "test", Cases)
    except Exception:
        assert False
