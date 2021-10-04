from collections import OrderedDict

from PenteraOperationToIncident import pentera_operation_to_incident

from CommonServerPython import argToList

MOCK_AUTHENTICATION_EXP = 1579763364
MOCK_PARSED_FULL_ACTION_REPORT = [OrderedDict([('Severity', '9.8'),
                                               ('Time', '2020-04-16T16:55:47Z'),
                                               ('Duration', '32.592'),
                                               ('Operation Type', 'BlueKeep (CVE-2019-0708) Vulnerability Discovery'),
                                               ('Techniques', 'Network Service Scanning(T1046)'),
                                               ('Parameters', {'ipv4': '1.1.1.2'}),
                                               ('Status', 'success')]),
                                  OrderedDict([('Severity', '8.2'),
                                               ('Time', '2020-04-16T17:01:53Z'),
                                               ('Duration', '0.365'),
                                               ('Operation Type', 'Password Crack Level 1'),
                                               ('Techniques', 'Brute Force(T1110)'),
                                               ('Parameters', {
                                                   'hash': 'someUser::someDomain:'
                                                           '735114766d02178700000000000000000000000000000000:'
                                                           '9a64264735234e04e665047d555cc983d4ad341cf0132f08:'
                                                           '1122334455667788'}),
                                               ('Status', 'success')]),
                                  OrderedDict([('Severity', '8.0'),
                                               ('Time', '2020-04-16T17:19:45Z'),
                                               ('Duration', '12.782'),
                                               ('Operation Type', 'Password Crack Level 2'),
                                               ('Techniques', 'Brute Force(T1110)'),
                                               ('Parameters', {'hash': 'd5cef3314f06d4aaaf83ae1e93309c97'}),
                                               ('Status', 'success')])]


def test_pentera_operation_to_incident():
    full_action_report = argToList(MOCK_PARSED_FULL_ACTION_REPORT)
    custom_fields_output = 'penteraoperationdetails'
    context_key = 'PenteraIncidents'

    entries = pentera_operation_to_incident(full_action_report, custom_fields_output, context_key)

    assert entries[0] == '### Map Pentera Operation to Incident'
