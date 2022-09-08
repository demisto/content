import demistomock as demisto


def test_get_host_status_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a get_host_status_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'params', return_value={'server': 'server',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'service_request_id': 'service_request_id'})

    import Centreon
    mocker.patch.object(Centreon, 'httpRequest', return_value=[{"Acknowledged": "0",
                                                                "Address": "192.168.1.22",
                                                                "Alias": "jumphost",
                                                                "CheckAttempt": "1",
                                                                "Criticality": "",
                                                                "Id": "37",
                                                                "InstanceName": "Central",
                                                                "LastCheck": "1524487822",
                                                                "LastHardStateChange": "1523986444",
                                                                "LastStateChange": "1523986444",
                                                                "MaxCheckAttempts": "3",
                                                                "Name": "jumphost",
                                                                "Output": "OK",
                                                                "State": "0",
                                                                "StateType": "1"}])
    mocker.patch.object(Centreon, 'httpPost', return_value={'authToken': 'authToken'})

    entry = Centreon.get_host_status_command()

    assert '### Centreon Hosts status' in entry.get('HumanReadable')


def test_get_service_status_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a get_service_status_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, 'params', return_value={'server': 'server',
                                                         'credentials': {'identifier': 'identifier',
                                                                         'password': 'password'}})
    mocker.patch.object(demisto, 'args', return_value={'service_request_id': 'service_request_id'})

    import Centreon
    mocker.patch.object(Centreon, 'httpRequest', return_value=[{"Acknowledged": "0",
                                                                "CheckAttempt": "1",
                                                                "Criticality": "",
                                                                "Description": "Ping",
                                                                "HostId": "37",
                                                                "LastCheck": "1524487467",
                                                                "LastHardStateChange": "1523986444",
                                                                "LastStateChange": "1523986444",
                                                                "MaxCheckAttempts": "3",
                                                                "Name": "jumphost",
                                                                "Output": "OK",
                                                                "Perfdata": "rta=0",
                                                                "ServiceId": "132",
                                                                "State": "0",
                                                                "StateType": "1"
                                                                }])
    mocker.patch.object(Centreon, 'httpPost', return_value={'authToken': 'authToken'})

    entry = Centreon.get_service_status_command()

    assert '### Centreon Services' in entry.get('HumanReadable')
