import demistomock as demisto
from CommonServerPython import entryTypes
from Ping import main
import re
import pytest
import os

# To run the tests in an editor see: test_data/ping

RETURN_ERROR_TARGET = 'Ping.return_error'


@pytest.mark.parametrize('address', ['google.com', '8.8.8.8'])
def test_ping(mocker, address):
    if os.getenv("GITHUB_ACTIONS"):
        pytest.skip("Ping cannot be executed from github actions because they block ICMP packets")
    mocker.patch.object(demisto, 'args', return_value={'address': address})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['address'] == address
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert address in results[0]["EntryContext"]["Ping"]['destination']
    assert re.fullmatch(r'\d+\.\d+\.\d+.\d+', results[0]["EntryContext"]["Ping"]['destination_ip']) is not None
    assert results[0]["EntryContext"]["Ping"]['mdev_rtt']


def test_ping_mocked(mocker):
    import subprocess
    address = "8.8.8.8"
    mocker.patch.object(demisto, 'args', return_value={'address': address})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        subprocess,
        "check_output",
        return_value=f'PING {address} ({address}) 56(84) bytes of data.\n--- {address} ping statistics ---\n3 '
                     f'packets transmitted, 3 received, 0% packet loss, time 2010ms'
                     f'\nrtt min/avg/max/mdev = 12.392/16.995/22.088/3.973 ms'
    )
    # validate our mocks are good
    assert demisto.args()['address'] == address
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert address in results[0]["EntryContext"]["Ping"]['destination']
    assert re.fullmatch(r'\d+\.\d+\.\d+.\d+', results[0]["EntryContext"]["Ping"]['destination_ip']) is not None
    assert results[0]["EntryContext"]["Ping"]['mdev_rtt']


def test_fail_ping(mocker):
    mocker.patch.object(demisto, 'args', return_value={'address': 'nonExistingDomain45343.com'})  # disable-secrets-detection
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'Name does not resolve' in err_msg or 'Name or service not known' in err_msg


def test_fail_ping_permission_error_xsoar8(mocker):
    """
    Given: ping which cannot be executed on engine0

    When: running ping script

    Then: Ensure that error indicating that ping can only run on custom engines
    """
    import subprocess
    mocker.patch.object(subprocess, "check_output", side_effect=Exception("ping: socket: Operation not permitted"))
    mocker.patch.object(demisto, 'args', return_value={'address': "8.8.8.8"})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    mocker.patch("Ping.is_xsoar_on_prem", return_value=False)
    main()

    err_msg = return_error_mock.call_args[0][0]
    assert "The Ping script can be executed only on custom engines" in err_msg
