from datetime import datetime

from pytest_mock.plugin import MockerFixture

import demistomock as demisto
import ForescoutEyeInspectButtonHostChangeLog
from ForescoutEyeInspectButtonHostChangeLog import get_hosts_changelog, main

HOSTS_CHANGELOG_MOCK = [{
    'id': 51,
    'timestamp': '2022-02-03T07:49:53.000+01:00',
    'event_type_id': 'hostcl_new_host',
    'event_type_name': 'New host',
    'event_category': 'PROPERTIES',
    'host_id': 49,
    'information_source': 'NETWORK',
    'sensor_id': 9,
    'username': '',
    'old_value': '',
    'new_value': '',
    'host_address': '192.168.60.192',
    'host_vlan': '',
    'host_name': '',
    'host_ip_reuse_domain_id': 1,
    'host_mac_addresses': ['B4:2E:99:C9:5E:75', 'C4:24:56:A4:86:11']
}]


def return_error_mock(message: str, *_):
    raise Exception(message)


def test_get_hosts_changelog(mocker: MockerFixture):
    mocker.patch.object(demisto, 'incident', return_value={'occurred': datetime.now().isoformat()})
    mocker.patch.object(demisto, 'executeCommand', return_value=HOSTS_CHANGELOG_MOCK)

    assert get_hosts_changelog()[0]['id'] == 51


def test_command_error(mocker: MockerFixture):
    mocker.patch.object(demisto, 'incident', return_value={'occurred': datetime.now().isoformat()})
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(ForescoutEyeInspectButtonHostChangeLog, 'return_error', return_error_mock)
    mocker.patch.object(demisto,
                        'executeCommand',
                        side_effect=Exception('Failed to communicate with server'))

    try:
        main()
    except Exception as e:
        assert 'Failed to communicate with server' in str(e)
