import pytest

import demistomock as demisto
from PANOStoCortexDataLakeMonitoring import check_instance, get_firewall_serials

ERR_MSG_CDL = "No active Cortex Data Lake integration found, please configure one."
ALL_INSTANCES = {
    'Cortex Data Lake_instance_1': {'brand': 'Cortex Data Lake', 'category': 'Analytics & SIEM',
                                    'defaultIgnored': 'false', 'state': 'active'},
    'CustomScripts': {'brand': 'Scripts', 'category': 'automation', 'defaultIgnored': 'false',
                      'state': 'active'},
    'EWS Mail Sender_instance_1': {'brand': 'EWS Mail Sender', 'category': 'Messaging',
                                   'defaultIgnored': 'false',
                                   'state': 'active'},
    'InnerServicesModule': {'brand': 'Builtin', 'category': 'Builtin', 'defaultIgnored': 'false',
                            'state': 'active'},
    'd2': {'brand': 'd2', 'category': 'Endpoint', 'defaultIgnored': 'false', 'state': 'active'},
    'pan_os_fw_8.1_3000': {'brand': 'Panorama', 'category': 'Network Security', 'defaultIgnored': 'false',
                           'state': 'disabled'},
    'pan_os_pano_8.1_8443': {'brand': 'Panorama', 'category': 'Network Security', 'defaultIgnored': 'false',
                             'state': 'active'},
    'splunk': {'brand': 'splunk', 'category': 'Analytics & SIEM', 'defaultIgnored': 'false', 'state': 'active'},
}


def test_check_instance_pan_os_success():
    """
    Given
    - All instances, integration name and error message.

    When
    - Checking if a valid instance name is present

    Then
    - Ensure the check_instance function runs successfully without exceptions
    """
    integration_name = 'pan_os_pano_8.1_8443'
    try:
        check_instance(ALL_INSTANCES, integration_name, '')
    except Exception:
        raise


def test_check_instance_pan_os_failure():
    """
    Given
    - All instances, integration name and error message.

    When
    - Checking if a non valid instance name is present

    Then
    - Ensure the check_instance function raises the appropriate error
    """
    integration_name = 'pan_os_pano_not_present'
    err_msg = "Integration instance pan_os_pano_not_present is not active or is not a PAN-OS integration."
    with pytest.raises(Exception) as err:
        check_instance(ALL_INSTANCES, integration_name, err_msg)
    assert str(err.value) == err_msg


def test_check_instance_cdl_success():
    """
    Given
    - All instances, integration name and error message.

    When
    - Checking if a non valid instance name is present

    Then
    - Ensure the check_instance function runs successfully without exceptions
    """
    integration_name = "Cortex Data Lake"
    try:
        check_instance(ALL_INSTANCES, integration_name, '')
    except Exception:
        raise


def test_get_firewall_serials(mocker):
    """
    Given
    - PAN-OS integration name

    When
    - Checking its config for FWs serials

    Then
    - Ensure the FWs serials are retrieved
    """
    integration_name = 'pan_os_pano_8.1_8443'
    mocker.patch.object(
        demisto,
        'executeCommand',
        return_value=[
            {
                'ModuleName': 'pan_os_pano_8.1_8443', 'Brand': 'Panorama', 'Category': 'Network Security', 'ID': '',
                'Version': 0, 'Type': 1,
                'Contents': {
                    'response':
                        {
                            '@status': 'success',
                            'result': {
                                'devices': {
                                    'entry': [
                                        {
                                            '@name': '123456789012345', 'certificate-subject-name': '123456789012345',
                                            'family': 'vm', 'hostname': 'PA-VM', 'model': 'PA-VM', 'multi-vsys': 'no',
                                            'operational-mode': 'normal', 'serial': '123456789012345',
                                            'sw-version': '8.1.7',
                                            'vsys': {
                                                'entry': {
                                                    '@name': 'vsys1', 'display-name': 'vsys1'
                                                }
                                            }
                                        },
                                        {
                                            '@name': '123456789012346', 'certificate-subject-name': '123456789012346',
                                            'family': 'vm', 'hostname': 'PA-VM', 'model': 'PA-VM', 'multi-vsys': 'no',
                                            'operational-mode': 'normal', 'serial': '123456789012346',
                                            'sw-version': '8.1.7',
                                            'vsys': {
                                                'entry': {
                                                    '@name': 'vsys1', 'display-name': 'vsys1'
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                },
                'HumanReadable': 'Command was executed successfully.',
                'ImportantEntryContext': None,
                'EntryContext': None,
                'IgnoreAutoExtract': False,
                'ReadableContentsFormat': 'text',
                'ContentsFormat': 'json'
            }]
    )
    fw_serials = get_firewall_serials(integration_name)
    assert fw_serials == ['123456789012345', '123456789012346']
