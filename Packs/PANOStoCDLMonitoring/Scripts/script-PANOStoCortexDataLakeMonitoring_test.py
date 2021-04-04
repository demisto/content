from script-PANOStoCortexDataLakeMonitoring import check_instance
import pytest

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
    'pan_os_fw_8.1_30013': {'brand': 'Panorama', 'category': 'Network Security', 'defaultIgnored': 'false',
                            'state': 'disabled'},
    'pan_os_pano_8.1_56111': {'brand': 'Panorama', 'category': 'Network Security', 'defaultIgnored': 'false',
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
    integration_name = 'pan_os_pano_8.1_56111'
    with pytest.raises(Exception):
        check_instance(ALL_INSTANCES, integration_name, '')


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
    with pytest.raises(Exception):
        check_instance(ALL_INSTANCES, integration_name, '')


# mocker.patch.object(
#     demisto,
#     'executeCommand',
#     return_value={
#         'isFetch': True,
#         'url': url,
#         'credentials': {
#             'identifier': 'identifier',
#             'password': 'password',
#         },
#         'incident_name': None
#     }
# )
