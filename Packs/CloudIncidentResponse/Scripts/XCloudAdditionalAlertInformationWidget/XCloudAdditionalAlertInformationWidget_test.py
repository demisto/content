import unittest
from unittest.mock import patch
from XCloudAdditionalAlertInformationWidget import get_additonal_info


class TestXCloudAdditionalAlertInformationWidget(unittest.TestCase):

    @patch('demistomock.context', return_value={'Core': {'OriginalAlert': [{'event': {'vendor': 'Vendor1',
                                                                                      'cloud_provider': 'AWS',
                                                                                      'log_name': 'SecurityLog',
                                                                                      'raw_log': {'eventType': 'Event1'},
                                                                                      'caller_ip': '192.168.1.1',
                                                                                      'caller_ip_geolocation': 'Location1',
                                                                                      'resource_type': 'ResourceType1',
                                                                                      'identity_name': 'User1',
                                                                                      'operation_name': 'Operation1',
                                                                                      'operation_status': 'Success',
                                                                                      'user_agent': 'Browser1'}}]}})
    def test_get_additonal_info(self, mock_context):
        # Test with a mock context containing one original alert
        expected_result = [{'Alert Full Description': None,
                            'Detection Module': None,
                            'Vendor': 'Vendor1',
                            'Provider': 'AWS',
                            'Log Name': 'SecurityLog',
                            'Event Type': 'Event1',
                            'Caller IP': '192.168.1.1',
                            'Caller IP Geo Location': 'Location1',
                            'Resource Type': 'ResourceType1',
                            'Identity Name': 'User1',
                            'Operation Name': 'Operation1',
                            'Operation Status': 'Success',
                            'User Agent': 'Browser1'}]

        result = get_additonal_info()
        assert result == expected_result

    # Add more test cases as needed


if __name__ == '__main__':
    unittest.main()
