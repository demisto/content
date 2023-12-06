import unittest
from unittest.mock import patch

from Packs.CloudIncidentResponse.Scripts.XCloudAdditionalAlertInformationWidget import XCloudAdditionalAlertInformationWidget
from XCloudAdditionalAlertInformationWidget import *


class TestXCloudAdditionalAlertInformationWidget(unittest.TestCase):

    @patch('demistomock.context', return_value={'Core': {'OriginalAlert': [{'event': {'alert_full_description': 'New cloud alert',
                                                                                      'detection_modules': 'BIOC',
                                                                                      'vendor': 'Vendor1',
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
        expected_result = [{'Alert Full Description': 'New cloud alert',
                            'Detection Module': 'BIOC',
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

        result = get_additonal_info()  # Corrected function name
        self.assertEqual(result, expected_result)

    def test_verify_list_type_dict(self):
        input_dict = {"EntryContext": {"Core.OriginalAlert": {"id": "123"}}}
        expected_output = {"EntryContext": {"OriginalAlert": {"id": "123"}}}
        output = verify_list_type(input_dict)
        self.assertEqual(output, expected_output)

    def test_verify_list_type_list(self):
        input_list = [{"EntryContext": {"Core.OriginalAlert": {"id": "123"}}}]
        expected_output = {"EntryContext": {"OriginalAlert": {"id": "123"}}}
        output = verify_list_type(input_list)
        self.assertEqual(output, expected_output)

    def test_verify_list_type_empty(self):
        input = None
        with self.assertRaises(Exception):
            verify_list_type(input)

    @patch('demistomock.executeCommand')
    @patch('demistomock.return_results')
    def test_main(self, mock_execute_command, mock_return_results):
        # Set up mocks
        mock_execute_command.side_effect = [
            [{'Contents': [{'some_key': 'some_value'}]}],  # Return value for 'core-get-cloud-original-alerts'
        ]

        # Call the main function
        XCloudAdditionalAlertInformationWidget.main()

        # Assert that the necessary functions and methods were called
        mock_execute_command.assert_called_with('core-get-cloud-original-alerts', {"alert_ids": 'some_id'})
        mock_return_results.assert_called_once()

if __name__ == '__main__':
    unittest.main()
