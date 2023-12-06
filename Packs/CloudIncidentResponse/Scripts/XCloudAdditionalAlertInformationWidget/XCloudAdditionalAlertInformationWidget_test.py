import unittest
from unittest.mock import patch, MagicMock
from XCloudAdditionalAlertInformationWidget import *


class TestXCloudAdditionalAlertInformationWidget(unittest.TestCase):

    @patch('demistomock.context', return_value={'Core': {'OriginalAlert': [{'event': {'alert_full_description': None,
                                                                                      'detection_modules': None,
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
        expected_result = [{'Alert Full Description': None,
                            'Detection Module': None,
                            'Vendor': 'Vendor1',
                            'Provider': 'AWS',
                            'Log Name': 'SecurityLog',
                            'Event Type': 'Event1',
                            'Caller IP': None,
                            'Caller IP Geo Location': 'Location1',
                            'Resource Type': 'ResourceType1',
                            'Identity Name': 'User1',
                            'Operation Name': 'Operation1',
                            'Operation Status': 'Success',
                            'User Agent': 'Browser1'}]

        result = get_additonal_info()  # Corrected function name
        assert result == expected_result

    def test_verify_list_type_dict(self):
        input_dict = [{
            "EntryContext": {"Core.OriginalAlert(val.internal_id && val.internal_id == obj.internal_id)": {"id": "123"}}}]
        expected_output =  {"OriginalAlert": {"id": "123"}}
        output = verify_list_type(input_dict)
        self.assertEqual(output, expected_output)

    def test_verify_list_type_list(self):
        input_list = [
            {"EntryContext": {"Core.OriginalAlert(val.internal_id && val.internal_id == obj.internal_id)": {"id": "123"}}}]
        expected_output = {"OriginalAlert": {"id": "123"}}
        output = verify_list_type(input_list)
        self.assertEqual(output, expected_output)

    def test_verify_list_type_empty(self):
        input = None
        expected_output = None
        output = verify_list_type(input)
        self.assertEqual(output, expected_output)

    @patch('demistomock.investigation', return_value={'id': 'mocked_id'})
    @patch('demistomock.context', {})  # Simulating an empty context
    @patch('CommonServerPython.return_error', side_effect=lambda x: exit(x))
    @patch('sys.exit', side_effect=lambda x: exit(x))
    def test_main_missing_original_alert(self, mock_sys_exit, mock_return_error, mock_context, mock_investigation):
        # Call the main function
        with self.assertRaises(SystemExit) as cm:
            main()

        # Ensure that sys.exit(0) is called during the test
        mock_sys_exit.assert_called_once_with(0)

        # Ensure that exit(0) is called
        self.assertEqual(cm.exception.code, 0)

        # Ensure that the mocked functions were called
        mock_context.assert_called_once()
        mock_investigation.assert_called_once()

        # Check if context is empty, throw an exception
        if not mock_context.return_value:
            raise DemistoException(f"Expected 'context' to have 'Core' structure. Got: {mock_context.return_value}")


if __name__ == '__main__':
    unittest.main()
