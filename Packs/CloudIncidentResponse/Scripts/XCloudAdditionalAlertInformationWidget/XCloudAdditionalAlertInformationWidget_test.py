import unittest
from unittest.mock import patch
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

        from unittest.mock import MagicMock
        demisto.searchIndicators = MagicMock(return_value={"total": 0})
        result = get_additonal_info()  # Corrected function name
        assert result == expected_result

    def test_verify_list_type_dict(self):
        input_dict = [{
            "EntryContext": {"Core.OriginalAlert(val.internal_id && val.internal_id == obj.internal_id)": {"id": "123"}}}]
        expected_output = {"OriginalAlert": {"id": "123"}}
        output = verify_list_type(input_dict)
        assert output == expected_output

    def test_verify_list_type_list(self):
        input_list = [
            {"EntryContext": {"Core.OriginalAlert(val.internal_id && val.internal_id == obj.internal_id)": {"id": "123"}}}]
        expected_output = {"OriginalAlert": {"id": "123"}}
        output = verify_list_type(input_list)
        assert output == expected_output

    def test_verify_list_type_empty(self):
        input = None
        expected_output = None
        output = verify_list_type(input)
        assert output == expected_output


if __name__ == '__main__':
    unittest.main()
