import unittest
from ShowIncidentIndicators import group_by_type, get_indicators_from_incident


class TestGroupByTypeAndGetIndicatorsFromIncident(unittest.TestCase):
    def test_group_by_type(self):
        indicators = [{"indicator_type": "IP", "value": "1.1.1.1"},
                      {"indicator_type": "IP", "value": "2.2.2.2"},
                      {"indicator_type": "File", "value": "file.exe"}]
        expected = ["--- IP ---", "1.1.1.1", "2.2.2.2", "", "--- File ---", "file.exe", ""]
        result = group_by_type(indicators)
        self.assertEqual(result, expected)

    def test_get_indicators_from_incident(self):
        def mock_execute_command(command, args):
            return [{"indicator_type": "IP", "value": "1.1.1.1"},
                      {"indicator_type": "IP", "value": "2.2.2.2"},
                      {"indicator_type": "File", "value": "file.exe"}]

        def mock_incident():
            return {"id": 123}

        demisto.execute_command = mock_execute_command
        demisto.incident = mock_incident

        expected = {"hidden": False, "options": ["--- IP ---", "1.1.1.1", "2.2.2.2", "", "--- File ---", "file.exe", ""]}
        result = get_indicators_from_incident()
        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
