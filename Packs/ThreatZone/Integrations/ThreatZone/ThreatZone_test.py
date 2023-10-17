from CommonServerPython import *
import unittest
from unittest.mock import patch
from ThreatZone import (generate_dbotscore,
                        threatzone_return_results,
                        encode_file_name,
                        threatzone_cdr_upload_sample,
                        threatzone_static_upload_sample,
                        threatzone_sandbox_upload_sample
                        )

DBOT_SCORES = {
    'Reliability': 'A - Completely reliable',
    'Vendor': 'ThreatZone',
    'Indicator': '6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0',
    'Score': 3,
    'Type': DBotScoreType.FILE
}

class MockClient:
    def threatzone_me(self):
        return {
            "userInfo": {
                "email": "name@company.com",
                "fullName": "Test User",
                "limitsCount": {
                "apiRequestCount": 5,
                "dailySubmissionCount": 5,
                "concurrentSubmissionCount": 2
                }
            },
            "plan": {
                "submissionLimits": {
                "apiLimit": 9999,
                "dailyLimit": 999,
                "concurrentLimit": 2
                }
            },
            "modules": []
        }
    def threatzone_check_limits(self, _):
        api_me = self.threatzone_me()
        acc_email = api_me["userInfo"]["email"]
        limits_count = api_me["userInfo"]["limitsCount"]
        submission_limits = api_me["plan"]["submissionLimits"]
        limits = {
            "E_Mail": f"{acc_email}",
            "Daily_Submission_Limit": f"{limits_count['dailySubmissionCount']}/{submission_limits['dailyLimit']}",
            "Concurrent_Limit": f"{limits_count['concurrentSubmissionCount']}/{submission_limits['concurrentLimit']}",
            "API_Limit": f"{limits_count['apiRequestCount']}/{submission_limits['apiLimit']}"
        }
        return {
            "avaliable": True,
            "Limits": limits,
        }

    def threatzone_add(self, param=None):
        return {"uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42", "message": "You have successfully submitted a submission."}


class Test_ThreatZone_Helper_Functions(unittest.TestCase):
    def setUp(self):
        self.client = MockClient()
        
    def test_threatzone_return_results(self):
        uuid = "12345"
        url = "http://example.com"
        readable_output = "Some readable output"
        availability = {"Limits": {"SomeLimit": "SomeValue"}}

        results = threatzone_return_results(uuid, url, readable_output, availability)

        self.assertEqual(len(results), 2)

        first_result, second_result = results

        self.assertEqual(first_result.outputs_prefix, 'ThreatZone.Submission')
        self.assertEqual(first_result.outputs_key_field, "UUID")
        self.assertEqual(first_result.outputs, {'UUID': uuid, 'URL': url})
        self.assertEqual(first_result.readable_output, "Some readable output")

        self.assertEqual(second_result.outputs_prefix, 'ThreatZone.Limits')
        self.assertEqual(second_result.outputs_key_field, "E_Mail")
        self.assertEqual(second_result.outputs, availability["Limits"])

    def test_encode_file_name(self):
        file_name = "Sample_File_名字.png"
        encoded_name = encode_file_name(file_name)
        
        self.assertEqual(encoded_name, b'Sample_File_.png')
        
    def test_generate_dbotscore(self):
        with patch('ThreatZone.get_reputation_reliability', return_value=DBotScoreReliability.A):
            dbot_score = generate_dbotscore(
                "6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0",
                {'THREAT_LEVEL': 3},
                'file'
            )
        self.assertEqual(len(list(dbot_score.to_context().values())), 1)
        self.assertIsInstance(dbot_score, Common.DBotScore)
        for k, v in list(dbot_score.to_context().values())[0].items():
            self.assertEqual(v, DBOT_SCORES[k])

@patch("ThreatZone.Client.threatzone_me", return_value=MockClient.threatzone_me)
class Test_ThreatZone_Main_Functions(unittest.TestCase):
    def setUp(self):
        self.client = MockClient()
        self.args = {
            'private': True,
            'environment': 'some_environment',
            'work_path': 'some_work_path',
            'timeout': 3600,
            'mouse_simulation': False,
            'https_inspection': False,
            'internet_connection': False,
            'raw_logs': True,
            'snapshot': False,
            'entry_id': 'file_entry_id',
        }

    def test_threatzone_sandbox_upload_sample(self, _):
        results = threatzone_sandbox_upload_sample(self.client, self.args)
        
        self.assertEqual(len(results), 2)
        
        first_result, second_result = results
        self.assertEqual(first_result.outputs_prefix, 'ThreatZone.Submission')
        self.assertEqual(first_result.outputs_key_field, "UUID")

        self.assertEqual(second_result.outputs_prefix, 'ThreatZone.Limits')
        self.assertEqual(second_result.outputs_key_field, "E_Mail")


    def test_fail_threatzone_sandbox_upload_sample(self, _):
        return_value = {
            "avaliable": False,
            "Limits": "",
            "Reason": "",
            "Suggestion": ""
        }
        with patch.object(self.client, 'threatzone_check_limits', return_value=return_value):
            with self.assertRaises(DemistoException):
                threatzone_sandbox_upload_sample(self.client, self.args)

    def test_threatzone_static_upload_sample(self, _):
        results = threatzone_static_upload_sample(self.client, self.args)
        
        self.assertEqual(len(results), 2)

        first_result, second_result = results

        self.assertEqual(first_result.outputs_prefix, 'ThreatZone.Submission')
        self.assertEqual(first_result.outputs_key_field, "UUID")

        self.assertEqual(second_result.outputs_prefix, 'ThreatZone.Limits')
        self.assertEqual(second_result.outputs_key_field, "E_Mail")


    def test_threatzone_cdr_upload_sample(self, _):
        results = threatzone_cdr_upload_sample(self.client, self.args)
        
        self.assertEqual(len(results), 2)
        
        first_result, second_result = results

        self.assertEqual(first_result.outputs_prefix, 'ThreatZone.Submission')
        self.assertEqual(first_result.outputs_key_field, "UUID")

        self.assertEqual(second_result.outputs_prefix, 'ThreatZone.Limits')
        self.assertEqual(second_result.outputs_key_field, "E_Mail")

if __name__ == '__main__':
    unittest.main()