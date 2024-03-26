import unittest
from unittest.mock import MagicMock
from RCSScan import rcs_scan_set_context, rcs_scan_start


class TestRCSScan(unittest.TestCase):
    def test_rcs_scan_set_context_new_key(self):
        """
        Test the behavior of rcs_scan_set_context when no existing RCSScanId key is present in the context.
        """
        demisto = MagicMock()
        demisto.context.return_value = {}
        demisto.executeCommand.return_value = None
        result = rcs_scan_set_context("12345", demisto)
        self.assertEqual(result, "RCSScanId Key Value set")

    def test_rcs_scan_set_context_update_key(self):
        """
        Test the behavior of rcs_scan_set_context when an existing RCSScanId key is present in the context,
        and a new scan_id is provided.
        """
        demisto = MagicMock()
        demisto.context.return_value = {"RCSScanId": "12345"}
        demisto.executeCommand.return_value = None
        result = rcs_scan_set_context("67890", demisto)
        self.assertEqual(result, "Updated RCSScanId Key Value")

    def test_rcs_scan_set_context_same_key(self):
        """
        Test the behavior of rcs_scan_set_context when an existing RCSScanId key is present in the context,
        and the same scan_id is provided.
        """
        demisto = MagicMock()
        demisto.context.return_value = {"RCSScanId": "12345"}
        demisto.executeCommand.return_value = None
        result = rcs_scan_set_context("12345", demisto)
        self.assertEqual(result, "RCSScanId remains unchanged")

    def test_rcs_scan_start(self):
        """
        Test the behavior of rcs_scan_start with provided arguments and a mocked demisto object.
        """
        demisto = MagicMock()
        demisto.executeCommand.return_value = [
            {"Type": None, "Contents": {"reply": {"scanId": "12345"}}}
        ]
        args = {
            "service_id": "1",
            "attack_surface_rule_id": "2",
            "alert_internal_id": "3",
        }
        result = rcs_scan_start(args, demisto)
        self.assertEqual(result, "RCSScanId Key Value set")


if __name__ == "__main__":
    unittest.main()
