import unittest
import pytest
import json
from unittest.mock import patch
from RiskSense import Client

CLIENT_DETAILS = {"ClientName": "test client", "Id": 747}


class MyTestCase(unittest.TestCase):
    client = Client("url", 60, False, False, ())

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_filter_payload")
    def test_hosts(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-hosts" command executes successfully then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_hosts_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "size": "10",
            "projection": "detail",
            "filters": [{"operator": "EXACT", "field": "hostname", "value": "test-hostname", "exclusive": "false"}],
            "page": "0",
        }

        with open("./TestData/hosts_res.json", encoding="utf-8") as f:
            expected_res = json.load(f)

        mocker_res.return_value = expected_res

        hr, ec, resp = get_hosts_command(self.client, {})

        with open("./TestData/hosts_ec.json") as f:
            expected_ec = json.load(f)

        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_payload_for_detail_commands")
    def test_host_detail(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-host-detail" command executes successfully then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_host_detail_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "filters": [{"operator": "EXACT", "field": "hostname", "value": "test-hostname", "exclusive": "false"}],
            "projection": "detail",
        }

        with open("./TestData/hosts_res.json", encoding="utf-8") as f:
            expected_res = json.load(f)
        mocker_res.return_value = expected_res

        hr, ec, resp = get_host_detail_command(self.client, {})
        with open("./TestData/hosts_ec.json") as f:
            expected_ec = json.load(f)
        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_unique_cves_payload")
    def test_unique_cves(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-unique-cves" command executes successfully then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_unique_cves_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "filters": [
                {
                    "operator": "EXACT",
                    "field": "id",
                    "value": "test-host_finding_id",
                }
            ],
            "projection": "detail",
            "page": 0,
            "size": 10,
        }

        with open("./TestData/unique_cves_resp.json", encoding="utf-8") as f:
            expected_res = json.load(f)
        mocker_res.return_value = expected_res

        hr, ec, resp = get_unique_cves_command(self.client, {})
        with open("./TestData/unique_cves_ec.json") as f:
            expected_ec = json.load(f)
        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_filter_payload")
    def test_host_finding(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-host-findings" command executes successfully
        then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_host_findings_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "projection": "detail",
            "sort": [{"field": "riskRating", "direction": "ASC"}],
            "page": "0",
            "size": "10",
            "filters": [
                {"field": "generic_state", "exclusive": "false", "operator": "EXACT", "value": "open"},
                {"field": "hostName", "exclusive": "false", "operator": "EXACT", "value": "loz.xg.mil"},
            ],
        }

        with open("./TestData/host_finding_resp.json", encoding="utf-8") as f:
            expected_res = json.load(f)
        mocker_res.return_value = expected_res

        hr, ec, resp = get_host_findings_command(self.client, {})
        with open("./TestData/host_finding_ec.json", encoding="utf-8") as f:
            expected_ec = json.load(f)

        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_filter_payload")
    def test_unique_open_findings(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-unique-open-findings" command executes successfully
        then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_unique_open_findings_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "filters": [{"field": "title", "exclusive": False, "operator": "EXACT", "value": "NetBIOS Name Accessible"}],
            "projection": "basic",
            "sort": [{"field": "id", "direction": "ASC"}],
            "page": 0,
            "size": 20,
        }

        with open("./TestData/unique_open_findings_resp.json", encoding="utf-8") as f:
            expected_res = json.load(f)
        mocker_res.return_value = expected_res

        hr, ec, resp = get_unique_open_findings_command(self.client, {})
        with open("./TestData/unique_open_findings_ec.json") as f:
            expected_ec = json.load(f)
        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_filter_payload")
    def test_apps(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-apps" command executes successfully
        then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_apps_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "size": "10",
            "projection": "detail",
            "filters": [{"operator": "EXACT", "field": "name", "value": "test-appname", "exclusive": "false"}],
            "page": "0",
        }

        with open("./TestData/apps_resp.json", encoding="utf-8") as f:
            expected_res = json.load(f)

        mocker_res.return_value = expected_res

        hr, ec, resp = get_apps_command(self.client, {})
        with open("./TestData/apps_ec.json") as f:
            expected_ec = json.load(f)

        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_payload_for_detail_commands")
    def test_host_finding_detail(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-host-finding-detail" command executes successfully
        then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_host_finding_detail_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "filters": [{"field": "id", "exclusive": "false", "operator": "EXACT", "value": "host finding id"}],
            "projection": "detail",
        }

        with open("./TestData/host_finding_details_resp.json", encoding="utf-8") as f:
            expected_res = json.load(f)

        mocker_res.return_value = expected_res

        hr, ec, resp = get_host_finding_detail_command(self.client, {})

        with open("./TestData/host_finding_details_ec.json") as f:
            expected_ec = json.load(f)

        assert expected_res == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    @patch("RiskSense.prepare_payload_for_detail_commands")
    def test_app_detail(self, mocker_request, mocker_res, mocker_client_id):
        """
        When "risksense-get-app-detail" command executes successfully
        then context output and response should match.

        :param mocker_request: mocker object of request.
        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import get_app_detail_command

        mocker_client_id.return_value = CLIENT_DETAILS
        mocker_request.return_value = {
            "filters": [{"operator": "EXACT", "field": "id", "value": "test-app", "exclusive": "false"}],
            "projection": "detail",
        }

        with open("./TestData/apps_resp.json", encoding="utf-8") as f:
            expected_res = json.load(f)

        mocker_res.return_value = expected_res

        hr, ec, resp = get_app_detail_command(self.client, {})

        with open("./TestData/apps_ec.json") as f:
            expected_ec = json.load(f)

        assert expected_res == resp
        assert expected_ec == ec

    def test_validate_values_for_between_operator(self):
        from RiskSense import validate_values_for_between_operator

        args = {"operator": "BETWEEN", "value": "200,400"}

        validate_values_for_between_operator(args)
        args["value"] = "2017-02-20,2020-01-01"
        validate_values_for_between_operator(args)

        with pytest.raises(ValueError):
            args["value"] = "2020-20-20,123.0.0"
            validate_values_for_between_operator(args)

        with pytest.raises(ValueError):
            args["value"] = "2020-20-20,123"
            validate_values_for_between_operator(args)

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    def test_apply_tag_using_search_tag_id(self, mocker_res, mocker_client_id):
        """
        When "risksense-apply-tag" command when tag found using search tag,
        executes successfully then context output and response should match.

        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import apply_tag_command

        mocker_client_id.return_value = CLIENT_DETAILS
        args = {"tagname": "TestForMe", "fieldname": "id", "value": "3571259"}

        resp_list = []

        # Search Tag response
        with open("TestData/search_tag_resp.json", encoding="utf-8") as f:
            resp_list.append(json.load(f))

        # Associate tag response.
        resp_list.append({"id": 2542063, "created": "2020-04-29T08:46:54"})

        # Expected EC
        with open("./TestData/tag_asset_ec.json", encoding="utf-8") as f:
            expected_ec = json.load(f)

        mocker_res.side_effect = resp_list

        hr, ec, resp = apply_tag_command(self.client, args)

        assert resp_list[1] == resp
        assert expected_ec == ec

    @patch("RiskSense.get_client_detail_from_context")
    @patch("RiskSense.Client.http_request")
    def test_apply_tag_using_create_tag(self, mocker_res, mocker_client_id):
        """
        When "risksense-apply-tag" command when tag not found and creates tag,
        executes successfully then context output and response should match.

        :param mocker_res: mocker object of response.
        :param mocker_client_id: mocker object of client id.
        :return: None
        """
        from RiskSense import apply_tag_command

        mocker_client_id.return_value = CLIENT_DETAILS
        args = {"tagname": "TestForMe", "fieldname": "id", "value": "3571259"}

        # Search tag Response & Get user from integration context response
        resp_list = [{}, {"userId": 123}]

        # Create Tag response
        with open("TestData/create_tag_resp.json", encoding="utf-8") as f:
            resp_list.append(json.load(f))

        # Associate tag response.
        resp_list.append({"id": 2542063, "created": "2020-04-29T08:46:54"})

        # Expected EC
        with open("./TestData/tag_asset_ec.json", encoding="utf-8") as f:
            expected_ec = json.load(f)

        mocker_res.side_effect = resp_list

        hr, ec, resp = apply_tag_command(self.client, args)
        assert resp_list[3] == resp
        assert expected_ec == ec


if __name__ == "__main__":
    unittest.main()
