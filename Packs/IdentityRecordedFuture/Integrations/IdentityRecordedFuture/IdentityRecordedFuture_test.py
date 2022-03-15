from freezegun import freeze_time
import io
import os
import unittest
import json
from pathlib import Path
from unittest.mock import patch, Mock
from IdentityRecordedFuture import Actions, Client, period_to_date

import vcr as vcrpy

CASSETTES = Path(__file__).parent / "test_data"
DATETIME_STR_VALUE = "2021-12-08T12:10:21.837Z"


def filter_out_whoami(response):
    body = response["body"]["string"]
    try:
        body.decode("utf-8")
        json_blob = json.loads(body)
        json_blob.pop("api_key", None)
        response["body"]["string"] = json.dumps(json_blob).encode("utf-8")
    except UnicodeDecodeError:
        pass  # It's not a json string
    return response


vcr = vcrpy.VCR(
    serializer="yaml",
    cassette_library_dir=str(CASSETTES),
    record_mode="once",
    filter_headers=[("X-RFToken", "XXXXXX")],
    before_record_response=filter_out_whoami,
)


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def create_client() -> Client:
    base_url = "https://api.recordedfuture.com/gw/xsoar/"
    verify_ssl = True
    token = os.environ.get("RF_TOKEN")
    headers = {
        "X-RFToken": token,
        "X-RF-User-Agent": "Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1",
    }

    return Client(
        base_url=base_url, verify=verify_ssl, headers=headers, proxy=None
    )


@vcr.use_cassette()
def test_client_whoami() -> None:
    client = create_client()
    resp = client.whoami()
    assert isinstance(resp, dict) is True


@patch("IdentityRecordedFuture.BaseClient._http_request", return_value={})
def test_identity_search(mock_http_request) -> None:
    client = create_client()
    resp = client.identity_search(
        "fake.com", DATETIME_STR_VALUE, ["Email"], [], 0
    )
    assert isinstance(resp, dict) is True


def test_period_to_date_none() -> None:
    period = "All time"
    period_start = period_to_date(period)
    assert period_start is None


@freeze_time("2020-01-01")
def test_period_to_date_period() -> None:
    period = "3 Months ago"
    expected = "2019-10-01T00:00:00.000000Z"
    period_start = period_to_date(period)
    assert isinstance(period_start, str)
    assert period_start == expected


class RFTestIdentity(unittest.TestCase):
    def setUp(self) -> None:
        self.domains = ["fake1.com"]
        self.password_properties = ["Letter", "Number"]
        self.period = "3 Months ago"

    @patch(
        "IdentityRecordedFuture.period_to_date",
        return_value=DATETIME_STR_VALUE,
    )
    def test_identity_search(self, period_to_date_mock) -> None:
        """Test search identities code"""
        domain_type = "All"
        all_domain_types = ["Email", "Authorization"]
        limit_identities = 33
        action_prefix = "RecordedFuture.Credentials.SearchIdentities"
        search_response = util_load_json(
            "./test_data/identity_search_response.json"
        )
        client = create_client()
        client.identity_search = Mock(return_value=search_response)
        actions = Actions(client)
        action_return = actions.identity_search_command(
            self.domains,
            self.period,
            domain_type,
            self.password_properties,
            limit_identities,
        )
        period_to_date_mock.assert_called_once_with(self.period)
        client.identity_search.assert_called_once_with(
            self.domains,
            DATETIME_STR_VALUE,
            all_domain_types,
            self.password_properties,
            limit_identities,
        )
        self.assertEqual(action_return.outputs_prefix, action_prefix)
        self.assertEqual(action_return.outputs, search_response)

    @patch(
        "IdentityRecordedFuture.period_to_date",
        return_value=DATETIME_STR_VALUE,
    )
    def test_identity_lookup(self, period_to_date_mock):
        email_identities = ["realname@fake.com"]
        username_identities = [
            {"login": "notreal", "domain": "fake1.com"},
            {
                "login_sha1": "afafa12344afafa12344afafa12344afafa12344",
                "domain": "fake1.com",
            },
        ]
        sha1_identities = ["afafa12344afafa12344afafa12344afafa12344"]
        identities = "realname@fake.com; notreal; afafa12344afafa12344afafa12344afafa12344"

        lookup_response = util_load_json(
            "./test_data/identity_lookup_response.json"
        )
        action_prefix = "RecordedFuture.Credentials.Identities"
        client = create_client()
        client.identity_lookup = Mock(return_value=lookup_response)
        actions = Actions(client)
        action_return = actions.identity_lookup_command(
            identities,
            self.period,
            self.password_properties,
            self.domains,
        )
        period_to_date_mock.assert_called_once_with(self.period)
        client.identity_lookup.assert_called_once_with(
            email_identities,
            username_identities,
            sha1_identities,
            DATETIME_STR_VALUE,
            self.password_properties,
        )
        self.assertEqual(action_return.outputs_prefix, action_prefix)
        self.assertEqual(action_return.outputs, lookup_response["identities"])
