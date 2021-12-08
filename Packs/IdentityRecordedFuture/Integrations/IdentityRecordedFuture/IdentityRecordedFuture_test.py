import io
import os
import unittest
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import call
from IdentityRecordedFuture import (
    Actions,
    Client,
)

from CommonServerPython import CommandResults
import vcr as vcrpy

CASSETTES = Path(__file__).parent / 'cassettes'


def filter_out_whoami(response):
    body = response['body']['string']
    try:
        body.decode('utf-8')
        json_blob = json.loads(body)
        json_blob.pop('api_key', None)
        response['body']['string'] = json.dumps(json_blob).encode('utf-8')
    except UnicodeDecodeError:
        pass  # It's not a json string
    return response


vcr = vcrpy.VCR(
    serializer='yaml',
    cassette_library_dir=str(CASSETTES),
    record_mode='once',
    filter_headers=[('X-RFToken', 'XXXXXX')],
    before_record_response=filter_out_whoami,
)


class RFTest(unittest.TestCase):
    def setUp(self) -> None:
        base_url = "https://api.recordedfuture.com/v2/"
        verify_ssl = True
        self.token = os.environ.get("RF_TOKEN")
        headers = {
            "X-RFToken": self.token,
            "X-RF-User-Agent": "Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1",
        }

        self.client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=None
        )
        self.actions = Actions(self.client)

    @vcr.use_cassette()
    def test_whoami(self) -> None:
        resp = self.client.whoami()
        self.assertEqual(isinstance(resp, dict), True)



def create_client():
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
