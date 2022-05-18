"""CimTrak Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the CimTrak Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
import io
import logging

LOGGER = logging.getLogger(__name__)


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_cimtrak(requests_mock):
    import glob

    for file in glob.glob("test_data/*.json"):
        # print("Testing " + file)
        test_json = util_load_json(file)
        for post in test_json["posts"]:
            requests_mock.post(post["url"], json=post["reply"])
        global response
        pre_script = "from CimTrak import Client\n"
        pre_script += "import CimTrak\n"
        pre_script += "from typing import List,Dict,Any\n"
        pre_script += "client = Client(\n"
        pre_script += "    base_url='https://test.com/',\n"
        pre_script += "    verify=False,\n"
        pre_script += "    headers={\n"
        pre_script += "        'Authentication': 'Bearer some_api_key'\n"
        pre_script += "    }\n"
        pre_script += ")\n"

        exec(pre_script + test_json["execute"], globals())
        dict_expected_result = test_json["response"]
        dict_actual_result = response

        # print("Actual:" + str(dict_actual_result))
        # print("Expected:" + str(dict_expected_result))

        assert dict_actual_result == dict_expected_result
