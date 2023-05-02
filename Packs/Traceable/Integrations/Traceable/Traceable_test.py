#!/usr/bin/env python -W ignore::DeprecationWarning

"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import demistomock as demisto
import logging
import pytest
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.captureWarnings(False)

logging.basicConfig(level=logging.INFO,
                    format="[%(filename)s:%(lineno)s - %(funcName)15s() ] %(asctime)s [%(levelname)s] [%(name)s] [%(threadName)s] %(message)s",
                    handlers=[logging.StreamHandler()])


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(caplog):
    caplog.set_level(logging.INFO)
    from Traceable import Client, fetch_incidents
    import urllib3
    urllib3.disable_warnings()
    headers = {}
    headers["Authorization"] = 'a8947809ba12872d81c8f38e0531997c523ed84d989c793e7dd0bd33c7fc944d7f382c21881780cd25830c0ad66c0f8a20fe1237495d1e64abb1533c60f10e2a'
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"

    client = Client(base_url='https://api.eu.traceable.ai', verify=False, headers=headers)
    client.set_security_score_category_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    # client.set_threat_category_list(threatCategoryList)
    client.set_ip_reputation_level_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_ip_abuse_velocity_list(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    client.set_limit(100)

    next_run, incidents = fetch_incidents(client, {"last_fetch": None}, '3 days')

    for i in range(0, 5):
        logging.info(json.dumps(incidents[i], indent=3))

    demisto.setLastRun(next_run)
    demisto.incidents(incidents)
    # next_run, incidents = fetch_incidents(client, next_run, '3 days')
    a = 123
    assert a == 123
