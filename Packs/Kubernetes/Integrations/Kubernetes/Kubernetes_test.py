"""Kubernetes Integration for Cortex XSOAR - Unit Tests file."""

import os
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_list_pods():
    pods = util_load_json(os.path.join('test_data/list_pods.json'))
    assert len(pods['items']) == 2
