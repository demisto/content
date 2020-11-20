"""Expanse V2 Integration for Cortex XSOAR - Unit Tests file

"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())
