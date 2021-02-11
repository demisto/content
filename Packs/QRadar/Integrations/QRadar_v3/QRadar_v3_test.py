"""
    QRadar_V3 integration for Cortex XSOAR - Unit Tests file
"""
import io
import json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())
