import json
from datetime import datetime
import importlib

import pytest

AWS_EKS = importlib.import_module("AWS-EKS")


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_datetime_to_str():
    data = {
        'createdAt': datetime(2020, 1, 1, 12, 0, 0)
    }
    AWS_EKS.datetime_to_str(data, 'createdAt')
    assert data['createdAt'] == '2020-01-01T12:00:00Z'


def test_datetime_to_str_invalid():
    data = {}
    AWS_EKS.datetime_to_str(data, 'createdAt')
    assert 'createdAt' not in data


def test_datetime_to_str_none():
    data = {'createdAt': None}
    AWS_EKS.datetime_to_str(data, 'createdAt')
    assert not data['createdAt']
