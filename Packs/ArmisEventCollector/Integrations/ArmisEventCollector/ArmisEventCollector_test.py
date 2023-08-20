import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())
