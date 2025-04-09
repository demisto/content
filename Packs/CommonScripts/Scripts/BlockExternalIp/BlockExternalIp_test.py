import json

import pytest
from CommonServerPython import *


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_checkpoint_object_names_to_members():
   """
   Given:
      - The command context and the ips.
   When:
      - Running the script block-external-ip for the checkpoint brand, getting the names of the current ips objects names.
   Then:
      - The correct object names.
   """
   from BlockExternalIp import checkpoint_object_names_to_members
   context = util_load_json('test_data/checkpoint_responses.json').get('show_object_name_to_members')
   ip_list = ['1.1.1.1', '1.2.2.2']
   expected_names = ['1.1.1.1', '1.2.2.2']
   result = checkpoint_object_names_to_members(context, ip_list)
   assert expected_names == result
