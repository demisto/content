from ruamel import yaml
import os
from Utils.update_playbook import update_playbook


def test_hello():
    actual_yml_path = "playbook-Phishing_Investigation_-_Generic.yml"
    try:
        update_playbook("./TestData/Phishing_Investigation_-_Generic.yml", None)

        expected_yml = yaml.safe_load(open("./TestData/playbook-Phishing_Investigation_-_Generic.yml"))
        actual_yml = yaml.safe_load(open(actual_yml_path))

        assert sorted(expected_yml) == sorted(actual_yml), "the yml files aren't equal"
    finally:
        if os.path.isfile(actual_yml_path):
            os.remove(actual_yml_path)
