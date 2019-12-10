import os
import re

from Tests.test_utils import run_command
from content_creator import update_content_version, update_branch


class TestingVersion:
    def test_update_content_version(self):
        test_path = "./test_py.py"
        content_version = '19.11.1'
        try:
            with open(test_path, "w+") as f:
                f.write("CONTENT_RELEASE_VERSION = 'wrong_one'")
            update_content_version(content_version, test_path)
            with open(test_path) as f:
                assert re.findall(rf'CONTENT_RELEASE_VERSION = \'{content_version}\'', f.read())
        finally:
            if os.path.isfile(test_path):
                os.remove(test_path)

    def test_update_branch(self):
        test_path = "./test_py.py"
        branches = run_command('git branch')
        branch_name_reg = re.search(r'\* (.*)', branches)
        branch_name = branch_name_reg.group(1)
        try:
            with open(test_path, "w+") as f:
                f.write("CONTENT_BRANCH_NAME = 'wrong_one'")
            update_branch(test_path)
            with open(test_path) as f:
                assert re.findall(rf'CONTENT_BRANCH_NAME = \'{branch_name}\'', f.read())
        finally:
            if os.path.isfile(test_path):
                os.remove(test_path)
