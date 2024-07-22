import json
import os
from pathlib import Path
from pytest_mock import MockerFixture
from requests_mock import Mocker
from manage_branch_protection import purge_branch_protection_rules

test_data_path = Path(__file__).parent.absolute() / "test_files"


class TestManageBranchProtectionRules():

    def _setup(mocker: MockerFixture):

        from manage_branch_protection import GH_REPO_ENV_VAR

        mocker.patch.dict(os.environ, {GH_REPO_ENV_VAR: "owner/repo"})

    def test_purge_repo_branch_protection_rules(self, requests_mock: Mocker):
        """

        """

        response = json.loads((test_data_path / "test_get_repo_branch_protection_rules.json").read_text())

        requests_mock.post(
            url='https://api.github.com/graphql',
            json=response
        )

        purge_branch_protection_rules(args={"owner": "owner", "repo": "repo"})
