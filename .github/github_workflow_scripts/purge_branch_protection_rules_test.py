import json
import logging
import os
from pathlib import Path
import re
from typing import Any
import github
import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestsMocker
from purge_branch_protection_rules import (
    GH_REPO_ENV_VAR,
    GH_TOKEN_ENV_VAR,
    GH_JOB_SUMMARY_ENV_VAR,
    BranchProtectionRule,
    get_repo_owner_and_name,
    convert_response_to_rules,
    write_deleted_summary_to_file,
    shouldnt_delete_rule,
    main
)

test_data_path = Path(__file__).parent.absolute() / "github_workflow_scripts_tests" / "test_files"


class TestPurgeBranchProtectionRules():
    protection_rules_response_data: dict[str, Any] = json.loads(
        (test_data_path / "test_get_repo_branch_protection_rules_data.json").read_text())
    delete_protection_rule_data: dict[str, str] = json.loads(
        (test_data_path / "test_delete_protection_rule_response.json").read_text())

    @pytest.fixture(autouse=True)
    def setup(self, mocker: MockerFixture, tmp_path: Path):

        summary = tmp_path / "summary.md"
        summary.touch()

        mocker.patch.dict(os.environ, {
            GH_TOKEN_ENV_VAR: "mock",
            GH_REPO_ENV_VAR: "foo/bar",
            GH_JOB_SUMMARY_ENV_VAR: str(summary)
        })

    def test_get_owner_repo_from_env_vars(self):
        """
        Test initialization of the repo owner from env vars.

        Given:
        - An env var `GH_REPO_ENV_VAR`.

        When:
        - The env var `GH_REPO_ENV_VAR` is set to 'foo/bar'

        Then:
        - The manager repo owner is 'foo'
        - The manager repo name is 'bar'
        """

        actual_owner, actual_name = get_repo_owner_and_name()

        assert actual_owner == "foo"
        assert actual_name == "bar"

    def test_get_owner_repo_invalid(self, mocker: MockerFixture):
        """
        Test what happens when an invalid repo is set in env var.

        Given:
        - An env var `GH_REPO_ENV_VAR`.

        When:
        - The env var `GH_REPO_ENV_VAR` is set to 'foo/bar'

        Then:
        - A `ValueError` is thrown
        """

        mocker.patch.dict(os.environ, {GH_REPO_ENV_VAR: "foo/bar/baz"})

        with pytest.raises(ValueError, match=re.escape("Input string must be in the format 'owner/repository'.")):
            get_repo_owner_and_name()

    def test_unset_repo_env_var(self, monkeypatch: pytest.MonkeyPatch):
        """
        Test what happens when the GITHUB_REPOSITORY env var is unset.

        Given:
        - An env var `GH_REPO_ENV_VAR`.

        When:
        - The env var `GH_REPO_ENV_VAR` is unset.

        Then:
        - A `SystemExit` is thrown
        """

        monkeypatch.delenv(GH_REPO_ENV_VAR, raising=False)

        with pytest.raises(SystemExit):
            main()

    def test_convert_response_to_rules_valid(
        self
    ):
        """
        Test the behavior of the method `convert_response_to_rules`
        when an valid response is given.

        Given:
        - A mock response.

        When:
        - The response is in expected structure.

        Then:
        - 4 rules are returned with expected attrs.
        """

        rules = convert_response_to_rules(self.protection_rules_response_data)

        assert rules
        assert len(rules) == 4
        for i, rule in enumerate(rules):
            assert rule.id == self.protection_rules_response_data.get("data").get(
                "repository").get("branchProtectionRules").get("nodes")[i].get("id")
            assert rule.pattern == self.protection_rules_response_data.get("data").get(
                "repository").get("branchProtectionRules").get("nodes")[i].get("pattern")
            assert rule.matching_refs == self.protection_rules_response_data.get("data").get("repository").get(
                "branchProtectionRules").get("nodes")[i].get("matchingRefs").get("totalCount")

    def test_convert_response_to_rules_invalid(
        self
    ):
        """
        Test the behavior of the method `convert_response_to_rules`
        when an invalid response is given.

        Given:
        - A mock response.

        When:
        - The response is not in expected structure.

        Then:
        - `AttributeError` is raised.
        """

        with pytest.raises(AttributeError):
            convert_response_to_rules({"data": "unexpected"})

    def test_md_summary_output(
            self,
            mocker: MockerFixture,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - A rule is deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes the rule that was deleted.
        """

        summary_file_path = tmp_path / "summary.md"
        summary_file_path.touch()
        mocker.patch.dict(os.environ, {GH_JOB_SUMMARY_ENV_VAR: str(summary_file_path)})

        deleted: list[BranchProtectionRule] = []
        for i in range(10):
            deleted.append(
                BranchProtectionRule(
                    id=str(i),
                    pattern=f"{i}/*",
                    matching_refs=0,
                    deleted=True
                )
            )

        write_deleted_summary_to_file(deleted)

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert len(actual_summary_lines) == 14
        assert "1/*" in actual_summary_lines[5]

    def test_md_summary_output_no_deleted_rules(
            self,
            mocker: MockerFixture,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        when there were no deleted rules.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - No rules have been deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes a message indicating rules have
        not been deleted.
        """

        summary_file_path = tmp_path / "summary.md"
        summary_file_path.touch()
        mocker.patch.dict(os.environ, {GH_JOB_SUMMARY_ENV_VAR: str(summary_file_path)})

        deleted: list[BranchProtectionRule] = []

        write_deleted_summary_to_file(deleted)

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert len(actual_summary_lines) == 3
        assert "No branch protection rules were deleted" in actual_summary_lines[2]

    def test_md_summary_output_no_deleted_rules_2(
            self,
            mocker: MockerFixture,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        when there was a list of processed rules
        but none of them were deleted.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - No rules have been deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes a message indicating rules have
        not been deleted.
        """

        summary_file_path = tmp_path / "summary.md"
        summary_file_path.touch()
        mocker.patch.dict(os.environ, {GH_JOB_SUMMARY_ENV_VAR: str(summary_file_path)})

        processed: list[BranchProtectionRule] = [
            BranchProtectionRule(
                id="1",
                pattern="abcd",
                matching_refs=0,
                error=github.GithubException(status=400)
            ),
            BranchProtectionRule(
                id="2",
                pattern="abce",
                matching_refs=0,
                error=github.GithubException(status=400)
            )
        ]

        write_deleted_summary_to_file(processed)

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert len(actual_summary_lines) == 3
        assert "No branch protection rules were deleted" in actual_summary_lines[2]

    def test_should_delete_rule(self):
        """
        Given:
        - A rule.

        When:
        - The rule doesn't have any associated refs and
        is not a protected rule.

        Then:
        - The rule should be deleted.
        """

        rule = BranchProtectionRule("1", "a", 0)

        assert not shouldnt_delete_rule(rule)

    def test_should_delete_rule_matching_refs(self):
        """
        Given:
        - A rule.

        When:
        - The rule doesn't has associated refs.

        Then:
        - The rule should not be deleted.
        """

        rule = BranchProtectionRule("1", "a", 1)

        actual = shouldnt_delete_rule(rule)
        assert actual
        assert "not deleted because it's associated to 1 existing branches/refs" in actual

    def test_should_delete_rule_protected(self):
        """
        Given:
        - A rule.

        When:
        - The rule is a protected one.

        Then:
        - The rule should not be deleted.
        """

        rule = BranchProtectionRule("1", "contrib/**/*", 255)

        actual = shouldnt_delete_rule(rule)
        assert actual
        assert "not deleted because it's in the list of protected rules" in actual

    def test_main(
        self,
        requests_mock: RequestsMocker,
        caplog: pytest.LogCaptureFixture,
    ):
        """
        Test the happy path of the `main` function.


        Given:
        - Mock response for get branch protection rules request.
        - Mock response for deleted branch protection rule request.

        When:
        - Mock response for get branch protection rules request is successful.
        - Mock response for deleted protection rules request is successful.

        Then:
        - The log includes information about how many rules were retrieved.
        - The log includes information about what happened to each rule.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            response_list=[
                {
                    'json': self.protection_rules_response_data,
                    'status_code': 200
                },
                {
                    'json': self.delete_protection_rule_data,
                    'status_code': 200
                }
            ]
        )
        with caplog.at_level(level=logging.DEBUG):  # Set the logging level you are interested in
            main()

        # Assert specific log messages in the captured logs
        actual_log_output = caplog.text.splitlines()
        assert "4 rules returned." in actual_log_output[13]
        assert "not deleted because it's in the list of protected rules" in actual_log_output[
            15]
        assert "was deleted successfully." in actual_log_output[
            25]
        assert "was deleted successfully." in actual_log_output[
            35]
        assert "not deleted because it's associated to 3 existing branches/refs" in actual_log_output[
            36]

    def test_main_rate_limit(self, requests_mock: RequestsMocker):
        """
        Test `main` function when a request is rate-limited.


        Given:
        - Mock response for get branch protection rules request.

        When:
        - Mock response for get branch protection rules request raises
        a `RateLimitExceededException`.

        Then:
        - The program exits 1.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            exc=github.RateLimitExceededException(
                status=403,
                data={"msg": "rate limit exceeded, resets in 1h"},
                headers={"x-rate-limit": "5000"}
            )
        )

        with pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 1

    def test_main_rate_limit_2nd(self, requests_mock: RequestsMocker):
        """
        Test `main` function when a request is rate-limited.


        Given:
        - Mock response for get branch protection rules request.
        - Mock response for delete branch protection rule request.

        When:
        - Mock response for get branch protection rules request is
        successful.
        - Mock response for delete branch protection rule request raises
        a `RateLimitExceededException`.

        Then:
        - The program exits 1.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            response_list=[
                {
                    'json': self.protection_rules_response_data,
                    'status_code': 200
                },
                {
                    'exc': github.RateLimitExceededException(
                        status=403,
                        data={"msg": "rate limit exceeded, resets in 1h"},
                        headers={"x-rate-limit": "5000"}
                    )
                }
            ]
        )

        with pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 1

    def test_main_rate_limit_skipping(self, requests_mock: RequestsMocker, caplog: pytest.LogCaptureFixture):
        """
        Test `main` function when a request is rate-limited.


        Given:
        - Mock response for get branch protection rules request.
        - 4 mock responses for delete branch protection rule request.

        When:
        - Mock response for get branch protection rules request is
        successful.
        - 1st mock response for delete branch protection rule request raises
        a `UnknownObjectException`.
        - 2nd-4th mock response for delete branch protection rule request are
        successful.

        Then:
        - 4 rules were processed, 1 with error is printed in log.
        - Which rule deletion failed is printed in log.
        - The program exits 1.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            response_list=[
                {
                    'json': self.protection_rules_response_data,
                    'status_code': 200
                },
                {
                    'exc': github.UnknownObjectException(
                        status=403,
                        data={"msg": "unknown error"},
                        headers={"x-rate-limit": "5000"}
                    )
                },
                {
                    'json': self.delete_protection_rule_data,
                    'status_code': 200
                },
                {
                    'json': self.delete_protection_rule_data,
                    'status_code': 200
                },
                {
                    'json': self.delete_protection_rule_data,
                    'status_code': 200
                }
            ]
        )

        with pytest.raises(SystemExit) as exc, caplog.at_level(level=logging.DEBUG):
            main()

        assert exc.value.code == 1

        actual_log_output = caplog.text.splitlines()
        assert "UnknownObjectException thrown while attempting to delete" in actual_log_output[21]
        assert "Processed 4 rules, 1 with errors." in actual_log_output[33]
        assert "RuntimeError: The following rules returned errors" in actual_log_output[45]

    def test_main_invalid_credentials(self, requests_mock: RequestsMocker):
        """
        Test `main` function when a invalid credentials are used
        to authenticate to GitHub.


        Given:
        - Mock response for get branch protection rules request.

        When:
        - Mock response for get branch protection rules request is raises
        a `BadCredentialsException`.

        Then:
        - The program exits 1.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            exc=github.BadCredentialsException(
                status=401,
                data={"msg": "Credentials supplied do not have permissions"},
                headers={"x-rate-limit": "0"}
            )
        )

        with pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 1
