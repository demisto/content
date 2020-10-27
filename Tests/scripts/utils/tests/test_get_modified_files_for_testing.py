import pytest

from Tests.scripts.collect_tests_and_content_packs import (
    get_modified_files_for_testing,
    COMMON_YML_LIST,
)


class TestGetModifiedFilesForTesting:
    """"
    Given: A git-diff output.

    When: Collecting tests

    Then: Validate the output contains or not the given files
    """

    def test_python_file(self, mocker):
        diff_line = "M       Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py"
        yml_file = "Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml"
        mocker.patch(
            "Tests.scripts.collect_tests_and_content_packs.glob.glob",
            return_value=[yml_file],
        )
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == [yml_file]
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_yaml_file(self):
        diff_line = "M      Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == [
            "Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml"
        ]
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_non_relevant_file(self):
        diff_line = "A       Packs/HelloWorld/Integrations/HelloWorld/cert.pem"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_test_file(self):
        diff_line = (
            "M       Packs/HelloWorld/Integrations/HelloWorld/connection_test.py"
        )
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_renamed_file(self):
        diff_line = (
            "R100	Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml	"
            "Packs/HelloWorld/Integrations/HelloWorld/NewHelloWorld.yml"
        )
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_test_playbook(self):
        diff_line = "M Packs/HelloWorld/TestPlaybooks/HelloWorld.yml"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == ["Packs/HelloWorld/TestPlaybooks/HelloWorld.yml"]
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_no_file_path(self):
        diff_line = ""
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_common_file_list(self):
        diff_line = f"M    {COMMON_YML_LIST[0]}"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == ["scripts/script-CommonIntegration.yml"]
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    @pytest.mark.parametrize(
        "path",
        (
            "Packs/HelloWorld/IndicatorTypes/reputation-cidr.json",
            "Packs/HelloWorld/IndicatorTypes/reputations.json",
        ),
    )
    def test_reputations_list(self, path: str):
        diff_line = f"M {path}"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is True
        assert is_indicator_json is False

    def test_conf(self):
        diff_line = "M Tests/conf.json"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is True
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_docs(self):
        diff_line = "A Packs/HelloWorld/README.md"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_metadata(self):
        diff_line = "M Packs/HelloWorld/pack_metadata.json"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == {"HelloWorld"}
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_indicator_fields(self):
        diff_line = "M Packs/HelloWorld/IndicatorFields/sample-field.json"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is True

    def test_secrets_whitelist(self):
        diff_line = "M Tests/secrets_white_list.json"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == []
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False

    def test_sample(self):
        diff_line = "M Tests/Util/Scripts/new_script.py"
        py_file = "Tests/Util/Scripts/new_script.py"
        (
            modified_files_list,
            modified_tests_list,
            changed_common,
            is_conf_json,
            sample_tests,
            modified_metadata_list,
            is_reputations_json,
            is_indicator_json,
        ) = get_modified_files_for_testing(diff_line)
        assert modified_files_list == []
        assert modified_tests_list == []
        assert changed_common == []
        assert is_conf_json is False
        assert sample_tests == [py_file]
        assert modified_metadata_list == set()
        assert is_reputations_json is False
        assert is_indicator_json is False
