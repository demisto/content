import pytest

from Tests.scripts.collect_tests_and_content_packs import get_modified_files_for_testing, COMMON_YML_LIST


class TestGetModifiedFilesForTesting:

    def test_python_file(self, mocker):
        diff_line = "M       Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py"
        yml_file = "Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml"
        mocker.patch(
            "Tests.scripts.collect_tests_and_content_packs.glob.glob",
            return_value=[yml_file])
        assert ([yml_file], [], [], False, [], set(), False, False) == get_modified_files_for_testing(diff_line)

    def test_yaml_file(self):
        diff_line = "M      Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml"
        yml_file = "Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml"
        assert ([yml_file], [], [], False, [], set(), False, False) == get_modified_files_for_testing(diff_line)

    def test_mock_non_relevant_file(self):
        diff_line = "A       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/cert.pem"
        assert ([], [], [], False, [], set(), False, False) == get_modified_files_for_testing(diff_line)

    def test_test_file(self):
        diff_line = "M       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/connection_test.py"
        assert ([], [], [], False, [], set(), False, False) == get_modified_files_for_testing(diff_line)

    def test_renamed_file(self):
        diff_line = "R100	Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.yml	Packs/HelloWorld/Integrations/HelloWorld/NewHelloWorld.yml"
        assert ([], [], [], False, [], set(), False, False) == get_modified_files_for_testing(diff_line)

    def test_test_playbook(self):
        diff_line = "M Packs/HelloWorld/TestPlaybooks/HelloWorld.yml"
        assert get_modified_files_for_testing(diff_line) == ([], ["Packs/HelloWorld/TestPlaybooks/HelloWorld.yml"], [], False, [], set(), False, False)

    def test_no_file_path(self):
        diff_line = ""
        assert get_modified_files_for_testing(diff_line) == ([], [], [], False, [], set(), False, False)

    def test_common_file_list(self):
        diff_line = f"M    {COMMON_YML_LIST[0]}"
        assert get_modified_files_for_testing(diff_line) == ([], [], ["scripts/script-CommonIntegration.yml"], False, [], set(), False, False)

    @pytest.mark.parametrize("path", (
        "Packs/HelloWorld/IndicatorTypes/reputation-cidr.json",
        "Packs/HelloWorld/IndicatorTypes/reputations.json"
    ))
    def test_reputations_list(self, path: str):
        diff_line = f"M {path}"
        assert get_modified_files_for_testing(diff_line) == ([], [], [], False, [], set(), True, False)

    def test_conf(self):
        diff_line = "M Tests/conf.json"
        assert get_modified_files_for_testing(diff_line) == ([], [], [], True, [], set(), False, False)

    def test_docs(self):
        diff_line = "A Packs/HelloWorld/README.md"
        assert get_modified_files_for_testing(diff_line) == ([], [], [], False, [], set(), False, False)

    def test_metadata(self):
        diff_line = "M Packs/HelloWorld/pack_metadata.json"
        assert get_modified_files_for_testing(diff_line) == ([], [], [], False, [], {"HelloWorld"}, False, False)

    def test_indicator_fields(self):
        diff_line = "M Packs/HelloWorld/IndicatorFields/sample-field.json"
        assert ([], [], [], False, [], set(), False, True) == get_modified_files_for_testing(diff_line)

    def test_secrets_whitelist(self):
        diff_line = "M Tests/secrets_white_list.json"
        assert get_modified_files_for_testing(diff_line) == ([], [], [], False, [], set(), False, False)

    def test_sample(self):
        diff_line = "M Tests/Util/Scripts/new_script.py"
        assert get_modified_files_for_testing(diff_line) == ([], [], [], False, ["Tests/Util/Scripts/new_script.py"], set(), False, False)

