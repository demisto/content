import json

from Tests.scripts.configure_tests import get_test_list, get_modified_files, RANDOM_TESTS_NUM

with open('Tests/scripts/infrastructure_tests/tests_data/mock_id_set.json', 'r') as mock_id_set_f:
    MOCK_ID_SET = json.load(mock_id_set_f)
with open('Tests/scripts/infrastructure_tests/tests_data/mock_conf.json', 'r') as mock_conf_f:
    MOCK_CONF = json.load(mock_conf_f)


class TestChangedPlaybook:
    TEST_ID = 'Calculate Severity - Standard - Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Playbooks/playbook-Calculate_Severity_By_Highest_DBotScore.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}


class TestChangedTestPlaybook:
    TEST_ID = 'EWSv2_empty_attachment_test'
    # points at a real file. if that file will change path the test should fail
    GIT_DIFF_RET = "M TestPlaybooks/playbook-EWSv2_empty_attachment_test.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}

    def test_changed_runnable_test__mocked_get_modified_files(self, mocker):
        # fake_test_playbook is fromversion 4.1.0 in playbook file
        test_id = 'fake_test_playbook'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/fake_test_playbook.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.1.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__integration_fromversion(self, mocker):
        # fake_test_playbook is fromversion 4.1.0 in integration file
        test_id = 'fake_test_playbook'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/fake_test_playbook.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__playbook_fromversion(self, mocker):
        # fake_test_playbook is fromversion 4.1.0 in playbook file
        test_id = 'fake_test_playbook'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/fake_test_playbook.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__playbook_toversion(self, mocker):
        # future_playbook_1 is toversion 99.99.99 in conf file
        test_id = 'future_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/future_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_runnable_test__playbook_toversion(self, mocker):
        # future_playbook_1 is toversion 99.99.99 in conf file
        test_id = 'future_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/future_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('99.99.99', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__skipped_test(self, mocker):
        test_id = 'skipped_integration_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/skipped_integration_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__skipped_integration(self, mocker):
        test_id = 'skipped_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/skipped_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1


class TestChangedIntegration:
    TEST_ID = 'PagerDuty Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Integrations/PagerDuty/PagerDuty.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}

    def test_changed_unrunnable_test__integration_fromversion(self, mocker):
        test_id = 'future_test_playbook_2'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/future_test_playbook_2.yml'
        file_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_integrations/future_integration_2.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[file_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__integration_toversion(self, mocker):
        test_id = 'past_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/past_test_playbook_1.yml'
        file_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_integrations/past_integration_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[file_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1


class TestChangedIntegrationAndPlaybook:
    TEST_ID = 'PagerDuty Test\nCalculate Severity - Standard - Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Integrations/PagerDuty/PagerDuty.py\n" \
                   "M Playbooks/playbook-Calculate_Severity_By_Highest_DBotScore.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == set(self.TEST_ID.split('\n'))


class TestChangedScript:
    TEST_ID = 'Extract Indicators From File - test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Scripts/ExtractIndicatorsFromTextFile/ExtractIndicatorsFromTextFile.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}

    def test_changed_unrunnable_test__script_fromversion(self, mocker):
        test_id = 'future_test_playbook_2'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/future_test_playbook_2.yml'
        file_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_integrations/future_integration_2.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[file_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1

    def test_changed_unrunnable_test__integration_toversion(self, mocker):
        test_id = 'past_test_playbook_2'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/past_test_playbook_2.yml'
        file_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_scripts/past_script_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[file_path],
                                                               modified_tests_list=[test_path])
        filterd_tests = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1


class TestSampleTesting:
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Tests/scripts/integration-test.yml"

    def test_sample_tests(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert len(filterd_tests) == RANDOM_TESTS_NUM


class TestChangedCommonTesting:
    TEST_ID = 'TestCommonPython'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml"

    def test_all_tests(self):
        filterd_tests = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert len(filterd_tests) >= RANDOM_TESTS_NUM


class TestPackageFilesModified:
    TEST_ID = 'PagerDuty Test\nCalculate Severity - Standard - Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = """M Packs/Active_Directory_Query/Integrations/Active_Directory_Query/Active_Directory_Query.py
A       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/cert.pem
M       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/connection_test.py
A       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/key.pem
"""

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        files_list, tests_list, all_tests, is_conf_json, sample_tests, is_reputations_json, is_indicator_json = \
            get_modified_files(self.GIT_DIFF_RET)
        assert len(sample_tests) == 0
        assert 'Packs/Active_Directory_Query/Integrations/Active_Directory_Query/Active_Directory_Query.yml' in files_list


class TestNoChange:
    def test_no_change(self, mocker):
        # fake_test_playbook is fromversion 4.1.0 in playbook file
        get_modified_files_ret = create_get_modified_files_ret()
        filterd_tests = get_mock_test_list('4.1.0', get_modified_files_ret, mocker)

        assert len(filterd_tests) >= RANDOM_TESTS_NUM


def create_get_modified_files_ret(modified_files_list=[], modified_tests_list=[], changed_common=[], is_conf_json=[],
                                  sample_tests=[], is_reputations_json=[], is_indicator_json=[]):
    """
    Returns return value for get_modified_files() to be used with a mocker patch
    """
    return (
        modified_files_list,
        modified_tests_list,
        changed_common,
        is_conf_json,
        sample_tests,
        is_reputations_json,
        is_indicator_json
    )


def get_mock_test_list(two_before_ga='4.5.0', get_modified_files_ret=None, mocker=None, git_diff_ret=''):
    branch_name = 'BranchA'
    if get_modified_files_ret is not None:
        mocker.patch('Tests.scripts.configure_tests.get_modified_files', return_value=get_modified_files_ret)
    tests = get_test_list(git_diff_ret, branch_name, two_before_ga, id_set=MOCK_ID_SET, conf=MOCK_CONF)
    return tests
