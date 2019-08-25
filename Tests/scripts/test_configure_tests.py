import os
import re
import unittest

from Tests.scripts.configure_tests import get_modified_files, get_test_list

FILTER_CONF = "Tests/filter_file.txt"


class TestConfigureTests_ChangedTestPlaybook(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M Playbooks/playbook-BitDam_Scan_File.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            tests = get_test_list(files_string, branch_name)
            tests_string = '\n'.join(tests)
            print('Collected the following tests:\n{0}'.format(tests_string))

        print("Creating filter_file.txt")
        with open(FILTER_CONF, "w") as filter_file:
            filter_file.write(tests_string)

    def test_changed_test(self):
        self.create_test_file()

        with open(FILTER_CONF, 'r') as filter_file:
            filterd_tests = filter_file.readlines()
            filterd_tests = [line.strip('\n') for line in filterd_tests]

        self.assertEquals(filterd_tests, ['Detonate File - BitDam Test'])

    def tearDown(self):
        os.remove(FILTER_CONF)


class TestConfigureTests_ChangedIntegration(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M Integrations/PagerDuty/PagerDuty.py"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            tests = get_test_list(files_string, branch_name)
            tests_string = '\n'.join(tests)
            print('Collected the following tests:\n{0}'.format(tests_string))

        print("Creating filter_file.txt")
        with open(FILTER_CONF, "w") as filter_file:
            filter_file.write(tests_string)

    def test_changed_playbook(self):
        self.create_test_file()

        with open(FILTER_CONF, 'r') as filter_file:
            filterd_tests = filter_file.readlines()
            filterd_tests = [line.strip('\n') for line in filterd_tests]

        self.assertEqual(filterd_tests, ['PagerDuty Test', ])

    def tearDown(self):
        os.remove(FILTER_CONF)


class TestConfigureTests_ChangedBoth(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M Integrations/PagerDuty/PagerDuty.py\nM Playbooks/playbook-BitDam_Scan_File.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            tests = get_test_list(files_string, branch_name)
            tests_string = '\n'.join(tests)
            print('Collected the following tests:\n{0}'.format(tests_string))

        print("Creating filter_file.txt")
        with open(FILTER_CONF, "w") as filter_file:
            filter_file.write(tests_string)

    def test_changed_both(self):
        self.create_test_file()

        with open(FILTER_CONF, 'r') as filter_file:
            filterd_tests = filter_file.readlines()
            filterd_tests = [line.strip('\n') for line in filterd_tests]

        self.assertEqual(sorted(filterd_tests),
                         sorted(['PagerDuty Test', 'Detonate File - BitDam Test']))

    def tearDown(self):
        os.remove(FILTER_CONF)


class TestConfigureTests_sampleTesting(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M Tests/scripts/integration-test.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            tests = get_test_list(files_string, branch_name)
            tests_string = '\n'.join(tests)
            print('Collected the following tests:\n{0}'.format(tests_string))

        print("Creating filter_file.txt")
        with open(FILTER_CONF, "w") as filter_file:
            filter_file.write(tests_string)

    def test_all_tests(self):
        self.create_test_file()

        with open(FILTER_CONF, 'r') as filter_file:
            filterd_tests = filter_file.readlines()
            filterd_tests = [line.strip('\n') for line in filterd_tests]

        self.assertEqual(len(filterd_tests), 3)

    def tearDown(self):
        os.remove(FILTER_CONF)


class TestConfigureTests_PackageFilesModified(unittest.TestCase):

    def test_package_modification(self):
        active_dir_mod_git = """M       Integrations/Active_Directory_Query/Active_Directory_Query.py
A       Integrations/Active_Directory_Query/cert.pem
M       Integrations/Active_Directory_Query/connection_test.py
A       Integrations/Active_Directory_Query/key.pem
"""
        files_list, tests_list, all_tests, is_conf_json, sample_tests, is_reputations_json, is_indicator_json = \
            get_modified_files(active_dir_mod_git)
        self.assertEquals(len(sample_tests), 0)
        self.assertIn('Integrations/Active_Directory_Query/Active_Directory_Query.yml', files_list)


if __name__ == '__main__':
    unittest.main()
