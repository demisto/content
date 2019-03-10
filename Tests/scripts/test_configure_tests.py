import os
import re
import unittest

from configure_tests import get_modified_files, get_test_list

FILTER_CONF = "filter_file.txt"


class TestConfigureTests_ChangedTestPlaybook(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M Playbooks.playbook-test.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            modified_files, modified_tests_list = get_modified_files(files_string)

            tests = get_test_list(modified_files, modified_tests_list)
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

        self.assertEqual(filterd_tests, ['Archer-Test-Playbook', ])

    def tearDown(self):
        os.remove(FILTER_CONF)


class TestConfigureTests_ChangedPlaybook(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M integration-test.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            modified_files, modified_tests_list = get_modified_files(files_string)

            tests = get_test_list(modified_files, modified_tests_list)
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
            return "M Playbooks.playbook-test.yml\nA integration-test.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            modified_files, modified_tests_list = get_modified_files(files_string)

            tests = get_test_list(modified_files, modified_tests_list)
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

        self.assertEqual(filterd_tests, ['PagerDuty Test', 'Archer-Test-Playbook'])

    def tearDown(self):
        os.remove(FILTER_CONF)


class TestConfigureTests_AllTesting(unittest.TestCase):
    def run_git_command(self, command):
        if 'git branch' in command:
            return "* BranchA\n BranchB"
        elif "git diff --name-status" in command:
            return "M Playbooks.playbook-invalid.yml"

    def create_test_file(self):
        branches = self.run_git_command("git branch")
        branch_name_reg = re.search("(?<=\* )\w+", branches)
        branch_name = branch_name_reg.group(0)

        print("Getting changed files from the branch: {0}".format(branch_name))
        tests_string = ''
        if branch_name != 'master':
            files_string = self.run_git_command("git diff --name-status origin/master...{0}".format(branch_name))

            modified_files, modified_tests_list = get_modified_files(files_string)

            tests = get_test_list(modified_files, modified_tests_list)
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

        self.assertEqual(filterd_tests, [])

    def tearDown(self):
        os.remove(FILTER_CONF)


if __name__ == '__main__':
    unittest.main()
