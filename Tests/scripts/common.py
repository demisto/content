import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from dateutil import parser
from gitlab import Gitlab
from jira import Issue
from junitparser import TestSuite, JUnitXml
from Tests.scripts.utils import logging_wrapper as logging
from gitlab.v4.objects.pipelines import ProjectPipeline
from gitlab.v4.objects.commits import ProjectCommit
from itertools import pairwise


CONTENT_NIGHTLY = 'Content Nightly'
CONTENT_PR = 'Content PR'
CONTENT_MERGE = 'Content Merge'
BUCKET_UPLOAD = 'Upload Packs to Marketplace Storage'
SDK_NIGHTLY = 'Demisto SDK Nightly'
PRIVATE_NIGHTLY = 'Private Nightly'
TEST_NATIVE_CANDIDATE = 'Test Native Candidate'
SECURITY_SCANS = 'Security Scans'
BUILD_MACHINES_CLEANUP = 'Build Machines Cleanup'
SDK_RELEASE = 'Automate Demisto SDK release'
UNIT_TESTS_WORKFLOW_SUBSTRINGS = {'lint', 'unit', 'demisto sdk nightly', TEST_NATIVE_CANDIDATE.lower()}

WORKFLOW_TYPES = {
    CONTENT_NIGHTLY,
    CONTENT_PR,
    CONTENT_MERGE,
    SDK_NIGHTLY,
    BUCKET_UPLOAD,
    PRIVATE_NIGHTLY,
    TEST_NATIVE_CANDIDATE,
    SECURITY_SCANS,
    BUILD_MACHINES_CLEANUP,
    SDK_RELEASE
}
BUCKET_UPLOAD_BRANCH_SUFFIX = '-upload_test_branch'
TOTAL_HEADER = "Total"
NOT_AVAILABLE = "N/A"
TEST_SUITE_JIRA_HEADERS: list[str] = ["Jira\nTicket", "Jira\nTicket\nResolution"]
TEST_SUITE_DATA_CELL_HEADER = "S/F/E/T"
TEST_SUITE_CELL_EXPLANATION = "(Table headers: Skipped/Failures/Errors/Total)"
NO_COLOR_ESCAPE_CHAR = "\033[0m"
RED_COLOR = "\033[91m"
GREEN_COLOR = "\033[92m"
TEST_PLAYBOOKS_REPORT_FILE_NAME = "test_playbooks_report.xml"
TEST_MODELING_RULES_REPORT_FILE_NAME = "test_modeling_rules_report.xml"
E2E_RESULT_FILE_NAME = "e2e_tests_result.xml"

FAILED_TO_COLOR_ANSI = {
    True: RED_COLOR,
    False: GREEN_COLOR,
}
FAILED_TO_COLOR_NAME = {
    True: "red",
    False: "green",
}
FAILED_TO_MSG = {
    True: "failed",
    False: "succeeded",
}

# This is the github username of the bot (and its reviewer) that pushes contributions and docker updates to the content repo.
CONTENT_BOT = 'content-bot'
CONTENT_BOT_REVIEWER = 'github-actions[bot]'


def get_instance_directories(artifacts_path: Path) -> dict[str, Path]:
    instance_directories: dict[str, Path] = {}
    for directory in artifacts_path.iterdir():
        if directory.is_dir() and directory.name.startswith("instance_") and \
                (instance_role_txt := directory / "instance_role.txt").exists():
            instance_role: str = instance_role_txt.read_text().replace("\n", "")
            instance_directories[instance_role] = directory
    return instance_directories


def get_test_results_files(artifacts_path: Path, file_name: str) -> dict[str, Path]:
    results_files: dict[str, Path] = {}
    for instance_role, directory in get_instance_directories(artifacts_path).items():
        if (file_path := Path(artifacts_path) / directory / file_name).exists():
            logging.info(f"Found result file: {file_path} for instance role: {instance_role}")
            results_files[instance_role] = file_path
    return results_files


def get_properties_for_test_suite(test_suite: TestSuite) -> dict[str, str]:
    return {prop.name: prop.value for prop in test_suite.properties()}


def failed_to_ansi_text(text: str, failed: bool) -> str:
    return f"{FAILED_TO_COLOR_ANSI[failed]}{text}{NO_COLOR_ESCAPE_CHAR}"


class TestSuiteStatistics:

    def __init__(self, no_color, failures: int = 0, errors: int = 0, skipped: int = 0, tests: int = 0):
        self.no_color = no_color
        self.failures = failures
        self.errors = errors
        self.skipped = skipped
        self.tests = tests

    def __add__(self, other):
        return TestSuiteStatistics(self.no_color, self.failures + other.failures, self.errors + other.errors,
                                   self.skipped + other.skipped, self.tests + other.tests)

    def show_with_color(self, res: int, show_as_error: bool | None = None) -> str:
        res_str = str(res)
        if self.no_color or show_as_error is None:
            return res_str
        return failed_to_ansi_text(res_str, show_as_error)

    def __str__(self):
        return (f"{self.show_with_color(self.skipped)}/"  # no color for skipped.
                f"{self.show_with_color(self.failures, self.failures > 0)}/"
                f"{self.show_with_color(self.errors, self.errors > 0)}/"
                f"{self.show_with_color(self.tests, self.errors + self.failures > 0)}")


def calculate_results_table(jira_tickets_for_result: dict[str, Issue],
                            results: dict[str, dict[str, Any]],
                            server_versions: set[str],
                            base_headers: list[str],
                            add_total_row: bool = True,
                            no_color: bool = False,
                            without_jira: bool = False,
                            with_skipped: bool = False,
                            multiline_headers: bool = True,
                            transpose: bool = False) -> tuple[list[str], list[list[Any]], JUnitXml, int]:
    xml = JUnitXml()
    headers_multiline_char = "\n" if multiline_headers else " "
    headers = [h.replace("\n", headers_multiline_char) for h in base_headers]
    if not without_jira:
        headers.extend([h.replace("\n", headers_multiline_char) for h in TEST_SUITE_JIRA_HEADERS])
    column_align = ["left"] * len(headers)
    fixed_headers_length = len(headers)
    server_versions_list: list[str] = sorted(server_versions)
    for server_version in server_versions_list:
        server_version_header = server_version.replace(' ', headers_multiline_char)
        headers.append(
            server_version_header
            if transpose else f"{server_version_header}{headers_multiline_char}{TEST_SUITE_DATA_CELL_HEADER}"
        )
        column_align.append("center")
    tabulate_data = [headers]
    total_row: list[Any] = ([""] * fixed_headers_length + [TestSuiteStatistics(no_color)
                                                           for _ in range(len(server_versions_list))])
    total_errors = 0
    for result, result_test_suites in results.items():
        row: list[Any] = []
        if not without_jira:
            if jira_ticket := jira_tickets_for_result.get(result):
                row.extend(
                    (
                        jira_ticket.key,
                        jira_ticket.get_field("resolution")
                        if jira_ticket.get_field("resolution")
                        else NOT_AVAILABLE,
                    )
                )
            else:
                row.extend([NOT_AVAILABLE] * len(TEST_SUITE_JIRA_HEADERS))

        skipped_count = 0
        errors_count = 0
        for server_version in server_versions_list:
            test_suite: TestSuite | None = result_test_suites.get(server_version)
            if test_suite:
                xml.add_testsuite(test_suite)
                row.append(
                    TestSuiteStatistics(
                        no_color,
                        test_suite.failures,
                        test_suite.errors,
                        test_suite.skipped,
                        test_suite.tests,
                    )
                )
                errors_count += test_suite.errors + test_suite.failures
                if test_suite.skipped and test_suite.failures == 0 and test_suite.errors == 0:
                    skipped_count += 1
            else:
                row.append(NOT_AVAILABLE)

        total_errors += errors_count
        # If all the test suites were skipped, don't add the row to the table.
        if skipped_count != len(server_versions_list) or with_skipped:
            row_result = f"{result}{headers_multiline_char}({TEST_SUITE_DATA_CELL_HEADER})" if transpose else result
            if no_color:
                row_result_color = row_result
            else:
                row_result_color = failed_to_ansi_text(row_result, errors_count > 0)
            row.insert(0, row_result_color)
            tabulate_data.append(row)

            # Offset the total row by the number of fixed headers
            for i, cell in enumerate(row[fixed_headers_length:], start=fixed_headers_length):
                if isinstance(cell, TestSuiteStatistics):
                    total_row[i] += cell
        else:
            logging.debug(f"Skipping {result} since all the test suites were skipped")
    if add_total_row:
        total_row[0] = TOTAL_HEADER if no_color else failed_to_ansi_text(TOTAL_HEADER, total_errors > 0)
        tabulate_data.append(total_row)

    if transpose:
        tabulate_data = pd.DataFrame(tabulate_data, index=None).transpose().to_numpy()

    return column_align, tabulate_data, xml, total_errors


def get_all_failed_results(results: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    failed_results = {}
    for result, result_test_suites in results.items():
        for test_suite in result_test_suites.values():
            if test_suite.errors or test_suite.failures:
                failed_results[result] = result_test_suites
                break

    return failed_results


def replace_escape_characters(sentence: str, replace_with: str = " ") -> str:
    escape_chars = ["\n", "\r", "\b", "\f", "\t"]
    for escape_char in escape_chars:
        sentence = sentence.replace(escape_char, replace_with)
    return sentence


def get_pipelines_and_commits(gitlab_client: Gitlab, project_id,
                              look_back_hours: int):
    """
    Get all pipelines and commits on the master branch in the last X hours.
    The commits and pipelines are in order of creation time.
    Args:
        gitlab_client - the gitlab instance
        project_id - the id of the project to query
        look_back_hours - the number of hours to look back for commits and pipeline
    Return:
        a list of gitlab pipelines and a list of gitlab commits in ascending order (as the way it is in the UI)
    """
    project = gitlab_client.projects.get(project_id)

    # Calculate the timestamp for look_back_hours ago
    time_threshold = (
        datetime.utcnow() - timedelta(hours=look_back_hours)).isoformat()

    commits = project.commits.list(all=True, since=time_threshold, order_by='updated_at', sort='asc')
    pipelines = project.pipelines.list(all=True, updated_after=time_threshold, ref='master',
                                       source='push', order_by='id', sort='asc')

    return pipelines, commits


def get_person_in_charge(commit: ProjectCommit) -> tuple[str, str, str] | tuple[None, None, None]:
    """
    Returns the name of the person in charge of the commit, the PR link and the beginning of the PR name.

    Args:
        commit: The Gitlab commit object containing author info.

    Returns:
        name: The name of the commit author.
        pr: The GitHub PR link for the Gitlab commit.
        beginning_of_pr_name: The beginning of the PR name.
    """
    name = commit.author_name
    # pr number is always the last id in the commit title, starts with a number sign, may or may not be in parenthesis.
    pr_number = commit.title.split("#")[-1].strip("()")
    beginning_of_pr_name = commit.title[:20] + "..."
    if pr_number.isnumeric():
        pr = f"https://github.com/demisto/content/pull/{pr_number}"
        return name, pr, beginning_of_pr_name
    else:
        return None, None, None


def are_pipelines_in_order(pipeline_a: ProjectPipeline, pipeline_b: ProjectPipeline) -> bool:
    """
    Check if the pipelines are in the same order of their commits.
    Args:
        pipeline_a: The first pipeline object.
        pipeline_b: The second pipeline object.
    Returns:
        bool
    """

    pipeline_a_timestamp = parser.parse(pipeline_a.created_at)
    pipeline_b_timestamp = parser.parse(pipeline_b.created_at)
    return pipeline_a_timestamp > pipeline_b_timestamp


def is_pivot(current_pipeline: ProjectPipeline, pipeline_to_compare: ProjectPipeline) -> bool | None:
    """
    Is the current pipeline status a pivot from the previous pipeline status.
    Args:
        current_pipeline: The current pipeline object.
        pipeline_to_compare: a pipeline object to compare to.
    Returns:
        True status changed from success to failed
        False if the status changed from failed to success
        None if the status didn't change or the pipelines are not in order of commits
    """

    in_order = are_pipelines_in_order(pipeline_a=current_pipeline, pipeline_b=pipeline_to_compare)
    if in_order:
        logging.info(f"The status of the current pipeline {current_pipeline.id} is {current_pipeline.status} and the "
                     f"status of the compared pipeline {pipeline_to_compare.id} is {pipeline_to_compare.status}")
        if pipeline_to_compare.status == 'success' and current_pipeline.status == 'failed':
            return True
        if pipeline_to_compare.status == 'failed' and current_pipeline.status == 'success':
            return False
    return None


def get_reviewer(pr_url: str) -> str | None:
    """
    Get the first reviewer who approved the PR.
    Args:
        pr_url: The URL of the PR.
    Returns:
        The name of the first reviewer who approved the PR.
    """
    approved_reviewer = None
    try:
        # Extract the owner, repo, and pull request number from the URL
        _, _, _, repo_owner, repo_name, _, pr_number = pr_url.split("/")

        # Get reviewers
        reviews_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/reviews"
        reviews_response = requests.get(reviews_url)
        reviews_data = reviews_response.json()

        # Find the reviewer who provided approval
        for review in reviews_data:
            if review["state"] == "APPROVED":
                approved_reviewer = review["user"]["login"]
                break
    except Exception as e:
        logging.error(f"Failed to get reviewer for PR {pr_url}: {e}")
    return approved_reviewer


def get_slack_user_name(name: str | None, name_mapping_path: str) -> str:
    """
    Get the slack user name for a given Github name.
    Args:
        name: The name to convert.
        name_mapping_path: The path to the name mapping file.
    Returns:
        The slack user name.
    """
    with open(name_mapping_path) as map:
        mapping = json.load(map)
    # If the name is the name of the 'docker image update bot' reviewer - return the owner of that bot.
        if name == CONTENT_BOT_REVIEWER:
            return mapping["docker_images"]["owner"]
        else:
            return mapping["names"].get(name, name)


def get_commit_by_sha(commit_sha: str, list_of_commits: list[ProjectCommit]) -> ProjectCommit | None:
    """
    Get a commit by its SHA.
    Args:
        commit_sha: The SHA of the commit.
        list_of_commits: A list of commits.
    Returns:
        The commit object.
    """
    return next((commit for commit in list_of_commits if commit.id == commit_sha), None)


def get_pipeline_by_commit(commit: ProjectCommit, list_of_pipelines: list[ProjectPipeline]) -> ProjectPipeline | None:
    """
    Get a pipeline by its commit.
    Args:
        commit: The commit object.
        list_of_pipelines: A list of pipelines.
    Returns:
        The pipeline object.
    """
    return next((pipeline for pipeline in list_of_pipelines if pipeline.sha == commit.id), None)


def create_shame_message(suspicious_commits: list[ProjectCommit],
                         pipeline_changed_status: bool, name_mapping_path: str) -> tuple[str, str, str, str] | None:
    """
    Create a shame message for the person in charge of the commit, or for multiple people in case of multiple suspicious commits.
    Args:
        suspicious_commits: A list of suspicious commits.
        pipeline_changed_status: A boolean indicating if the pipeline status changed.
        name_mapping_path: The path to the name mapping file.
    Returns:
        A tuple of strings containing the message, the person in charge, the PR link and the color of the message.
    """
    hi_and_status = person_in_charge = in_this_pr = color = ""
    for suspicious_commit in suspicious_commits:
        name, pr, beginning_of_pr = get_person_in_charge(suspicious_commit)
        if name and pr and beginning_of_pr:
            if name == CONTENT_BOT:
                name = get_reviewer(pr)
            name = get_slack_user_name(name, name_mapping_path)
            msg = "broken" if pipeline_changed_status else "fixed"
            color = "danger" if pipeline_changed_status else "good"
            emoji = ":cry:" if pipeline_changed_status else ":muscle:"
            if suspicious_commits.index(suspicious_commit) == 0:
                hi_and_status = f"Hi, The build was {msg} {emoji} by:"
                person_in_charge = f"@{name}"
                in_this_pr = f" That was done in this PR: {slack_link(pr, beginning_of_pr)}"

            else:
                person_in_charge += f" or @{name}"
                in_this_pr = ""

    return (hi_and_status, person_in_charge, in_this_pr, color) if hi_and_status and person_in_charge and color else None


def slack_link(url: str, text: str) -> str:
    """
    Create a slack link.
    Args:
        url: The URL to link to.
        text: The text to display.
    Returns:
        The slack link.
    """
    return f"<{url}|{text}>"


def was_message_already_sent(commit_index: int, list_of_commits: list, list_of_pipelines: list) -> bool:
    """
    Check if a message was already sent for newer commits, this is possible if pipelines of later commits,
    finished before the pipeline of the current commit.
    Args:
        commit_index: The index of the current commit.
        list_of_commits: A list of commits.
        list_of_pipelines: A list of pipelines.
    Returns:

    """
    for previous_commit, current_commit in pairwise(reversed(list_of_commits[:commit_index])):
        current_pipeline = get_pipeline_by_commit(current_commit, list_of_pipelines)
        previous_pipeline = get_pipeline_by_commit(previous_commit, list_of_pipelines)
        # in rare cases some commits have no pipeline
        if current_pipeline and previous_pipeline and (is_pivot(current_pipeline, previous_pipeline) is not None):
            return True
    return False


def get_nearest_newer_commit_with_pipeline(list_of_pipelines: list[ProjectPipeline], list_of_commits: list[ProjectCommit],
                                           current_commit_index: int) -> tuple[ProjectPipeline, list] | tuple[None, None]:
    """
     Get the nearest newer commit that has a pipeline.
    Args:
        list_of_pipelines: A list of pipelines.
        list_of_commits: A list of commits.
        current_commit_index: The index of the current commit.
    Returns:
        A tuple of the nearest pipeline and a list of suspicious commits that have no pipelines.
    """
    suspicious_commits = []
    for index in reversed(range(0, current_commit_index - 1)):
        next_commit = list_of_commits[index]
        suspicious_commits.append(list_of_commits[index + 1])
        next_pipeline = get_pipeline_by_commit(next_commit, list_of_pipelines)
        if next_pipeline:
            return next_pipeline, suspicious_commits
    return None, None


def get_nearest_older_commit_with_pipeline(list_of_pipelines: list[ProjectPipeline], list_of_commits: list[ProjectCommit],
                                           current_commit_index: int) -> tuple[ProjectPipeline, list] | tuple[None, None]:
    """
     Get the nearest oldest commit that has a pipeline.
    Args:
        list_of_pipelines: A list of pipelines.
        list_of_commits: A list of commits.
        current_commit_index: The index of the current commit.
    Returns:
        A tuple of the nearest pipeline and a list of suspicious commits that have no pipelines.
    """
    suspicious_commits = []
    for index in range(current_commit_index, len(list_of_commits) - 1):
        previous_commit = list_of_commits[index + 1]
        suspicious_commits.append(list_of_commits[index])
        previous_pipeline = get_pipeline_by_commit(previous_commit, list_of_pipelines)
        if previous_pipeline:
            return previous_pipeline, suspicious_commits
    return None, None
