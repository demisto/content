import sys
from argparse import ArgumentParser
from pathlib import Path

from Tests.scripts.common import WORKFLOW_TYPES, CONTENT_NIGHTLY, BUCKET_UPLOAD, CONTENT_PR, SDK_NIGHTLY, CONTENT_MERGE
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

CONTENT_NIGHTLY_JOBS = [
    'run-unittests-and-lint: [native:dev,from-yml]',
    'run-unittests-and-lint: [native:ga,native:maintenance,native:candidate]',
    'run-validations',
    'trigger-private-build',
    'mpv2-prepare-testing-bucket',
    'xpanse-prepare-testing-bucket',
    'xsoar-prepare-testing-bucket',
    'xsiam_server_ga',
    # 'xsoar_ng_server_ga',
    'tests_xsoar_server: [Server 6.9]',
    'tests_xsoar_server: [Server 6.10]',
    'tests_xsoar_server: [Server 6.11]',
    'tests_xsoar_server: [Server 6.12]',
    'tests_xsoar_server: [Server Master]',
    'xsoar-test_playbooks_results',
    'xsiam-test_playbooks_results',
    'xsiam-test_modeling_rule_results',
    'cloning-content-repo-last-upload-commit',
    # 'xsoar-saas_test_e2e_results',
]

SDK_NIGHTLY_JOBS = [
    'demisto-sdk-nightly:run-unittests-and-lint',
    'demisto-sdk-nightly:run-validations',
    'demisto-sdk-nightly:run-validations-new-validate-flow',
    'demisto_sdk_nightly:check_idset_dependent_commands',
    'demisto-sdk-nightly:xsoar-prepare-testing-bucket',
    'demisto-sdk-nightly:marketplacev2-prepare-testing-bucket',
    'demisto-sdk-nightly:xpanse-prepare-testing-bucket',
    'demisto-sdk-nightly:test-upload-flow',
    'demisto-sdk-nightly:run-commands-against-instance',
    'demisto-sdk-nightly:run-end-to-end-tests',
]

BUCKET_UPLOAD_JOBS = [
    'run-unittests-and-lint-upload-flow: [native:dev,from-yml]',
    'run-unittests-and-lint-upload-flow: [native:ga,native:maintenance,native:candidate]',
    'run-validations-upload-flow',
    'run-validations-upload-flow-new-validate-flow',
    'mpv2-prepare-testing-bucket-upload-flow',
    'upload-id-set-bucket',
    'xpanse-prepare-testing-bucket-upload-flow',
    'xsoar-prepare-testing-bucket-upload-flow',
    'install-packs-in-server6_9',
    'install-packs-in-server6_10',
    'install-packs-in-server6_11',
    'install-packs-in-server6_12',
    'install-packs-in-server-master',
    'install-packs-in-xsiam-ga',
    'upload-packs-to-marketplace',
    'upload-packs-to-marketplace-v2',
    'upload-packs-to-xpanse-marketplace',
]

CONTENT_COMMON_JOBS = [
    'run-unittests-and-lint: [native:dev,from-yml]',
    'run-unittests-and-lint: [native:ga,native:maintenance,native:candidate]',
    'run-validations',
    'run-validations-new-validate-flow',
    'test-upload-flow',
    'trigger-private-build',
    'validate-content-conf',
    'mpv2-prepare-testing-bucket',
    'xpanse-prepare-testing-bucket',
    'xsoar-prepare-testing-bucket',
    'xsoar-saas-prepare-testing-bucket',
    'xsiam_server_ga',
    'tests_xsoar_server: [Server 6.9]',
    'tests_xsoar_server: [Server 6.10]',
    'tests_xsoar_server: [Server 6.11]',
    'tests_xsoar_server: [Server 6.12]',
    'tests_xsoar_server: [Server Master]',
    'xsoar_ng_server_ga',
    'xsoar-test_playbooks_results',
    'xsiam-test_playbooks_results',
    'xsiam-test_modeling_rule_results',
]

CONTENT_PR_JOBS = CONTENT_COMMON_JOBS + [
    'stop-running-pipelines',
]

CONTENT_MERGE_JOBS = CONTENT_COMMON_JOBS + [
    'merge-dev-secrets',
]

JOBS_PER_TRIGGERING_WORKFLOW = {
    CONTENT_NIGHTLY: CONTENT_NIGHTLY_JOBS,
    SDK_NIGHTLY: SDK_NIGHTLY_JOBS,
    BUCKET_UPLOAD: BUCKET_UPLOAD_JOBS,
    CONTENT_PR: CONTENT_PR_JOBS,
    CONTENT_MERGE: CONTENT_MERGE_JOBS,
}


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--job-done-files', required=True, help='the folder where the job files are located')
    parser.add_argument(
        '-tw', '--triggering-workflow', help='The type of ci pipeline workflow the notifier is reporting on',
        choices=WORKFLOW_TYPES)
    return parser.parse_args()


def main():
    install_logging('check_jobs_done.log', logger=logging)
    args = parse_args()

    base_path = Path(args.job_done_files)
    should_fail = False
    for job in JOBS_PER_TRIGGERING_WORKFLOW[args.triggering_workflow]:
        if "new-validate-flow" in job:
            continue
        job_file = base_path / f'{job}.txt'
        logging.info(f'checking job {job} with file {job_file} in {job_file.absolute()}')
        if not job_file.exists():
            logging.error(f"job {job} is not done yet")
            should_fail = True
        elif job_file.read_text().strip() != 'done':
            logging.error(f"something isn't OK with job name {job}")
            should_fail = True

    if should_fail:
        sys.exit(1)


if __name__ == '__main__':
    main()
