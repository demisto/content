from pathlib import Path
from argparse import ArgumentParser
from os import getenv
from Tests.scripts.utils import logging_wrapper as logging


NIGHTLY_JOBS = [
    'run-unittests-and-lint: [native:dev,from-yml]',
    'run-unittests-and-lint: [native:ga,native:maintenance,native:candidate]',
    'run-validations',
    'trigger-private-build',
    'mpv2-prepare-testing-bucket',
    'xpanse-prepare-testing-bucket',
    'xsoar-prepare-testing-bucket',
    'xsiam_server_ga',
    'xsoar_server_master',
]
SDK_NIGHTLY_JOBS = [
    'demisto-sdk-nightly:run-unittests-and-lint',
    'demisto-sdk-nightly:run-validations',
    'demisto_sdk_nightly:check_idset_dependent_commands',
    'demisto-sdk-nightly:xsoar-prepare-testing-bucket',
    'demisto-sdk-nightly:marketplacev2-prepare-testing-bucket',
    'demisto-sdk-nightly:xpanse-prepare-testing-bucket',
    'demisto-sdk-nightly:test-upload-flow',
    'demisto-sdk-nightly:run-commands-against-instance',
    'demisto-sdk-nightly:run-end-to-end-tests',
]
UPLOAD_JOBS = [
    'run-unittests-and-lint-upload-flow: [native:dev,from-yml]',
    'run-unittests-and-lint-upload-flow: [native:ga,native:maintenance,native:candidate]',
    'run-validations-upload-flow',
    'mpv2-prepare-testing-bucket-upload-flow',
    'upload-id-set-bucket',
    'xpanse-prepare-testing-bucket-upload-flow',
    'xsoar-prepare-testing-bucket-upload-flow',
    'install-packs-in-server6_8',
    'install-packs-in-server6_9',
    'install-packs-in-server6_10',
    'install-packs-in-server6_11',
    'install-packs-in-server-master',
    'install-packs-in-xsiam-ga',
    'upload-packs-to-marketplace',
    'upload-packs-to-marketplace-v2',
    'upload-packs-to-xpanse-marketplace',
]
PUSH_JOBS = [
    'run-unittests-and-lint: [native:dev,from-yml]',
    'run-unittests-and-lint: [native:ga,native:maintenance,native:candidate]',
    'trigger-private-build',
    'validate-content-conf',
    'mpv2-prepare-testing-bucket',
    'xpanse-prepare-testing-bucket',
    'xsoar-prepare-testing-bucket',
    'xsiam_server_ga',
    'xsoar_server_6_8',
    'xsoar_server_6_9',
    'xsoar_server_6_10',
    'xsoar_server_6_11',
    'xsoar_server_master',
]
JOBS_PER_BUILD_TYPE = {
    'NIGHTLY': NIGHTLY_JOBS,
    'DEMISTO_SDK_NIGHTLY': SDK_NIGHTLY_JOBS,
    'BUCKET_UPLOAD': UPLOAD_JOBS,
    'push': PUSH_JOBS
}


def parse_args():
    args = ArgumentParser()
    args.add_argument('--job-done-files', required=True, help='the folder where the job files are located')
    return args.parse_args()


def get_build_jobs():
    for build in ['NIGHTLY', 'DEMISTO_SDK_NIGHTLY', 'BUCKET_UPLOAD']:
        if getenv(build):
            return JOBS_PER_BUILD_TYPE[build]
    return PUSH_JOBS


def main():
    args = parse_args()

    base_path = Path(args.job_done_files)
    should_fail = False
    for job in get_build_jobs():
        job_file = base_path / f'{job}.txt'
        logging.info(f'checking job {job} with file {job_file} in {job_file.absolute()}')
        if not job_file.exists():
            logging.error(f"job {job} is not done yet")
            should_fail = True
        elif job_file.read_text().strip() != 'done':
            logging.error(f"something isn't OK with job name {job}")
            should_fail = True

    if should_fail:
        exit(1)


if __name__ == '__main__':
    main()
