import argparse
import os
import sys
import traceback
import gitlab

from Tests.scripts.common import BUCKET_UPLOAD_BRANCH_SUFFIX
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging


GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID') or 2596  # the default is the id of the content repo in code.pan.run
GITLAB_CANCEL_TOKEN = os.getenv('GITLAB_CANCEL_TOKEN', '')
CI_COMMIT_BRANCH = os.getenv('CI_COMMIT_BRANCH', '')
CI_PIPELINE_ID = os.getenv('CI_PIPELINE_ID', '')
GITLAB_STATUSES_TO_CANCEL = "created,waiting_for_resource,preparing,pending,running"


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Stop running pipelines')
    parser.add_argument('-u', '--url', help='The gitlab server url', default=GITLAB_SERVER_URL)
    parser.add_argument('-gp', '--gitlab-project-id', help='The Gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument('-c', '--ci-token', help='The token for Gitlab', required=False, default=GITLAB_CANCEL_TOKEN)
    parser.add_argument('--pipeline-id', help='Current Pipeline ID', required=False, default=CI_PIPELINE_ID)
    parser.add_argument('--current-branch', required=False, help='Current branch name', default=CI_COMMIT_BRANCH)
    return parser.parse_args()


def branch_name_for_test_upload_flow(branch_name: str, pipeline_id: str) -> str:
    return f"{branch_name}{BUCKET_UPLOAD_BRANCH_SUFFIX}-{pipeline_id}"


def cancel_pipelines_for_branch_name(gitlab_client: gitlab.Gitlab,
                                     project: gitlab.v4.objects.Project,
                                     branch_name: str,
                                     triggering_source: str,
                                     cancel_children: bool = True,
                                     build_number: int | None = None) -> bool:

    logging.info(f"Canceling pipelines for branch:{branch_name}, triggering source:{triggering_source}")
    success = True
    for pipeline in project.pipelines.list(ref=branch_name, status=GITLAB_STATUSES_TO_CANCEL, source=triggering_source):
        # Only cancel pipelines that were created before the current pipeline, If there is a newer
        # pipeline it will cancel our run, If the build number is None cancel all pipelines.
        if build_number is None or pipeline.id < int(build_number):
            try:
                pipeline.cancel()
                logging.info(f"Pipeline id:{pipeline.id} for branch:{branch_name} was canceled")
                if cancel_children:
                    test_upload = branch_name_for_test_upload_flow(branch_name, pipeline.id)
                    logging.info(f"Trying to cancel pipeline for test upload flow branch:{test_upload}")
                    success &= cancel_pipelines_for_branch_name(gitlab_client, project, test_upload,
                                                                "trigger", False, pipeline.id)
            except Exception:
                logging.error(f'Failed to cancel pipeline:{pipeline.id} for branch:{branch_name}')
                logging.error(traceback.format_exc())
                success = False
        else:
            logging.info(f"Pipeline {pipeline.id} was not canceled")
    return success


def main():
    try:
        install_logging('stop_running_pipeline.log', logger=logging)
        options = options_handler()
        logging.info(f"Gitlab server url: {options.url}\n"
                     f"Gitlab project id: {options.gitlab_project_id}\n"
                     f"Current branch: {options.current_branch}\n"
                     f"Pipeline ID: {options.pipeline_id}\n")

        gitlab_client = gitlab.Gitlab(options.url, private_token=options.ci_token)
        project = gitlab_client.projects.get(int(options.gitlab_project_id))
        if not cancel_pipelines_for_branch_name(gitlab_client, project, options.curret_branch, "push"):
            logging.info(f"Failed to cancel pipelines for branch:{options.current_branch}")
            sys.exit(1)
        logging.success(f"Successfully canceled pipelines for branch:{options.current_branch}")

    except Exception:
        logging.exception('Failed cancel pipelines')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
