import argparse
import contextlib
import os
import sys

from gitlab import Gitlab
from gitlab.v4.objects import Project, ProjectPipeline
from google.cloud import compute_v1

from Tests.scripts.common import BUCKET_UPLOAD_BRANCH_SUFFIX
from Tests.scripts.gcp_instances import InstancesService
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID') or 2596  # the default is the id of the content repo in code.pan.run
GITLAB_CANCEL_TOKEN = os.getenv('GITLAB_CANCEL_TOKEN', '')
CI_COMMIT_BRANCH = os.getenv('CI_COMMIT_BRANCH', '')
CI_PIPELINE_ID = os.getenv('CI_PIPELINE_ID', '')
# The order of the statuses is important, we want to cancel the pipeline before it starts running.
GITLAB_STATUSES_TO_CANCEL = ["created", "waiting_for_resource", "preparing", "pending", "running"]


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Stop running pipelines')
    parser.add_argument('-u', '--url', help='The gitlab server url', default=GITLAB_SERVER_URL)
    parser.add_argument('-gp', '--gitlab-project-id', help='The Gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument('-c', '--ci-token', help='The token for Gitlab', required=False, default=GITLAB_CANCEL_TOKEN)
    parser.add_argument('--pipeline-id', help='Current Pipeline ID', required=False, default=CI_PIPELINE_ID)
    parser.add_argument('--current-branch', required=False, help='Current branch name', default=CI_COMMIT_BRANCH)
    parser.add_argument('--creds',
                        help='GCP creds',
                        required=True,
                        type=str)
    parser.add_argument('--zone',
                        help='GCP zone',
                        required=True,
                        type=str)
    return parser.parse_args()


def branch_name_for_test_upload_flow(branch_name: str, pipeline_id: str) -> str:
    return f"{branch_name}{BUCKET_UPLOAD_BRANCH_SUFFIX}-{pipeline_id}"


def get_all_pipelines_for_all_statuses(project: Project, branch_name: str, triggering_source: str) -> list[ProjectPipeline]:
    # Get all pipelines for all statuses, some pipelines might be duplicated as they might change
    # transition (e.g. from pending to running)
    pipelines: dict[str, ProjectPipeline] = {}
    for status in GITLAB_STATUSES_TO_CANCEL:
        with contextlib.suppress(Exception):
            pipelines_for_status: list[ProjectPipeline] = project.pipelines.list(status=status,  # type: ignore[assignment]
                                                                                 ref=branch_name,
                                                                                 source=triggering_source)
            for pipeline in pipelines_for_status:
                pipelines[pipeline.id] = pipeline
    return list(pipelines.values())


def delete_all_instances_for_pipeline(instances_service: InstancesService,
                                      all_instances: dict[str, compute_v1.Instance],
                                      pipeline_id: int):
    if instances_to_delete := [instance_name for instance_name in all_instances if str(pipeline_id) in instance_name]:
        logging.info(f"Found {len(instances_to_delete)} instances to delete for pipeline:{pipeline_id}")
        for i, instance_name in enumerate(sorted(instances_to_delete), start=1):
            try:
                logging.info(f"Deleting instance:{instance_name} {i}/{len(instances_to_delete)}")
                instances_service.delete_instance(instance_name)
            except Exception:
                logging.error(f'Failed to delete instance:{instance_name}')
    else:
        logging.info(f"No instances to delete for pipeline:{pipeline_id}")


def cancel_pipelines_for_branch_name(gitlab_client: Gitlab,
                                     project: Project,
                                     branch_name: str,
                                     triggering_source: str,
                                     instances_service: InstancesService,
                                     all_instances: dict[str, compute_v1.Instance],
                                     cancel_children: bool = True,
                                     pipeline_id: int | None = None) -> bool:

    pipelines = get_all_pipelines_for_all_statuses(project, branch_name, triggering_source)
    if not pipelines:
        logging.info(f"No pipelines found for branch:{branch_name}, triggering source:{triggering_source}")
        return True

    logging.info(f"Found {len(pipelines)} pipelines for branch:{branch_name}, triggering source:{triggering_source}")
    success = True
    for pipeline in pipelines:
        # Only cancel pipelines that were created before the current pipeline, If there is a newer
        # pipeline it will cancel our run, If the build number is None cancel all pipelines.
        if not pipeline_id or pipeline.id < pipeline_id:
            try:
                logging.info(f"Canceling pipeline id:{pipeline.id} for branch:{branch_name}")
                if pipeline.status in GITLAB_STATUSES_TO_CANCEL:
                    pipeline.cancel()
                    logging.success(f"Pipeline id:{pipeline.id} for branch:{branch_name} was canceled")
                else:
                    # This is probably because the pipeline was already canceled or finished while we were running.
                    logging.warning(f"Pipeline id:{pipeline.id} for branch:{branch_name} was not canceled because it's "
                                    f"status is {pipeline.status}")
            except Exception:
                logging.error(f'Failed to cancel pipeline:{pipeline.id} for branch:{branch_name}')
                success = False

            delete_all_instances_for_pipeline(instances_service, all_instances, pipeline.id)

            if cancel_children:
                test_upload = branch_name_for_test_upload_flow(branch_name, pipeline.id)
                logging.info(f"Trying to cancel pipeline for test upload flow branch:{test_upload}")
                success &= cancel_pipelines_for_branch_name(gitlab_client, project, test_upload, "trigger",
                                                            instances_service, all_instances, False)
        elif pipeline.id == pipeline_id:
            logging.info(f"Pipeline {pipeline.id} was not canceled as it is the current pipeline")
        else:
            logging.info(f"Pipeline {pipeline.id} was not canceled because it's newer than the current build")
    return success


def main():
    try:
        install_logging('stop_running_pipeline.log', logger=logging)
        options = options_handler()
        logging.info(f"Gitlab server url: {options.url}\n"
                     f"Gitlab project id: {options.gitlab_project_id}\n"
                     f"Current branch: {options.current_branch}\n"
                     f"Pipeline ID: {options.pipeline_id}\n")

        instances_service = InstancesService(options.creds, options.zone)
        all_instances = instances_service.get_all_instances()
        logging.info(f"Found {len(all_instances)} instances")
        gitlab_client = Gitlab(options.url, private_token=options.ci_token)
        project = gitlab_client.projects.get(int(options.gitlab_project_id))
        pipeline_id = int(options.pipeline_id) if options.pipeline_id else None
        if not cancel_pipelines_for_branch_name(gitlab_client, project, options.current_branch, "push",
                                                instances_service, all_instances, True, pipeline_id):
            logging.info(f"Failed to cancel pipelines for branch:{options.current_branch}")
            sys.exit(1)
        logging.success(f"Successfully canceled pipelines for branch:{options.current_branch}")

    except Exception:
        logging.exception('Failed to cancel pipelines')
        sys.exit(1)


if __name__ == '__main__':
    main()
