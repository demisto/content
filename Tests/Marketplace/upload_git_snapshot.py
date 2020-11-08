import logging
import os
import argparse
from Tests.Marketplace.marketplace_services import init_storage_client

from Tests.scripts.utils.log_util import install_logging


def upload_git_snapshot(git_snapshot_path, pack_name, branch_name, pack_version, storage_bucket, repo_name, git_org):
    try:
        git_snapshot_name = f'org-{git_org}_repo-{repo_name}_branch-{branch_name}_version-{pack_version}.zip'
        git_snapshot_storage_path = os.path.join('backup', pack_name, pack_version, git_snapshot_name)

        git_snapshot_blob = storage_bucket.blob(git_snapshot_storage_path)

        with open(git_snapshot_path, "rb") as git_snapshot:
            git_snapshot_blob.upload_from_file(git_snapshot)
    except Exception:
        logging.exception("Error: failed uploading git snapshot.")


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-sp', '--snapshot_path', help="The full path to the git snapshot to upload.", required=True)
    parser.add_argument('-p', '--pack_name', help="The pack which was modified in the uploaded snapshot.",
                        required=True, default="All")
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-br', '--branch_name', help="The name of the branch in the git snapshot.", required=True)
    parser.add_argument('-v', '--pack_version', help="The version of the pack in the snapshot.", required=True)
    parser.add_argument('-r', '--git_repo', help="The git repo in the snapshot.", required=True)
    parser.add_argument('-o', '--git_org', help="The git org in the snapshot.", required=True)
    parser.add_argument('-s', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)

    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    install_logging('upload_git_snapshot.log')
    option = option_handler()
    storage_bucket_name = option.bucket_name
    service_account = option.service_account
    pack_name = option.pack_name
    branch_name = option.branch_name
    pack_version = option.pack_version
    snapshot_path = option.snapshot_path
    git_repo = option.git_repo
    git_org = option.git_org

    # google cloud storage client initialized
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(storage_bucket_name)

    upload_git_snapshot(snapshot_path, pack_name, branch_name, pack_version, storage_bucket, git_repo, git_org)


if __name__ == '__main__':
    main()
