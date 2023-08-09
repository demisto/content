import json
import logging as logger
import zipfile
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

import requests
from demisto_sdk.commands.common.logger import logging_setup

from Tests.scripts.utils.log_util import install_logging

logging_setup(3)
install_logging("find_pack_dependencies_changes.log", logger=logger)


API_BASE_URL = "https://code.pan.run/api/v4"
PROJECT_ID = '2596'


def parse_args():
    args = ArgumentParser()
    args.add_argument('--gitlab-token', required=True, help='A gitlab API token')
    args.add_argument('--master-sha', required=True, help='master branch commit SHA')
    args.add_argument('--job-name', required=True, help='The job name to take the artifact from')
    args.add_argument('--marketplace', required=True, help='The marketplace name')
    args.add_argument('--current-file', required=True, help='Path to current pack_dependencies.json')
    args.add_argument('--output', required=True, help='Path to diff output file')
    return args.parse_args()


def load_json(filepath: str) -> dict:
    with open(filepath) as f:
        return json.load(f)


class GitlabClient:
    def __init__(self, gitlab_token: str) -> None:
        self.base_url = f"{API_BASE_URL}/projects/{PROJECT_ID}"
        self.project_id = '2596'
        self.token = gitlab_token

    def _get(self, endpoint: str, to_json: bool = False, stream: bool = False) -> Any:
        url = f"{self.base_url}/{endpoint}"
        headers = {"PRIVATE-TOKEN": self.token}
        response = requests.get(url, headers=headers, stream=stream)
        response.raise_for_status()
        if to_json:
            return response.json()
        return response

    def get_pipelines_by_sha(self, commit_sha: str):
        pipelines: list = self._get(f"pipelines?sha={commit_sha}", to_json=True)
        if not pipelines:
            raise Exception(f"No pipelines for SHA {commit_sha}")
        return pipelines

    def get_job_id_by_name(self, pipeline_id: str, job_name: str):
        response: list = self._get(f"pipelines/{pipeline_id}/jobs", to_json=True)
        for job in response:
            if job["name"] == job_name:
                job_id = job["id"]
                logger.info(f"{job_id=}")
                return job_id
        raise Exception(f"Job {job_name} does not exist in pipeline {pipeline_id}.")

    def download_and_extract_packs_dependencies_artifact(self, job_id: str, marketplace: str):
        response: requests.Response = self._get(f"jobs/{job_id}/artifacts", stream=True)
        with open("artifacts_bundle.zip", "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=8192):
                zip_file.write(chunk)

        with zipfile.ZipFile("artifacts_bundle.zip", "r") as zip_ref:
            zip_ref.extractall()

        artifacts_path = Path(f"artifacts/{marketplace}/packs_dependencies.json")
        if artifacts_path.is_file():
            logger.info(f"{artifacts_path=} exists, loading the file")
            return load_json(artifacts_path.as_posix())
        raise Exception(
            "pack_dependencies.json file not found in the extracted artifacts"
        )

    def get_packs_dependencies_json(self, commit_sha: str, job_name: str, marketplace: str) -> dict:
        pipeline_ids = [p["id"] for p in self.get_pipelines_by_sha(commit_sha)]
        for pipeline_id in pipeline_ids:
            job_id = self.get_job_id_by_name(pipeline_id, job_name)
            try:
                return self.download_and_extract_packs_dependencies_artifact(job_id, marketplace)
            except Exception as e:
                logger.info(
                    "Could not extract pack_dependencies.json from job"
                    f"{job_id} of pipeline #{pipeline_id}. Error: {e}"
                )
        raise Exception(
            f"Could not extract pack_dependencies.json from any pipeline of SHA {commit_sha}"
        )


def compare_pack_field(pack_id: str, previous: dict, current: dict, res: dict, field: str) -> None:
    if previous[pack_id][field] != current[pack_id][field]:
        if added := {
            k: v for k, v in current[pack_id][field].items()
            if k not in previous[pack_id][field]
        }:
            if "added" not in res:
                res["added"] = {}
            res["added"][field] = added
        if removed := {
            k: v for k, v in previous[pack_id][field].items()
            if k not in current[pack_id][field]
        }:
            if "removed" not in res:
                res["removed"] = {}
            res["removed"][field] = removed
        if modified := {
            k: v for k, v in current[pack_id][field].items()
            if k in previous[pack_id][field]
            and v["mandatory"] != previous[pack_id][field][k]["mandatory"]
        }:
            if "modified" not in res:
                res["modified"] = {}
            res["modified"][field] = modified


def get_pack_diff(pack_id: str, previous: dict, current: dict) -> dict:
    if pack_id not in previous:
        return {
            "added": {
                "dependencies": current[pack_id]["dependencies"],
                "allLevelDependencies": current[pack_id]["allLevelDependencies"]
            }
        }
    if pack_id not in current:
        return {
            "removed": {
                "dependencies": previous[pack_id]["dependencies"],
                "allLevelDependencies": previous[pack_id]["allLevelDependencies"]
            }
        }
    res: dict = {}
    for field in ["dependencies", "allLevelDependencies"]:
        compare_pack_field(pack_id, previous, current, res, field)
    return res


def compare(previous: dict, current: dict) -> dict:
    diff: dict = {
    }
    all_packs = set(previous.keys()).union(current.keys())
    for pack_id in all_packs:
        if pack_diff := get_pack_diff(pack_id, previous, current):
            diff[pack_id] = pack_diff
    return diff


def log_outputs(diff: dict) -> None:
    if not diff:
        logger.info("No difference in dependencies.")

    s = "\n".join([f"{pack}:\n{json.dumps(data, indent=4)}" for pack, data in diff.items()])
    logger.info(f"Found the following differences:\n{s}")


def write_json(diff: dict, filepath: str) -> None:
    with open(filepath, "w") as f:
        f.write(json.dumps(diff, indent=4))


def main():
    args = parse_args()
    gitlab_client = GitlabClient(args.gitlab_token)
    previous = gitlab_client.get_packs_dependencies_json(args.master_sha, args.job_name, args.marketplace)
    current = load_json(args.current_file)
    diff = compare(previous, current)
    log_outputs(diff)
    write_json(diff, args.output)


if __name__ == '__main__':
    main()
