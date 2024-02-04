import os
from tempfile import mkdtemp
import zipfile
from pathlib import Path
from typing import Any

import requests


GITLAB_SERVER_URL = os.getenv("CI_SERVER_URL", "https://gitlab.xdr.pan.local")  # disable-secrets-detection
API_BASE_URL = f"{GITLAB_SERVER_URL}/api/v4"
PROJECT_ID = os.getenv("CI_PROJECT_ID", "1061")


class GitlabClient:
    def __init__(self, gitlab_token: str) -> None:
        self.base_url = f"{API_BASE_URL}/projects/{PROJECT_ID}"
        self.headers = {"PRIVATE-TOKEN": gitlab_token}

    def _get(
        self,
        endpoint: str,
        params: dict | None = None,
        to_json: bool = False,
        stream: bool = False,
    ) -> Any:
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, params, headers=self.headers, stream=stream)
        response.raise_for_status()
        if to_json:
            return response.json()
        return response

    def get_pipelines(
            self,
            commit_sha: str = None,
            ref: str = None,
            sort: str = "asc",
    ) -> list:
        params = {
            "sha": commit_sha,
            "ref": ref,
            "sort": sort,
        }
        return self._get("pipelines", params=params, to_json=True)

    def get_job_id_by_name(self, pipeline_id: str, job_name: str) -> str | None:
        response: list = self._get(f"pipelines/{pipeline_id}/jobs", to_json=True)
        for job in response:
            if job["name"] == job_name:
                return job["id"]
        return None

    def download_and_extract_artifacts_bundle(
        self,
        job_id: str,
    ) -> Path:
        temp_path = Path(mkdtemp())
        target_path = temp_path / "artifacts.zip"
        response: requests.Response = self._get(f"jobs/{job_id}/artifacts", stream=True)
        with open(target_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=8192):
                zip_file.write(chunk)

        with zipfile.ZipFile(target_path, "r") as zip_ref:
            zip_ref.extractall(temp_path)

        return temp_path

    def get_artifact_file(
        self,
        commit_sha: str,
        job_name: str,
        artifact_filepath: Path,
        ref: str = None,
    ) -> str:
        """Gets an artifact file data as text.

        Args:
            commit_sha (str): A commit SHA
            job_name (str): A job name
            artifact_filepath (Path): The artifact file path
            ref (str): The branch name.

        Raises:
            Exception: An exception message specifying the reasons for not returning the file data,
            for each pipeline triggered for the given commit SHA.

        Returns:
            str: The artifact text data.
        """
        try:
            pipelines = self.get_pipelines(commit_sha=commit_sha, ref=ref)
            if not pipelines:
                raise Exception("No pipelines found for this SHA")
            errors = []
            for pipeline in pipelines:
                pid = pipeline["id"]
                if job_id := self.get_job_id_by_name(pid, job_name):
                    try:
                        bundle_path = self.download_and_extract_artifacts_bundle(job_id)
                        return (bundle_path / artifact_filepath).read_text()
                    except requests.HTTPError:
                        errors.append(f"Pipeline #{pid}: No artifacts in job {job_name}")
                    except FileNotFoundError:
                        errors.append(f"Pipeline #{pid}: The file {artifact_filepath} does not exist in the artifacts")
                else:
                    errors.append(f"Pipeline #{pid}: No job with the name {job_name}")
            raise Exception("\n".join(errors))

        except Exception as e:
            raise Exception(
                f"Could not extract {artifact_filepath.name} from any pipeline with SHA {commit_sha}:\n{e}"
            )
