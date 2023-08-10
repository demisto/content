import enum
import json
from tempfile import mkdtemp
import zipfile
from pathlib import Path
from typing import Any

import requests


API_BASE_URL = "https://code.pan.run/api/v4"  # disable-secrets-detection
PROJECT_ID = '2596'


class GetArtifactErrors(str, enum.Enum):
    NO_PIPELINES = "No pipelines for this SHA"
    NO_JOB = "No jobs with the specified name"
    NO_ARTIFACTS = "No artifacts in the specified job"
    NO_FILE_IN_ARTIFACTS = "The specified file does not exist in the artifacts"


class GitlabClient:
    def __init__(self, gitlab_token: str) -> None:
        self.base_url = f"{API_BASE_URL}/projects/{PROJECT_ID}"
        self.project_id = '2596'
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

    def get_pipelines_by_sha(self, commit_sha: str) -> list:
        return self._get(f"pipelines?sha={commit_sha}", to_json=True)

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
    ) -> str:
        """Gets an artifact file data as text.

        Args:
            commit_sha (str): A commit SHA
            job_name (str): A job name
            artifact_filepath (Path): The artifact file path

        Raises:
            Exception: An exception message specifying the reasons for not returning the file data.

        Returns:
            str: The artifact text data.
        """
        pipeline_ids = [p["id"] for p in self.get_pipelines_by_sha(commit_sha)]
        pid_to_err = {}
        for pipeline_id in pipeline_ids:
            if job_id := self.get_job_id_by_name(pipeline_id, job_name):
                try:
                    bundle_path = self.download_and_extract_artifacts_bundle(job_id)
                    return (bundle_path / artifact_filepath).read_text()
                except requests.HTTPError:
                    pid_to_err[pipeline_id] = GetArtifactErrors.NO_ARTIFACTS.value
                except FileNotFoundError:
                    pid_to_err[pipeline_id] = GetArtifactErrors.NO_FILE_IN_ARTIFACTS.value
            else:
                pid_to_err[pipeline_id] = GetArtifactErrors.NO_JOB.value

        raise Exception(
            f"Could not extract {artifact_filepath.name} from any pipeline of SHA {commit_sha}. "
            f"Err: {GetArtifactErrors.NO_PIPELINES.value if not pipeline_ids else pid_to_err}"
        )

    def get_packs_dependencies_json(
        self,
        commit_sha: str,
        job_name: str,
        marketplace: str,
    ) -> dict:
        file_path = Path(f"artifacts/{marketplace}/packs_dependencies.json")
        return json.loads(
            self.get_artifact_file(commit_sha, job_name, file_path)
        )
