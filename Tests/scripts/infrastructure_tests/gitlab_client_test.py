import io
import json
from typing import Any
import zipfile

import pytest

from Tests.scripts.gitlab_client import GitlabClient, GetArtifactErrors


@pytest.fixture
def client() -> GitlabClient:
    return GitlabClient("mock_token")


@pytest.fixture
def sha() -> str:
    return "mock_sha"


@pytest.fixture
def job_name() -> str:
    return "mock_job_name"


@pytest.fixture
def marketplace() -> str:
    return "xsoar"


def mock_artifacts_api_response(
    marketplace: str,
    data: dict | None = None,
) -> bytes:
    mock_bytes = io.BytesIO()
    with zipfile.ZipFile(mock_bytes, 'w') as zipf:
        if data is not None:
            zipf.writestr(
                f'artifacts/{marketplace}/packs_dependencies.json',
                json.dumps(data),
            )

    mock_bytes.seek(0)
    return mock_bytes.getvalue()


def test_get_packs_dependencies(
    client: GitlabClient,
    sha: str,
    job_name: str,
    marketplace: str,
    requests_mock,
) -> None:
    """
        Given:
            - A Gitlab Client
            - A Commit SHA
            - The job name in which a packs_dependencies.json should be stored as an artifact
            - A marketplace version
        When:
            - Calling get_packs_dependencies_json()
        Then:
            - Ensure the response is the expected data.
    """
    packs_dependencies_json: dict = {}
    requests_mock.get(
        f"{client.base_url}/pipelines?sha={sha}",
        json=[{"id": "mock_pipeline_id"}],
    )
    requests_mock.get(
        f"{client.base_url}/pipelines/mock_pipeline_id/jobs",
        json=[{"id": "mock_job_id", "name": job_name}],
    )
    requests_mock.get(
        f"{client.base_url}/jobs/mock_job_id/artifacts",
        content=mock_artifacts_api_response(marketplace, packs_dependencies_json),
    )
    assert client.get_packs_dependencies_json(
        sha,
        job_name,
        marketplace,
    ) == packs_dependencies_json


@pytest.mark.parametrize(
    'pipelines_mock_response, jobs_mock_response, artifacts_mock_repsonse, expected_err',
    [
        pytest.param(
            [],
            None,
            None,
            GetArtifactErrors.NO_PIPELINES,
            id="No Pipelines",
        ),
        pytest.param(
            [{"id": "mock_pipeline_id"}],
            [{"id": "mock_job_id", "name": "some_job"}],
            None,
            GetArtifactErrors.NO_JOB,
            id="No Job",
        ),
        pytest.param(
            [{"id": "mock_pipeline_id"}],
            [{"id": "mock_job_id", "name": "mock_job_name"}],
            {"status_code": 404},
            GetArtifactErrors.NO_ARTIFACTS,
            id="No artifacts",
        ),
        pytest.param(
            [{"id": "mock_pipeline_id"}],
            [{"id": "mock_job_id", "name": "mock_job_name"}],
            {"content": mock_artifacts_api_response(marketplace, data=None)},
            GetArtifactErrors.NO_FILE_IN_ARTIFACTS,
            id="No pack_dependencies.json file in artifacts",
        ),
    ]
)
def test_get_packs_dependencies_bad(
    client: GitlabClient,
    sha: str,
    job_name: str,
    marketplace: str,
    requests_mock: Any,
    pipelines_mock_response: list | None,
    jobs_mock_response: list | None,
    artifacts_mock_repsonse: dict | None,
    expected_err: GetArtifactErrors,
) -> None:
    """
        Given:
            - A Gitlab Client
            - A Commit SHA
            - The job name in which a packs_dependencies.json should be stored as an artifact
            - A marketplace version
            - Test cases for different Gitlab API responses.
        When:
            - Calling get_packs_dependencies_json()
        Then:
            - Ensure an exception is raised for all test cases.
    """
    requests_mock.get(
        f"{client.base_url}/pipelines?sha={sha}",
        json=pipelines_mock_response,
    )
    requests_mock.get(
        f"{client.base_url}/pipelines/mock_pipeline_id/jobs",
        json=jobs_mock_response,
    )
    if artifacts_mock_repsonse:
        requests_mock.get(
            f"{client.base_url}/jobs/mock_job_id/artifacts",
            **artifacts_mock_repsonse,
        )
    with pytest.raises(Exception) as e:
        client.get_packs_dependencies_json(
            sha,
            job_name,
            marketplace,
        )
    assert expected_err.value in str(e)
