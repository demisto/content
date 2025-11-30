import requests
from utils import (
    timestamped_print,
    GITHUB_API_BASE_URL,
    GITHUB_API_VERSION,
    get_env_var,
    GITHUB_TOKEN,
    BRANCH_NAME,
    ORGANIZATION_NAME,
    REPO_NAME,
)
import sys

# Constants
print = timestamped_print


def validate_codeowners_file(owner: str, repo: str) -> dict:
    """Validates the CODEOWNERS file by request to the "/codeowners/errors" endpoint.

    Args:
        owner: The owner of the repository.
        repo: The name of the repository.

    Returns:
        Dict containing the validation result.
    """

    url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/codeowners/errors"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {get_env_var(GITHUB_TOKEN)}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }

    try:
        response = requests.get(url, headers=headers, params={"ref": get_env_var(BRANCH_NAME)})
        response.raise_for_status()
        return response.json()

    except Exception as e:
        return {"error": True, "message": str(e)}


def main() -> int:
    try:
        validation_result = validate_codeowners_file(ORGANIZATION_NAME, REPO_NAME)

        if validation_result.get("error", False):
            print(f"CODEOWNERS Validation failed: {validation_result.get('message')}")
            return 1

        if errors := validation_result.get("errors", []):
            print(f"CODEOWNERS file has {len(errors)} error(s):")
            for error in errors:
                suggestion = f"; Fix Suggestion: {error.get('suggestion')}" if error.get("suggestion") else ""
                print(
                    f"Line {error.get('line', 'N/A')} ERROR: {error.get('kind')}: {error.get('source','').rstrip()}{suggestion}"
                )
            return 1
        else:
            print("CODEOWNERS file is valid! No errors found.")
            return 0

    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
