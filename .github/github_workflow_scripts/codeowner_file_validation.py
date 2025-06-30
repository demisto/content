import requests
from utils import timestamped_print
import os
import sys

# Constants
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
BRANCH_NAME = os.getenv("BRANCH_NAME", "main")
CODEOWNERS = "CODEOWNERS"
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
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }

    try:
        response = requests.get(url, headers=headers, params={"ref": BRANCH_NAME})
        response.raise_for_status()
        return response.json()

    except Exception as e:
        return {"error": True, "message": str(e)}


def main() -> int:
    repository_owner = "demisto"
    repository_name = "content"

    try:
        validation_result = validate_codeowners_file(repository_owner, repository_name)

        if validation_result.get("error", False):
            print(f"CODEOWNERS Validation failed: {validation_result.get('message')}")
            return 1

        if errors := validation_result.get("errors", []):
            print(f"CODEOWNERS file has {len(errors)} error(s):")
            for error in errors:
                print(f"{error.get('line', 'N/A')}: {error.get('kind')}, {error.get('message')}\n")
                if suggestion := error.get("suggestion"):
                    print(f"Fix line {error.get('line', 'N/A')} Suggestion: {suggestion}\n")
            return 1
        else:
            print("CODEOWNERS file is valid! No errors found.")
            return 0

    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
