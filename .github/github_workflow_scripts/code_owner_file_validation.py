import requests
from utils import timestamped_print
import os
import sys

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
BRANCH_NAME = os.getenv("BRANCH_NAME", "main")
print = timestamped_print

def validate_codeowners_file(owner: str, repo: str) -> dict:
    """
    Validates the CODEOWNERS file for a given GitHub repository using codeowners/errors endpoint.

    Args:
        owner (str): The owner of the repository.
        repo (str): The name of the repository.

    Returns:
        dict: A dictionary containing the API response. If successful, it will
              contain a 'errors' key with a list of error objects (if any),
              or an empty list if the CODEOWNERS file is valid.
              If an error occurs during the API call, it will contain 'error'
              and 'message' keys.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/codeowners/errors"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        response = requests.get(url, headers=headers, params={"ref": BRANCH_NAME})
        response.raise_for_status()
        data = response.json()
        return data

    except RequestException as e:
        print(f"RequestException: {e.response.status_code} - {e.response.text}")
        return {"error": True, "message": f"RequestException: {e.response.status_code} - {e.response.text}"}

if __name__ == "__main__":

    repository_owner = "demisto"
    repository_name = "content"

    validation_result = validate_codeowners_file(repository_owner, repository_name)

    if validation_result.get("error",False):
        print(f"Validation failed: {validation_result['message']}")
    else:
        if errors := validation_result.get("errors", []):
            print("CODEOWNERS file has errors:")
            for error in errors:
                print(f" - Line {error.get('line', 'N/A')}: {error.get('message', 'No message provided')}\n")
            sys.exit(1)
        else:
            timestamped_print("\nCODEOWNERS file is valid! No errors found.")

