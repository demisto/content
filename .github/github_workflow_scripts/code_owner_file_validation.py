import requests
from utils import timestamped_print
import os
import sys

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
BRANCH_NAME = os.getenv("BRANCH_NAME", "main")

def validate_codeowners_file(owner: str, repo: str) -> dict:
    """
    Validates the CODEOWNERS file for a given GitHub repository using the GitHub API.

    This function sends a GET request to the 'list-codeowners-errors' endpoint
    of the GitHub REST API to check for any syntax or validity errors in the
    CODEOWNERS file.

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
    api_version = "2022-11-28"
    url = f"https://api.github.com/repos/{owner}/{repo}/codeowners/errors"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": api_version,
    }

    try:
        response = requests.get(url, headers=headers, params={"ref": BRANCH_NAME})
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        data = response.json()
        return data

    except requests.exceptions.HTTPError as e:
        timestamped_print(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
        return {"error": True, "message": f"HTTP error: {e.response.status_code} - {e.response.text}"}
    except requests.exceptions.ConnectionError as e:
        timestamped_print(f"Connection error occurred: {e}")
        return {"error": True, "message": f"Connection error: {e}"}
    except requests.exceptions.Timeout as e:
        timestamped_print(f"Timeout error occurred: {e}")
        return {"error": True, "message": f"Timeout error: {e}"}
    except requests.exceptions.RequestException as e:
        timestamped_print(f"An unexpected request error occurred: {e}")
        return {"error": True, "message": f"An unexpected request error: {e}"}
    except ValueError as e:
        timestamped_print(f"Failed to decode JSON response: {e}")
        return {"error": True, "message": f"Failed to decode JSON response: {e}"}


if __name__ == "__main__":
    # --- Configuration ---
    repository_owner = "demisto"
    repository_name = "content"

    validation_result = validate_codeowners_file(repository_owner, repository_name)

    if "error" in validation_result and validation_result["error"]:
        timestamped_print(f"Validation failed: {validation_result['message']}")
    else:
        errors = validation_result.get("errors", [])
        if errors:
            timestamped_print("\nCODEOWNERS file has errors:")
            for error in errors:
                # Each error object might have keys like 'line', 'column', 'kind', 'message', 'path'
                line = error.get("line", "N/A")
                message = error.get("message", "No message provided")
                timestamped_print(f"  - Line {line}: {message}")
            sys.exit(1)
        else:
            timestamped_print("\nCODEOWNERS file is valid! No errors found.")

    timestamped_print("\n--- Script Finished ---")
