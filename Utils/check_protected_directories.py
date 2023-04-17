import argparse
import sys
from pathlib import Path

PROTECTED_DIRECTORIES = {
    ".circleci",
    ".devcontainer",
    ".github",
    ".github/workflows",
    ".gitlab",
    ".guardrails",
    ".hooks",
    ".vscode",
    "Templates",
    "TestData",
    "TestPlaybooks",
    "Tests",
    "Utils"
}

EXCEPTIONS = {
    "Tests/conf.json"
}


def main(changed_files):
    # Check if any protected directories have been modified
    for changed_file in changed_files:
        changed_path = Path(changed_file)
        top_level_directory = changed_path.parents[-1].as_posix()
        if top_level_directory in PROTECTED_DIRECTORIES and changed_file not in EXCEPTIONS:
            print(f"Error: Changes made to protected directory - {top_level_directory}: {changed_file}")
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for changes in protected directories.")
    parser.add_argument("changed_files", nargs="+", help="List of changed files.")
    args = parser.parse_args()
    main(args.changed_files)
