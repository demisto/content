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
    found_files = []
    # Check if any protected directories have been modified
    for changed_file in changed_files:
        changed_path = Path(changed_file)
        top_level_directory = changed_path.parents[1]
        if top_level_directory.name in PROTECTED_DIRECTORIES and changed_file not in EXCEPTIONS:
            print(f"Error: Contribution branch includes changes to files under {top_level_directory}, "
                  f"which is a protected directory. Please revert them. (file: {changed_file})")
            found_files.append(changed_file)
    if found_files:
        sys.exit(1)
    else:
        print("Done, no files were found in prohibited paths")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for changes in protected directories.")
    parser.add_argument("changed_files", nargs="+", help="List of changed files.")
    args = parser.parse_args()
    main(args.changed_files)
