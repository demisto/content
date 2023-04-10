import argparse
import re
import sys

PROTECTED_DIRECTORIES = [
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
]

EXCEPTIONS = [
    "Tests/conf.json",
    ".github/scripts/check_protected_directories.py"
    ".github/workflows/protect-directories.yml"
]


def main(changed_files):
    # Check if any protected directories have been modified
    for changed_file in changed_files:
        for protected_dir in PROTECTED_DIRECTORIES:
            if re.match(f"^{protected_dir}/", changed_file) and not (changed_file in EXCEPTIONS):
                print(f"Error: Changes made to protected directory - {protected_dir}: {changed_file}")
                sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for changes in protected directories.")
    parser.add_argument("changed_files", nargs="+", help="List of changed files.")
    args = parser.parse_args()
    main(args.changed_files)
