import argparse
import sys
from pathlib import Path

<<<<<<< HEAD
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
=======
CONTENT_ROOT = Path(__file__).parents[1]
assert CONTENT_ROOT.name == "content"

PROTECTED_DIRECTORY_PATHS: set[Path] = {
    Path(CONTENT_ROOT, dir_name)
    for dir_name in (
        ".circleci",
        ".devcontainer",
        ".github",
        ".gitlab",
        ".guardrails",
        ".hooks",
        ".vscode",
        "Templates",
        "TestData",
        "TestPlaybooks",
        "Tests",
        "Utils",
    )
}

EXCEPTIONS: set[Path] = {
    Path(CONTENT_ROOT, "Tests/conf.json"),
}


def is_path_change_allowed(path: Path) -> bool:
    try:
        first_level_dir = path.relative_to(CONTENT_ROOT).parts[0]  # e.g. Packs, Utils
    except ValueError as e:
        raise ValueError(f"Expected {path} to be under {CONTENT_ROOT}") from e

    if Path(CONTENT_ROOT, first_level_dir) in PROTECTED_DIRECTORY_PATHS:
        return path in EXCEPTIONS  # if in exception, it's allowed
    return True


def main(changed_files: list[str]):
    if unsafe_changes := sorted(
        path for path in changed_files if not is_path_change_allowed(Path(path))
    ):
        for path in unsafe_changes:
            print(  # noqa: T201
                f"::error file={path},line=1,endLine=1,title=Protected folder::"
                "Modifying infrastructure files in contribution branches is not allowed."
            )
        sys.exit(1)

    print("Done, no files were found in prohibited paths")  # noqa: T201


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check for changes in protected directories."
    )
>>>>>>> master
    parser.add_argument("changed_files", nargs="+", help="List of changed files.")
    args = parser.parse_args()
    main(args.changed_files)
