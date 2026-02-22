import argparse
import os
import sys
from pathlib import Path

CONTENT_ROOT = Path(__file__).parents[2]
assert CONTENT_ROOT.name == "content" or (os.getenv("CIRCLECI") and CONTENT_ROOT.name == "project")

PROTECTED_DIRECTORY_PATHS: set[Path] = {
    Path(CONTENT_ROOT, dir_name)
    for dir_name in (
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

PROTECTED_FILE_PATHS: set[Path] = {Path(CONTENT_ROOT, file_name) for file_name in ("AGENTS.md",)}

EXCEPTIONS: set[Path] = {
    Path(CONTENT_ROOT, "Tests/conf.json"),
}


def is_path_change_allowed(path: Path) -> bool:
    full_path = path if CONTENT_ROOT.name in path.parts else Path(CONTENT_ROOT, path)

    if full_path in PROTECTED_FILE_PATHS:
        return full_path in EXCEPTIONS

    first_level_dir = Path(CONTENT_ROOT, full_path.relative_to(CONTENT_ROOT).parts[0])
    if first_level_dir in PROTECTED_DIRECTORY_PATHS:
        return full_path in EXCEPTIONS
    return True


def main(changed_files: list[str]):
    if unsafe_changes := sorted(full_path for full_path in changed_files if not is_path_change_allowed(Path(full_path))):
        for path in unsafe_changes:
            print(  # noqa: T201
                f"::error file={path},line=1,endLine=1,title=Protected folder::"
                "Modifying infrastructure files in contribution branches is not allowed."
            )
        sys.exit(1)

    print("Done, no files were found in prohibited paths")  # noqa: T201


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for changes in protected directories.")
    parser.add_argument("changed_files", nargs="+", help="List of changed files.")
    args = parser.parse_args()
    main(args.changed_files)
