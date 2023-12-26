import argparse
import sys
from pathlib import Path

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
    parser.add_argument("changed_files", nargs="+", help="List of changed files.")
    args = parser.parse_args()
    main(args.changed_files)
