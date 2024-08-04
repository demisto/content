import os
from pathlib import Path
import typer

CONTENT_ROOT = Path(__file__).parents[2]
assert CONTENT_ROOT.name == "content" or (
    os.getenv("CIRCLECI") and CONTENT_ROOT.name == "project"
), f'{CONTENT_ROOT=}, expected its name to be "content", or "project" when in CircleCI'

CONTRIBUTION_PROTECTED_DIRECTORIRES: set[Path] = {
    CONTENT_ROOT / top_level_directory_name
    for top_level_directory_name in (
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
GLOBALLY_PROTECTED_FILES: set[Path] = {
    CONTENT_ROOT / path for path in (".gitlab/ci/.gitlab-ci.yml",)
}

EXCEPTIONS: set[Path] = {
    CONTENT_ROOT / "Tests/conf.json",
}


def resolve_content_path(path: Path) -> Path:
    if path.is_relative_to(CONTENT_ROOT):
        return path
    return CONTENT_ROOT / path


def extract_first_level_folder(path: Path) -> Path:
    return path.relative_to(CONTENT_ROOT).parents[0]


def is_path_change_allowed(path: Path, is_contribution: bool) -> bool:
    if path in GLOBALLY_PROTECTED_FILES:  # enforced in all branches
        return path in EXCEPTIONS

    # Contributions are also checked against a list of top-level folders
    if is_contribution and any(
        path.is_relative_to(protected_dir)
        for protected_dir in CONTRIBUTION_PROTECTED_DIRECTORIRES
    ):
        return path in EXCEPTIONS  # if in exception, it's allowed

    return True


def main(
    changed_files: list[Path] = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        file_okay=True,
        help="List of modified files",
    ),
    is_contribution: bool = typer.Option(
        ...,
        "--contribution-pr/--non-contribution-pr",
        envvar="IS_CONTRIBUTION",
    ),
) -> None:
    changed_files = [resolve_content_path(path) for path in changed_files]

    if unsafe_changes := sorted(
        path
        for path in changed_files
        if not is_path_change_allowed(path, is_contribution)
    ):
        for path in unsafe_changes:
            print(  # noqa: T201
                f"::error file={path},line=1,endLine=1,title=Protected folder::"
                "Modifying infrastructure files in contribution branches is not allowed."
            )
        raise typer.Exit(1)

    print("Done, no files were found in prohibited paths")  # noqa: T201


if __name__ == "__main__":
    typer.run(main)
