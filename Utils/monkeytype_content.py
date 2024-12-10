import os
import subprocess
import sys
from pathlib import Path


def compile_python_path(path: Path):
    for parent in path.parents:
        if parent.name == "Packs":
            packs = parent
            content_path = packs.parent
            python_path = [
                packs / "Base/Scripts/CommonServerPython",
                content_path / "Tests/demistomock",
                content_path,
                path,
            ]
            api_modules = packs / "ApiModules" / "Scripts"
            if api_modules.exists():
                python_path.extend(path.absolute() for path in api_modules.iterdir())
            return python_path
    raise RuntimeError("Could not find Packs folder")


def create_env_var_dict(path: Path):
    python_path = ":".join(str(path_) for path_ in compile_python_path(path))
    return os.environ.copy() | {"PYTHONPATH": os.environ["PYTHONPATH"] + ":" + python_path}


def run_monkeytype(path: Path):
    """
    This function runs monkeytype on the Python files in the path's folder.
    It knows how to identify variable types and recommends adding typing according to the tests.
    """
    if path.is_file():
        path = path.parent
    runner_path = path / "runner.py"  # a temporary file, generated at runtime,
    # solving an issue where MonkeyType can't run on files outside of python packages
    env = create_env_var_dict(path)
    subprocess.run(
        [
            "pytest",
            str(path),
            "--monkeytype-output=./monkeytype.sqlite3",
        ],
        capture_output=True,
        env=env,
        cwd=path,
    )
    modules = subprocess.run(
        # list the python files to run on (usually `<integration>.py` and `test_<integration>.py`)
        ["monkeytype", "list-modules"],
        text=True,
        capture_output=True,
        cwd=path,
        env=env,
    ).stdout.splitlines()
    filtered_modules = set(modules).difference(
        ("demistomock", "CommonServerPython")
    )  # we don't want to run monkeytype on these
    runner_path.write_text(
        "\n".join(f"import {module}\n{module}.main()" for module in filtered_modules)
    )
    for module in filtered_modules:  # actually run monkeytype on each module
        subprocess.run(
            ["monkeytype", "-v", "stub", module], cwd=path, env=env, capture_output=True
        )
        subprocess.run(
            ["monkeytype", "-v", "apply", module], cwd=path, env=env, capture_output=True
            # apply works but exit status is non-zero
        )
    runner_path.unlink()  # that was a temporary file we no longer need
    (path / "monkeytype.sqlite3").unlink()  # created by monkeytype


if __name__ == "__main__":
    run_monkeytype(Path(sys.argv[2]))
