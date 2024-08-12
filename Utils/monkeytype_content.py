import os
import subprocess
import sys
from pathlib import Path


def compile_python_path(path: Path):
    for parent in path.parents:
        if parent.name == 'Packs':
            packs = parent
            content_path = packs.parent
            python_path = [packs / "Base/Scripts/CommonServerPython",
                           content_path / "Tests/demistomock",
                           content_path,
                           path
                           ]
            api_modules = packs / "ApiModules" / "Scripts"
            if api_modules.exists():
                python_path.extend(path.absolute() for path in api_modules.iterdir())
            return python_path
    raise RuntimeError("Could not find Packs folder")


def run_monkeytype(path: Path):
    if path.is_file():
        path = path.parent
    runner_path = path / "runner.py"
    python_path = ':'.join(str(path_) for path_ in compile_python_path(path))
    env = os.environ.copy() | {'PYTHONPATH': os.environ['PYTHONPATH'] + ":" + python_path}
    try:
        subprocess.run(
            [
                "python3",
                "-m",
                "pytest",
                str(path),
                "--monkeytype-output=./monkeytype.sqlite3",
            ],
            check=True,
            env=env,
            cwd=path,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        print(e.stdout)
        raise
    modules = subprocess.run(
        ["python3", "-m", "monkeytype", "list-modules"], text=True, check=True, capture_output=True, cwd=path, env=env
    ).stdout.splitlines()
    print(6)
    # filtered_modules = set(modules).difference(("demistomock", "CommonServerPython"))
    # runner_path.write_text("\n".join(f"import {module}\n{module}.main()" for module in filtered_modules))
    # for module in filtered_modules:
    #     subprocess.run(["monkeytype", "-v", "stub", module], check=True, cwd=path, env=env)
    #     subprocess.run(["monkeytype", "-v", "apply", module], check=True, cwd=path, env=env)
    # runner_path.unlink()


if __name__ == "__main__":
    run_monkeytype(Path(sys.argv[1]))
