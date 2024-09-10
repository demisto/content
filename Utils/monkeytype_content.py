import pprint
import argparse
import os
import subprocess
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
    if path.is_file():
        path = path.parent
    runner_path = path / "runner.py"
    env = create_env_var_dict(path)
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
        ["python", "-m", "monkeytype", "list-modules"], text=True, check=True, capture_output=True, cwd=path, env=env
    ).stdout.splitlines()
    filtered_modules = set(modules).difference(
        (
            "demistomock",
            # "CommonServerPython",
        )
    )

    runner_path.write_text("\n".join(f"import {module}\n{module}.main()" for module in filtered_modules))
    for module in filtered_modules:
        subprocess.run(["python", "-m", "monkeytype", "-v", "stub", module], check=True, cwd=path, env=env)
    Path(path / "modules.txt").write_text("\n".join(filtered_modules))
    runner_path.unlink()


# def apply_monkeytype(path: Path):
#     integration_or_script_path = path.parent
#     env = create_env_var_dict(integration_or_script_path)
#     if (modules_path := path.with_name("modules.txt")).exists():
#         for module in (modules_path).read_text().splitlines():
#             result = subprocess.run(
#                 ["run", "monkeytype", "-v", "apply", module],
#                 env=env,
#                 cwd=integration_or_script_path,
#             )
#             if result.returncode:
#                 raise ValueError(f"{result}")
#     else:
#         print(f"modules doesn't exist under {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="ContentMonkeyType", description="Generates monkeytype stubs and applies them")
    parser.add_argument("command")
    parser.add_argument("path", help="path to the content item folder or modules file")

    args = parser.parse_args()
    path = Path(args.path)

    if args.command == "run":
        run_monkeytype(path)
    # elif args.command == "apply":
    #     apply_monkeytype(path)
    else:
        raise NotImplementedError("invalid command")
