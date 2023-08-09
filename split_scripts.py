import subprocess
from pathlib import Path

path = Path("/Users/ipolishuk/dev/demisto/content/Packs/IAM/Scripts")


def get_all_file_scripts(path: Path) -> list[Path]:
    scripts = []
    for file_name in path.iterdir():
        if file_name.is_file():
            scripts.append(file_name)
    return scripts


def delete_script(script: Path):
    script.unlink()


def split_scripts(scripts: list[Path]):
    for script in scripts:
        cmd = [
            "demisto-sdk",
            "split",
            "-i",
            f"{script}"
        ]
        try:
            subprocess.run(
                cmd
            )
        except Exception as e:
            raise e

        delete_script(script)


def main():
    scripts = get_all_file_scripts(path)
    split_scripts(scripts)


main()