import subprocess
import sys
import shutil


def check_which_ruff():
    ruff_path = shutil.which("ruff")
    if ruff_path:
        sys.stdout.write("Ruff is installed\n")
        return True
    else:
        sys.stdout.write("Ruff is NOT found in the system's PATH.\n")
        return False


def get_ruff_version():
    try:
        result = subprocess.run([sys.executable, "-m", "ruff", "--version"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "subprocess.CalledProcessError"
    except FileNotFoundError:
        return "FileNotFoundError"
    except Exception:
        return "Exception"


if __name__ == "__main__":
    which_ruff = check_which_ruff()
    if which_ruff:
        ruff_version = get_ruff_version()
        if ruff_version:
            sys.stdout.write(f"{ruff_version}\n")
