import subprocess
import sys


def get_ruff_version():
    try:
        result = subprocess.run([sys.executable, "-m", "ruff", "--version"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


if __name__ == "__main__":
    ruff_version = get_ruff_version()
    if ruff_version:
        print(f"Ruff version: {ruff_version}")
    else:
        print("Could not determine Ruff version.")
