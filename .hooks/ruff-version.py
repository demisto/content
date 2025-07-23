import sys
import shutil
import importlib.metadata


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
        # Attempt to get the version of the 'ruff' package
        ruff_version = importlib.metadata.version("ruff")
        sys.stdout.write(f"Ruff package is installed. Version: {ruff_version}\n")
        return ruff_version
    except importlib.metadata.PackageNotFoundError:
        sys.stdout.write("Ruff package is NOT installed in this Python environment.\n")
        return None
    except Exception as e:
        # Catch any other unexpected errors during the process
        sys.stdout.write(f"An unexpected error occurred while checking ruff version: {e}")
        return None


if __name__ == "__main__":
    which_ruff = check_which_ruff()
    if which_ruff:
        ruff_version = get_ruff_version()
        if ruff_version:
            sys.stdout.write(f"{ruff_version}\n")
