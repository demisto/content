import subprocess
import sys


def main(*filenames):
    subprocess.run(["demisto-sdk", "pre-commit", *filenames])


if __name__ == "__main__":
    main(*sys.argv[1:])
