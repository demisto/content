import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kwargs", nargs="*")
    args = parser.parse_args()
    subprocess.run(["demisto-sdk", "pre-commit", *args.kwargs])


if __name__ == "__main__":
    main()
