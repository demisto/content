# This script receives a command to run and a list of files to run it on.
# It will execute the command in parallel processes using multiprocessing Pool in the file working directory
# This is needed because some of our scripts should run in the same working directory as the file they are running on
# This script should support python2 and should not use external libraries, as it will run in minimal docker containers
import subprocess
import os
import sys


def run_script(args, files):
    results = []
    try:
        for file in files:
            results.append(run_command(args + [os.path.abspath(file)], os.path.dirname(file)))
        if any(result != 0 for result in results):
            return 1
    except subprocess.CalledProcessError as e:
        print("Error: {e}".format(e=e))  # noqa: T201,UP032
        return 1
    except Exception as e:
        print("An error occurred: {e}".format(e=e))  # noqa: T201,UP032
        return 1
    return 0


def run_command(args, directory):
    if sys.version_info[0] < 3:
        return subprocess.call(args, cwd=directory)
    return subprocess.run(args, cwd=directory).returncode


def main():
    args = sys.argv[1:]
    files_index = args.index("--files") if "--files" in args else -1
    script_args = args[:files_index]
    files = None
    if files_index != -1:
        files = args[files_index + 1:]

    # Run the script
    exit_code = run_script(script_args, files)
    if exit_code:
        raise SystemExit(exit_code)
    SystemExit(exit_code)


if __name__ == "__main__":
    main()
