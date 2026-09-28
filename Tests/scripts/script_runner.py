# This script receives a command to run and a list of files to run it on.
# Each command is executed in the working directory of the file it runs on, because some of our scripts
# must run in the same working directory as the file they are running on.
# By default the files are processed serially. Setting the SCRIPT_RUNNER_JOBS environment variable to a
# value greater than 1 processes them concurrently using a bounded thread pool (capped at MAX_JOBS).
# This script should support python2 and should not use external libraries, as it will run in minimal docker containers
import subprocess
import os
import sys
from multiprocessing.pool import ThreadPool

# Upper bound on the number of concurrent workers, to avoid oversubscribing the container CPUs.
MAX_JOBS = 8
# Environment variable used to opt into concurrent execution.
JOBS_ENV_VAR = "SCRIPT_RUNNER_JOBS"


def get_jobs():
    """Return the number of workers to use, defaulting to 1 (serial) and clamped to MAX_JOBS.

    Parsing is defensive: an unset, empty, non-integer or non-positive value falls back to 1.
    """
    try:
        jobs = int(os.environ.get(JOBS_ENV_VAR, "1"))
    except (TypeError, ValueError):
        return 1
    if jobs < 1:
        return 1
    return min(jobs, MAX_JOBS)


def run_script(args, files):
    results = []
    try:
        jobs = get_jobs()
        if jobs <= 1 or len(files) <= 1:
            for file in files:
                results.append(run_command(args + [os.path.abspath(file)], os.path.dirname(file)))
        else:
            # Threads (not processes) are used on purpose: every worker blocks in subprocess.run,
            # which releases the GIL, so the actual work happens in separate OS processes anyway.
            # Note: a worker exception does not stop the pool early. map() waits for every chunk to
            # finish before propagating, so unlike the serial path the remaining queued files still
            # run; only the rest of the raising worker's own chunk is skipped.
            pool = ThreadPool(jobs)
            try:
                results = pool.map(lambda file: run_command(args + [os.path.abspath(file)], os.path.dirname(file)), files)
            finally:
                pool.close()
                pool.join()
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
    if sys.version_info[0] < 3:  # noqa: UP036
        return subprocess.call(args, cwd=directory)
    return subprocess.run(args, cwd=directory).returncode


def main():
    args = sys.argv[1:]
    files_index = args.index("--files") if "--files" in args else -1
    script_args = args[:files_index]
    files = None
    if files_index != -1:
        files = args[files_index + 1 :]

    # Run the script
    exit_code = run_script(script_args, files)
    if exit_code:
        raise SystemExit(exit_code)
    SystemExit(exit_code)


if __name__ == "__main__":
    main()
