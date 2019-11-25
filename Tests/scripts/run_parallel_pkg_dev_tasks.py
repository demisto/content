#!/usr/bin/env python3
import os
import sys
import subprocess
import concurrent.futures
from typing import List, Optional, Tuple

from pkg_dev_test_tasks import get_dev_requirements

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/uploads/2018/07/Demisto-Icon-Dark.png'

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.abspath(SCRIPT_DIR + '/../..')
sys.path.append(CONTENT_DIR)
from Tests.test_utils import print_color, LOG_COLORS  # noqa: E402


def run_dev_task(pkg_dir: str, params: Optional[List[str]]) -> Tuple[subprocess.CompletedProcess, str]:
    args = [SCRIPT_DIR + '/pkg_dev_test_tasks.py', '-d', pkg_dir]
    if params:
        args.extend(params)
    cmd_line = " ".join(args)
    # color stderr in red and remove the warning about no config file from pylint
    cmd_line += r" 2> >(sed '/No config file found, using default configuration/d' | sed $'s,.*,\x1B[31m&\x1B[0m,'>&1)"
    res = subprocess.run(cmd_line, text=True, capture_output=True, shell=True, executable='/bin/bash')
    return res, pkg_dir


def should_run_pkg(pkg_dir: str) -> bool:
    diff_compare = os.getenv("DIFF_COMPARE")
    if not diff_compare:
        return True
    if os.getenv('CONTENT_PRECOMMIT_RUN_DEV_TASKS'):
        # if running in precommit we check against staged
        diff_compare = '--staged'
    res = subprocess.run(["git", "diff", "--name-only", diff_compare, "--", pkg_dir], text=True, capture_output=True)
    if res.stdout:
        return True
    return False


def handle_run_res(res: Tuple[subprocess.CompletedProcess, str], fail_pkgs: list, good_pkgs: list):
    if res[0].returncode != 0:
        fail_pkgs.append(res[1])
        print_color("============= {} =============".format(res[1]), LOG_COLORS.RED)
    else:
        good_pkgs.append(res[1])
        print("============= {} =============".format(res[1]))
    print(res[0].stdout)
    print(res[0].stderr)


def create_result_files(failed_unittests):
    with open('./Tests/failed_unittests.txt', "w") as failed_unittests_file:
        failed_unittests_file.write('\n'.join(failed_unittests))


def main():
    if len(sys.argv) == 2 and (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
        print("Run pkg_dev_test_tasks.py in parallel. Accepts same parameters as pkg_dev_test_tasks.py.\n"
              "Additionally you can specify the following environment variables:\n"
              "DIFF_COMPARE: specify how to do a git compare. Leave empty to run on all.\n"
              "MAX_WORKERS: max amount of workers to use for running "
              )
        sys.exit(1)
    max_workers = int(os.getenv("MAX_WORKERS", "10"))
    find_out = subprocess.check_output(["find", "Integrations", "Scripts", "Beta_Integrations",
                                        "-maxdepth", "1", "-mindepth", "1", "-type", "d", "-print"], text=True)
    pkg_dirs = find_out.splitlines()
    pkgs_to_run = []
    for dir in pkg_dirs:
        if should_run_pkg(dir):
            pkgs_to_run.append(dir)
    print("Starting parallel run for [{}] packages with [{}] max workers".format(len(pkgs_to_run), max_workers))
    params = sys.argv[1::]
    fail_pkgs = []
    good_pkgs = []
    if len(pkgs_to_run) > 1:  # setup pipenv before hand to avoid conflics
        get_dev_requirements(2.7)
        get_dev_requirements(3.7)
    # run CommonServer non parallel to avoid conflicts
    # when we modify the file for mypy includes
    if 'Scripts/CommonServerPython' in pkgs_to_run:
        pkgs_to_run.remove('Scripts/CommonServerPython')
        res = run_dev_task('Scripts/CommonServerPython', params)
        handle_run_res(res, fail_pkgs, good_pkgs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures_submit = [executor.submit(run_dev_task, dir, params) for dir in pkgs_to_run]
        for future in concurrent.futures.as_completed(futures_submit):
            res = future.result()
            handle_run_res(res, fail_pkgs, good_pkgs)
    if fail_pkgs:
        create_result_files(fail_pkgs)
        print_color("\n******* FAIL PKGS: *******", LOG_COLORS.RED)
        print_color("\n\t{}\n".format("\n\t".join(fail_pkgs)), LOG_COLORS.RED)
    if good_pkgs:
        print_color("\n******* SUCCESS PKGS: *******", LOG_COLORS.GREEN)
        print_color("\n\t{}\n".format("\n\t".join(good_pkgs)), LOG_COLORS.GREEN)
    if not good_pkgs and not fail_pkgs:
        print_color("\n******* No changed packages found *******\n", LOG_COLORS.YELLOW)
    if fail_pkgs:
        sys.exit(1)


if __name__ == "__main__":
    main()
