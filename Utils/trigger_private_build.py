import re
import argparse
import demisto_sdk.commands.common.tools as tools


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()

    branches = tools.run_command("git branch")
    branch_name_reg = re.search(r"\* (.*)", branches)
    branch_name = branch_name_reg.group(1)
    files_string = tools.run_command("git diff --name-status origin/master...{0}".format(branch_name))


if __name__ == "__main__":
    main()
