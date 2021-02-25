import argparse


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()
    #add step after prepare environment to trigger the build
    #add test after run unit test and lint to get the status
    # use git diff to get the files and decide if need to run

    #call https://api.github.com/repos/demisto/content-private/actions/runs?branch=master&event=repository_dispatch twice and get the last workflow

    #polling the get status


if __name__ == "__main__":
    main()
