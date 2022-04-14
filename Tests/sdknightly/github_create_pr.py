try:
    from github import Github
    import argparse
    from Tests.scripts.utils.log_util import install_logging
    from Tests.scripts.utils import logging_wrapper as logging
except ImportError as excp:
    raise ImportError ('the github package is not installed {excp.name} {excp.path}')
    

def create_pr_e2e(args):
    org_name = 'demisto'
    repo_name = 'content'
    github_token = args.github_token
    gh = Github(github_token, verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')
    pr_title = 'sdk_nightly: end 2 end tests'
    pr_body = 'sdk_nightly: running end to end tests'
    pr_base_branch = 'master'
    pr = content_repo.create_pull(title=pr_title, body=pr_body, base=pr_base_branch, draft=False)

def main():
    install_logging('create_new_pr_sdk_nightly_end2end.log')
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('pr_name', help='push request name')   
    arg_parser.add_argument('github_token', help='Github token')
    args = arg_parser.parse_args()
    
    create_pr_e2e(args)
    return 

if __name__ == "__main__":
    main()
