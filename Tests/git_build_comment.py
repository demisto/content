from sys import argv
import requests


def github_errors(response):
    res_dict = response.json()
    if response.ok:
        return res_dict
    raise Exception(res_dict.get('message'))


def main():
    print('------------------------------------')
    if len(argv) != 5:
        raise ValueError('no params.')
    try:
        with open('./skipped_tests.txt', 'r') as tests:
            # failes
            skipped_tests = tests.read()
    except FileNotFoundError:
        pass
    else:
        if skipped_tests:
            token = argv[1]
            branch_name = argv[2]
            sha1 = argv[3]
            query = f'?q={sha1}+head:{branch_name}+is:open+is:pr+org:demisto+repo:demisto/contetnt'
            url = 'https://api.github.com/search/issues'
            headers = {'Authorization': 'Bearer ' + token}
            res = requests.get(url + query, headers=headers, verify=False)
            res = github_errors(res)
            if res and res.get('total_count', 0) == 1:
                issue_url = res['items'][0].get('comments_url') if res.get('items', []) else None
                if issue_url:
                    print('-------------------------------------------'
                          '---------------------------------------------------')
                    # res = requests.post(issue_url, json={'body': skipped_tests}, headers=headers, verify=False)
                    # github_errors(res)
            else:
                raise Exception('there is more then one open pr to the same branch.')


main()
