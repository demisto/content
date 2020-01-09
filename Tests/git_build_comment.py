import sys
import requests
from urllib3 import disable_warnings
from typing import Dict


def github_errors(response):
    res_dict = response.json()
    if response.ok:
        return res_dict
    else:
        raise Exception(res_dict.get('message'))


def main():
    if len(sys.argv) != 4:
        raise ValueError('no params.')
    try:
        with open('./skipped_tests.txt', 'r') as tests:
            skipped_tests = tests.read()
    except FileNotFoundError:
        return
    else:
        if skipped_tests:
            token = sys.argv[1]
            branch_name = sys.argv[2]
            sha1 = sys.argv[3]
            q = f'?q={sha1}+head:{branch_name}+is:open+is:pr+org:demisto+repo:demisto/contetnt'
            url = 'https://api.github.com/search/issues'
            disable_warnings()
            headers = {'Authorization': 'Bearer ' + token}
            res = requests.get(url + q, headers=headers, verify=False)
            res = github_errors(res)
            if res and res.get('total_count', 0) == 1:
                issue_url = res['items'][0].get('comments_url') if res.get('items', []) else None
                if issue_url:
                    print('----------------------------------------------------------------------------------------------')
                    # res = requests.post(issue_url, json={'body': skipped_tests}, headers=headers, verify=False)
                    # github_errors(res)
                    pass
            else:
                raise Exception('there is more then one open pr to the same branch.')


main()
