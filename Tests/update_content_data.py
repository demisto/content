import argparse
import demisto_client
import os
# import requests
# import urllib3
# from Tests.test_content import load_conf_files
from Tests.test_utils import print_error

SERVER_URL = 'https://{}'
# Disable insecure warnings
# urllib3.disable_warnings()


def options_handler():
    parser = argparse.ArgumentParser(description='Utility to upload new content')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-s', '--server', help='The server URL to connect to (leaving out the protocol e.g.'
                        ' without \'https://\')', required=True)
    parser.add_argument('-c', '--conf', help='Path to conf file')
    parser.add_argument('-e', '--secret', help='Path to secret conf file')
    parser.add_argument('-up', '--content_zip', help='Path to new content zipfile to upload', required=True)

    options = parser.parse_args()

    return options


def upload_content(server, username, password, content_zip_path):
    try:
        c = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
        file_path = os.path.abspath(content_zip_path)
        files = {'file': file_path}
        header_params = {'Content-Type': 'multipart/form-data'}

        msg = '\nMaking "POST" request to server - "{}" to upload'.format(server)
        msg += ' the content zip file "{}"'.format(content_zip_path)
        print(msg)
        res = c.api_client.call_api(resource_path='/content/upload', method='POST',
                                    header_params=header_params, files=files)

        if isinstance(res, tuple):
            status_code = res[1]
        else:
            status_code = res.status_code
        if status_code >= 300 or status_code < 200:
            msg = "Upload has failed with status code " + str(status_code)
            raise Exception(msg)
        else:
            print('\n"{}" successfully uploaded to server "{}"'.format(content_zip_path, server))
    except Exception as e:
        print_error(str(e))


# def get_xsrf_token(server, username, password):
#     print('\nMaking request to fetch xsrf-token')
#     base_url = server
#     body = {
#         'user': username,
#         'password': password
#     }
#     res = requests.get(base_url, data=body, verify=False)
#     if res.status_code < 200 or res.status_code >= 300:
#         msg = 'requests exception: [{}] - ' \
#               '{}\n{}'.format(res.status_code, res.reason, res.text)
#         raise Exception(msg)
#     else:
#         print('\nrequest to fetch xsrf-token was successful')
#     set_cookie = res.headers.get('Set-Cookie', '')
#     split_set_cookie = set_cookie.split(';')
#     xsrf_token = split_set_cookie[0].replace('XSRF-TOKEN=', '')
#     return xsrf_token, res.cookies


# def login(server, username, password, xsrf_token, cookies):
#     print('\nMaking request to login to demisto server instance')
#     url = server + '/login'
#     headers = {'X-XSRF-TOKEN': xsrf_token, 'Accept': 'application/json', 'Content-Type': 'application/json'}
#     body = {
#         'user': username,
#         'password': password
#     }
#     res = requests.post(url, headers=headers, cookies=cookies, json=body, verify=False)
#     if res.status_code < 200 or res.status_code >= 300:
#         msg = 'requests exception: [{}] - ' \
#               '{}\n{}'.format(res.status_code, res.reason, res.text)
#         raise Exception(msg)
#     else:
#         print('\nrequest to login was successful')
#     return res.cookies


def main():
    options = options_handler()
    server = options.server
    server = SERVER_URL.format(server)
    # conf_path = options.conf
    # secret_conf_path = options.secret
    username = options.user
    password = options.password
    content_zip_path = options.content_zip

    # conf, secret_conf = load_conf_files(conf_path, secret_conf_path)

    # username = secret_conf.get('username')
    # password = secret_conf.get('userPassword')
    # demisto_api_key = secret_conf.get('temp_apikey')
    upload_content(server, username, password, content_zip_path)


if __name__ == '__main__':
    main()
