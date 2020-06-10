import argparse
import os
import ast
import demisto_client

from demisto_sdk.commands.common.tools import print_error


def options_handler():
    parser = argparse.ArgumentParser(description='Utility to upload new content')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-s', '--server', help='The server to connect to (leaving out the protocol e.g.'
                                               ' without \'https://\')', required=True)
    parser.add_argument('--content_zip', help='Path to new content zipfile to upload', required=True)

    options = parser.parse_args()

    return options


def update_content(content_zip_path, server=None, username=None, password=None, client=None):
    """Update the content on a demisto instance with the content files in a zip file.

    Args:
        server (str): URL of the demisto server instance.
        username (str): Username to login to the demisto instance.
        password (str): Password of the associated username to login to the demisto insatnce.
        content_zip_path (str): The path to the zip file containing content files.
        client (demisto_client): The configured client to use.
    """
    try:
        # Configure Demisto Client and make request to upload content zip file
        if not client:
            client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
        file_path = os.path.abspath(content_zip_path)
        files = {'file': file_path}
        header_params = {'Content-Type': 'multipart/form-data'}

        msg = '\nMaking "POST" request to server - "{}" to upload'.format(server)
        msg += ' the content zip file "{}"'.format(content_zip_path)
        print(msg)
        response_data, status_code, _ = client.api_client.call_api(resource_path='/content/upload', method='POST',
                                                                   header_params=header_params, files=files)

        if status_code >= 300 or status_code < 200:
            result_object = ast.literal_eval(response_data)
            message = result_object['message']
            msg = "Upload has failed with status code " + str(status_code) + '\n' + message
            raise Exception(msg)
        else:
            print('\n"{}" successfully uploaded to server "{}"'.format(content_zip_path, server))
    except Exception as e:
        print_error(str(e))


def main():
    options = options_handler()
    server_url = 'https://{}'
    server = options.server if options.server.startswith('http') else server_url.format(options.server)
    username = options.user
    password = options.password
    content_zip_path = options.content_zip
    update_content(content_zip_path, server, username, password)


if __name__ == '__main__':
    main()
