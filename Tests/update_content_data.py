import argparse
import os
import ast
import demisto_client
import logging

from Tests.scripts.utils.log_util import install_simple_logging


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
        password (str): Password of the associated username to login to the demisto instance.
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
        logging.info(
            f'Making "POST" request to server - "{server}" to upload the content zip file "{content_zip_path}"')
        response_data, status_code, _ = client.api_client.call_api(resource_path='/content/upload', method='POST',
                                                                   header_params=header_params, files=files)

        if status_code >= 300 or status_code < 200:
            result_object = ast.literal_eval(response_data)
            message = result_object['message']
            raise Exception(f"Upload has failed with status code {status_code}\n{message}")
        else:
            logging.success(f'"{content_zip_path}" successfully uploaded to server "{server}"')
    except Exception:
        logging.exception(f'Failed to upload {content_zip_path} to server {server}')


def main():
    install_simple_logging()
    options = options_handler()
    server_url = 'https://{}'
    server = options.server if options.server.startswith('http') else server_url.format(options.server)
    username = options.user
    password = options.password
    content_zip_path = options.content_zip
    update_content(content_zip_path, server, username, password)


if __name__ == '__main__':
    main()
