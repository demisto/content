import argparse
import requests
from Tests.test_utils import print_error


def options_handler():
    parser = argparse.ArgumentParser(description='Utility to upload new content')
    parser.add_argument('-b', '--branch', help='The branch to get the latest successful build content from')

    options = parser.parse_args()

    return options


def get_latest_artifacts(branch):
    try:
        print('Making request to get the artifacts from the latest successful build on branch "{}"'.format(branch))
        params = {
            'branch': branch,
            'filter': 'successful'
        }
        res = requests.get('https://circleci.com/api/v1.1/project/github/demisto/content/latest/artifacts',
                           params=params)
        if res.status_code < 200 or res.status_code >= 300:
            msg = 'requests exception: [{}] - ' \
                  '{}\n{}'.format(res.status_code, res.reason, res.text)
            raise Exception(msg)
        print('Request for latest artifacts successful')
        return res
    except Exception as e:
        print_error(str(e))


def download_artifact(url, file_name=''):
    try:
        artifact = url.split('/')[-1]
        print('Making request to download the "{}" artifact'.format(artifact))
        res = requests.get(url, stream=True)
        if res.status_code < 200 or res.status_code >= 300:
            msg = 'requests exception: [{}] - ' \
                  '{}\n{}'.format(res.status_code, res.reason, res.text)
            raise Exception(msg)
        else:
            print('Request to download the "{}" artifact successful'.format(artifact))

        if not file_name:
            file_name = artifact
        
        print('Writing artifact to local storage')

        with open(file_name, 'wb') as f:
            for chunk in res.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        print('Artifact successfully saved to local storage as "{}"'.format(file_name))
    except Exception as e:
        print_error(str(e))


def main():
    options = options_handler()
    branch = options.branch
    branch = branch if branch else 'master'
    resp = get_latest_artifacts(branch)
    for artifact in resp.json():
        file_name = artifact.get('path', '').split('/')[-1]
        if file_name in ['content_new.zip', 'content_test.zip']:
            new_file_name = 'prev_' + file_name
            dl_url = artifact.get('url', '')
            download_artifact(dl_url, new_file_name)


if __name__ == '__main__':
    main()
