import os
import json
import shutil
import argparse
import requests
from zipfile import ZipFile, ZIP_DEFLATED
from Tests.test_utils import print_error


def options_handler():
    parser = argparse.ArgumentParser(description='Utility to download content artifacts from previous builds')
    parser.add_argument('-b', '--branch', help='The branch to get the latest successful build content from')
    parser.add_argument('-p', '--prefix', help='Prefix to prepend to the content artifact '
                        'filenames. Default is "prev_"')

    options = parser.parse_args()

    return options


def get_all_file_paths(directory):

    # initializing empty file paths list
    file_paths = []

    # crawling through directory and subdirectories
    for root, directories, files in os.walk(directory):
        for filename in files:
            # join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)

    # returning all file paths
    return file_paths


def modify_content_descriptor(content_zipfile_name):
    '''
    Unzip the content zipfile. Update the release field inside the content-descriptor.json file
    to an older release number. Rezip.

    Arguments:
        content_zipfile_name: (str)
            The name of the content zipfile whose content-descriptor.json file needs modification

    Returns:
        (str)
        The name of the (updated) content zipfile
    '''
    zipfile_name = content_zipfile_name
    zipfile_write = '.'.join(zipfile_name.split('.')[:-1]) + '_modded.zip'
    if os.path.isfile(zipfile_write):
        os.remove(zipfile_write)
    content_descriptor = 'content-descriptor.json'
    zipwriter = ZipFile(zipfile_write, 'w', compression=ZIP_DEFLATED)
    directory = './extracted_content'
    print('extracting files from content zipfile "{}" to "{}" directory'.format(zipfile_name, directory))
    with ZipFile(zipfile_name, 'r') as the_zip:
        if os.path.exists(directory):
            shutil.rmtree(directory)
        os.makedirs(directory)
        the_zip.extractall(path=directory)

    desc_json = {}
    prev_dir = os.getcwd()
    os.chdir(directory)
    file_paths = get_all_file_paths('.')
    for file_path in file_paths:
        file_name = file_path.split('/')[-1]
        if file_name == content_descriptor:
            with open(file_path, 'r') as the_file:
                file_contents = the_file.read()
                desc_json = json.loads(file_contents)
                release_num = desc_json.get('release')
                print('release number was "{}"'.format(release_num))
                split_release_num = release_num.split('.')
                decreased_digit = str(int(split_release_num[0]) - 1)
                new_release_num_arr = [decreased_digit]
                new_release_num_arr.extend(split_release_num[1:])
                new_release_num = '.'.join(new_release_num_arr)
                print('decreasing release number to "{}"'.format(new_release_num))
                desc_json['release'] = new_release_num
            with open(file_path, 'w') as the_file:
                the_file.write(json.dumps(desc_json))
        zipwriter.write(file_path)
    print('zipped to new zip file "{}"'.format(zipfile_write))
    os.chdir(prev_dir)
    # remove original content zipfile
    os.remove(zipfile_name)
    print('original zipfile "{}" successfully deleted'.format(zipfile_name))
    # rename modified content zipfile to original content zipfile name
    os.rename(zipfile_write, zipfile_name)
    print('modified zipfile "{}" renamed to "{}"'.format(zipfile_write, zipfile_name))
    return zipfile_name


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
    # Disable insecure warnings
    requests.packages.urllib3.disable_warnings()

    options = options_handler()
    branch = options.branch
    branch = branch if branch else 'master'
    prefix = options.prefix
    prefix = prefix if prefix else 'prev_'
    resp = get_latest_artifacts(branch)
    for artifact in resp.json():
        file_name = artifact.get('path', '').split('/')[-1]
        if file_name in ['content_new.zip', 'content_test.zip']:
            new_file_name = prefix + file_name
            dl_url = artifact.get('url', '')
            download_artifact(dl_url, new_file_name)
            # update release number of content_new.zip
            if file_name == 'content_new.zip':
                modify_content_descriptor(new_file_name)


if __name__ == '__main__':
    main()
