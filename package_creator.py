#!/usr/bin/env python
from __future__ import print_function
import os
import io
import sys
import glob
import base64
import argparse
import re
import yaml

from Tests.test_utils import server_version_compare

IS_CI = os.getenv('CI', False)

DIR_TO_PREFIX = {
    'Integrations': 'integration',
    'Beta_Integrations': 'integration',
    'Scripts': 'script'
}

TYPE_TO_EXTENSION = {
    'python': '.py',
    'javascript': '.js',
    'powershell': '.ps1'
}

IMAGE_PREFIX = 'data:image/png;base64,'


def write_yaml_with_docker(output_path, yml_text, yml_data, script_obj):
    """Write out the yaml file taking into account the dockerimage45 tag.
    If it is present will create 2 integration files
    One for 4.5 and below and one for 5.0.

    Arguments:
        output_path {str} -- output path
        yml_text {str} -- yml text
        yml_data {dict} -- yml object
        script_obj {dict} -- script object

    Returns:
        dict -- dictionary mapping output path to text data
    """
    output_map = {output_path: yml_text}
    if 'dockerimage45' in script_obj:
        # we need to split into two files 45 and 50. Current one will be from version 5.0
        yml_text = re.sub(r'^\s*dockerimage45:.*\n?', '', yml_text, flags=re.MULTILINE)  # remove the dockerimage45 line
        yml_text45 = yml_text
        if 'fromversion' in yml_data:
            # validate that this is a script/integration which targets both 4.5 and 5.0+.
            if server_version_compare(yml_data['fromversion'], '5.0.0') >= 0:
                raise ValueError('Failed: {}. dockerimage45 set for 5.0 and later only'.format(output_path))
            yml_text = re.sub(r'^fromversion:.*$', 'fromversion: 5.0.0', yml_text, flags=re.MULTILINE)
        else:
            yml_text = 'fromversion: 5.0.0\n' + yml_text
        if 'toversion' in yml_data:
            # validate that this is a script/integration which targets both 4.5 and 5.0+.
            if server_version_compare(yml_data['toversion'], '5.0.0') < 0:
                raise ValueError('Failed: {}. dockerimage45 set for 4.5 and earlier only'.format(output_path))
            yml_text45 = re.sub(r'^toversion:.*$', 'toversion: 4.5.9', yml_text45, flags=re.MULTILINE)
        else:
            yml_text45 = 'toversion: 4.5.9\n' + yml_text45
        if script_obj.get('dockerimage45'):  # we have a value for dockerimage45 set it as dockerimage
            yml_text45 = re.sub(r'(^\s*dockerimage:).*$', r'\1 ' + script_obj.get('dockerimage45'),
                                yml_text45, flags=re.MULTILINE)
        else:  # no value for dockerimage45 remove the dockerimage entry
            yml_text45 = re.sub(r'^\s*dockerimage:.*\n?', '', yml_text45, flags=re.MULTILINE)
        output_path45 = re.sub(r'\.yml$', '_45.yml', output_path)
        output_map = {
            output_path: yml_text,
            output_path45: yml_text45
        }
    for file_path, file_text in output_map.items():
        if IS_CI and os.path.isfile(file_path):
            raise ValueError('Output file already exists: {}.'
                             ' Make sure to remove this file from source control'
                             ' or rename this package (for example if it is a v2).'.format(output_path))
        with io.open(file_path, mode='w', encoding='utf-8') as file_:
            file_.write(file_text)
    return output_map


def merge_script_package_to_yml(package_path, dir_name, dest_path=""):
    """Merge the various components to create an output yml file

    Args:
        package_path (str): Directory containing the various files
        dir_name (str): Parent directory containing package (Scripts/Integrations)
        dest_path (str, optional): Defaults to "". Destination output

    Returns:
        output path, script path, image path
    """
    print("Merging package: {}".format(package_path))
    output_filename = '{}-{}.yml'.format(DIR_TO_PREFIX[dir_name], os.path.basename(os.path.dirname(package_path)))
    if dest_path:
        output_path = os.path.join(dest_path, output_filename)
    else:
        output_path = os.path.join(dir_name, output_filename)

    yml_paths = glob.glob(package_path + '*.yml')
    yml_path = yml_paths[0]
    for path in yml_paths:
        # The plugin creates a unified YML file for the package.
        # In case this script runs locally and there is a unified YML file in the package we need to ignore it.
        # Also,
        # we don't take the unified file by default because there might be packages that were not created by the plugin.
        if 'unified' not in path:
            yml_path = path
            break

    with open(yml_path, 'r') as yml_file:
        yml_data = yaml.safe_load(yml_file)

    script_obj = yml_data

    if dir_name != 'Scripts':
        script_obj = yml_data['script']
    script_type = TYPE_TO_EXTENSION[script_obj['type']]

    with io.open(yml_path, mode='r', encoding='utf-8') as yml_file:
        yml_text = yml_file.read()

    yml_text, script_path = insert_script_to_yml(package_path, script_type, yml_text, dir_name, yml_data)
    image_path = None
    desc_path = None
    if dir_name in ('Integrations', 'Beta_Integrations'):
        yml_text, image_path = insert_image_to_yml(dir_name, package_path, yml_data, yml_text)
        yml_text, desc_path = insert_description_to_yml(dir_name, package_path, yml_data, yml_text)

    output_map = write_yaml_with_docker(output_path, yml_text, yml_data, script_obj)
    return list(output_map.keys()), yml_path, script_path, image_path, desc_path


def insert_image_to_yml(dir_name, package_path, yml_data, yml_text):
    image_data, found_img_path = get_data(dir_name, package_path, "*png")
    image_base64 = base64.b64encode(image_data).decode('utf-8')
    image_data = IMAGE_PREFIX + image_base64

    if yml_data.get('image'):
        yml_text = yml_text.replace(yml_data['image'], image_data)

    else:
        yml_text = 'image: ' + image_data + '\n' + yml_text
    # verify that our yml is good (loads and returns the image)
    mod_yml_data = yaml.safe_load(yml_text)
    yml_image = mod_yml_data.get('image')
    assert yml_image.strip() == image_data.strip()

    return yml_text, found_img_path


def insert_description_to_yml(dir_name, package_path, yml_data, yml_text):
    if yml_data.get('detaileddescription'):
        raise ValueError('Please move the detailed description from the yml to a description file (.md)'
                         ' in the package: {}'.format(package_path))

    desc_data, found_desc_path = get_data(dir_name, package_path, '*_description.md')
    if desc_data:
        desc_data = desc_data.decode('utf-8')
        if not desc_data.startswith('"'):
            # for multiline detailed-description, if it's not wrapped in quotation marks
            # add | to the beginning of the description, and shift everything to the right
            desc_data = '|\n  ' + desc_data.replace('\n', '\n  ')
        temp_yml_text = u"detaileddescription: "
        temp_yml_text += desc_data
        temp_yml_text += u"\n"
        temp_yml_text += yml_text

        yml_text = temp_yml_text

    return yml_text, found_desc_path


def get_data(dir_name, package_path, extension):
    data_path = glob.glob(package_path + extension)
    data = None
    found_data_path = None
    if dir_name in ('Integrations', 'Beta_Integrations') and data_path:
        found_data_path = data_path[0]
        with open(found_data_path, 'rb') as data_file:
            data = data_file.read()

    return data, found_data_path


def get_code_file(package_path, script_type):
    """Return the first code file in the specified directory path

    :param package_path: directory to search for code file
    :type package_path: str
    :param script_type: script type: .py or .js
    :type script_type: str
    :return: path to found code file
    :rtype: str
    """

    ignore_regex = r'CommonServerPython\.py|CommonServerUserPython\.py|' \
                   r'demistomock\.py|test_.*\.py|_test\.py|conftest\.py'
    if not package_path.endswith('/'):
        package_path += '/'
    if package_path.endswith('Scripts/CommonServerPython/'):
        return package_path + 'CommonServerPython.py'

    script_path = list(filter(lambda x: not re.search(ignore_regex, x),
                              glob.glob(package_path + '*' + script_type)))[0]
    return script_path


def insert_script_to_yml(package_path, script_type, yml_text, dir_name, yml_data):
    script_path = get_code_file(package_path, script_type)
    with io.open(script_path, mode='r', encoding='utf-8') as script_file:
        script_code = script_file.read()

    clean_code = clean_python_code(script_code)

    lines = ['|-']
    lines.extend(u'    {}'.format(line) for line in clean_code.split('\n'))
    script_code = u'\n'.join(lines)

    if dir_name == 'Scripts':
        if yml_data.get('script'):
            if yml_data['script'] != '-' and yml_data['script'] != '':
                raise ValueError("Please change the script to be blank or a dash(-) for package {}"
                                 .format(package_path))

    elif dir_name in ('Integrations', 'Beta_Integrations'):
        if yml_data.get('script', {}).get('script'):
            if yml_data['script']['script'] != '-' and yml_data['script']['script'] != '':
                raise ValueError("Please change the script to be blank or a dash(-) for package {}"
                                 .format(package_path))
    else:
        raise ValueError('Unknown yml type for dir: {}. Expecting: Scripts/Integrations'.format(package_path))

    yml_text = yml_text.replace("script: ''", "script: " + script_code)
    yml_text = yml_text.replace("script: '-'", "script: " + script_code)

    # verify that our yml is good (loads and returns the code)
    mod_yml_data = yaml.safe_load(yml_text)
    if dir_name == 'Scripts':
        yml_script = mod_yml_data.get('script')
    else:
        yml_script = mod_yml_data.get('script', {}).get('script')

    assert yml_script.strip() == clean_code.strip()

    return yml_text, script_path


def clean_python_code(script_code, remove_print_future=True):
    script_code = script_code.replace("import demistomock as demisto", "")
    script_code = script_code.replace("from CommonServerPython import *", "")
    script_code = script_code.replace("from CommonServerUserPython import *", "")
    # print function is imported in python loop
    if remove_print_future:  # docs generation requires to leave this
        script_code = script_code.replace("from __future__ import print_function", "")
    return script_code


def get_package_path():
    parser = argparse.ArgumentParser(description='Utility merging package yml with its code into one yml file')
    parser.add_argument('-p', '--packagePath', help='Path to the package', required=True)
    parser.add_argument('-d', '--destPath', help='Destination directory path for the result yml', default="")
    options = parser.parse_args()
    package_path = options.packagePath
    dest_path = options.destPath
    if package_path[-1] != '/':
        package_path = package_path + '/'

    directory_name = ""
    for dir_name in DIR_TO_PREFIX:
        if dir_name in package_path:
            directory_name = dir_name

    if not directory_name:
        print("You have failed to provide a legal file path, a legal file path "
              "should contain either Integrations or Scripts directories")
        sys.exit(1)

    return package_path, directory_name, dest_path


def main():
    package_path, dir_name, dest_path = get_package_path()
    output, yml, script, image, _ = merge_script_package_to_yml(package_path, dir_name, dest_path)
    print("Done creating: {}, from: {}, {}, {}".format(output, yml, script, image))


if __name__ == "__main__":
    main()
