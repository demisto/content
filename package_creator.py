#!/usr/bin/env python

import os
import sys
import glob
import yaml
import base64
import argparse
import re

DIR_TO_PREFIX = {
    'Integrations': 'integration',
    'Scripts': 'script'
}

TYPE_TO_EXTENSION = {
    'python': '.py',
    'javascript': '.js'
}

IMAGE_PREFIX = 'data:image/png;base64,'


def merge_script_package_to_yml(package_path, dir_name, dest_path=""):
    """Merge the various components to create an output yml file

    Args:
        package_path (str): Directory containing the various files
        dir_name (str): Parent directory containing package (Scripts/Integrations)
        dest_path (str, optional): Defaults to "". Destination output

    Returns:
        output path, script path, image path
    """
    output_filename = '{}-{}.yml'.format(DIR_TO_PREFIX[dir_name], os.path.basename(os.path.dirname(package_path)))
    if dest_path:
        output_path = os.path.join(dest_path, output_filename)
    else:
        output_path = os.path.join(dir_name, output_filename)

    yml_path = glob.glob(package_path + '*.yml')[0]
    with open(yml_path, 'r') as yml_file:
        yml_data = yaml.safe_load(yml_file)

    if dir_name == 'Scripts':
        script_type = TYPE_TO_EXTENSION[yml_data['type']]
    elif dir_name == 'Integrations':
        script_type = TYPE_TO_EXTENSION[yml_data['script']['type']]

    with open(yml_path, 'r') as yml_file:
        yml_text = yml_file.read()

    yml_text, script_path = insert_script_to_yml(package_path, script_type, yml_text, dir_name, yml_data)
    yml_text, image_path = insert_image_to_yml(dir_name, package_path, yml_data, yml_text)
    yml_text, desc_path = insert_description_to_yml(dir_name, package_path, yml_data, yml_text)

    with open(output_path, 'w') as f:
        f.write(yml_text)
    return output_path, yml_path, script_path, image_path, desc_path


def insert_image_to_yml(dir_name, package_path, yml_data, yml_text):
    image_path = glob.glob(package_path + '*png')
    found_img_path = None
    if dir_name == 'Integrations' and image_path:
        found_img_path = image_path[0]
        with open(found_img_path, 'rb') as image_file:
            image_data = image_file.read()

        if yml_data.get('image'):
            yml_text = yml_text.replace(yml_data['image'], IMAGE_PREFIX + base64.b64encode(image_data))

        else:
            yml_text = 'image: ' + IMAGE_PREFIX + base64.b64encode(image_data) + '\n' + yml_text

    return yml_text, found_img_path


def insert_description_to_yml(dir_name, package_path, yml_data, yml_text):
    desc_data, found_desc_path = get_data(dir_name, package_path, '*md')

    if yml_data.get('detaileddescription'):
        if yml_data['detaileddescription'] != '-':
            raise ValueError("Please change the detailed description to a dash(-)")
    if desc_data:
        yml_text = yml_text.replace("detaileddescription: '-'", "detaileddescription:" + desc_data)

    return yml_text, found_desc_path


def get_data(dir_name, package_path, extension):
    data_path = glob.glob(package_path + extension)
    data = None
    found_data_path = None
    if dir_name == 'Integrations' and data_path:
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

    ignore_regex = r'CommonServerPython\.py|CommonServerUserPython\.py|demistomock\.py|test_.*\.py|_test\.py'
    script_path = list(filter(lambda x: not re.search(ignore_regex, x),
                              glob.glob(package_path + '*' + script_type)))[0]
    return script_path


def insert_script_to_yml(package_path, script_type, yml_text, dir_name, yml_data):
    script_path = get_code_file(package_path, script_type)
    with open(script_path, 'r') as script_file:
        script_code = script_file.read()

    script_code = clean_python_code(script_code)

    lines = ['|-']
    lines.extend('    {}'.format(line) for line in script_code.split('\n'))
    script_code = '\n'.join(lines)

    if dir_name == 'Scripts':
        if yml_data.get('script'):
            if yml_data['script'] != '-':
                raise ValueError("Please change the script to a dash(-)")

    elif dir_name == 'Integrations':
        if yml_data.get('script', {}).get('script'):
            if yml_data['script']['script'] != '-':
                raise ValueError("Please change the script to a dash(-)")

    yml_text = yml_text.replace("script: '-'", "script: " + script_code)

    return yml_text, script_path


def clean_python_code(script_code):
    script_code = script_code.replace("import demistomock as demisto", "")
    script_code = script_code.replace("from CommonServerPython import *", "")
    script_code = script_code.replace("from CommonServerUserPython import *", "")
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
    for dir_name in DIR_TO_PREFIX.keys():
        if dir_name in package_path:
            directory_name = dir_name

    if not directory_name:
        print "You have failed to provide a legal file path, a legal file path " \
              "should contain either Integrations or Scripts directories"
        sys.exit(1)

    return package_path, directory_name, dest_path


if __name__ == "__main__":
    package_path, dir_name, dest_path = get_package_path()
    output, yml, script, image = merge_script_package_to_yml(package_path, dir_name, dest_path)
    print("Done creating: {}, from: {}, {}, {}".format(output, yml, script, image))
