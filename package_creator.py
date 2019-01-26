import os
import sys
import glob
import yaml
import base64
import argparse

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

    yml_text = insert_script_to_yml(package_path, script_type, yml_text, dir_name, yml_data)
    yml_text = insert_image_to_yml(dir_name, package_path, yml_data, yml_text)

    with open(output_path, 'w') as f:
        f.write(yml_text)


def insert_image_to_yml(dir_name, package_path, yml_data, yml_text):
    image_path = glob.glob(package_path + '*png')
    if dir_name == 'Integrations' and image_path:
        with open(image_path[0], 'rb') as image_file:
            image_data = image_file.read()

        if yml_data.get('image'):
            yml_text = yml_text.replace(yml_data['image'], IMAGE_PREFIX + base64.b64encode(image_data))

        else:
            yml_text = 'image: ' + IMAGE_PREFIX + base64.b64encode(image_data) + '\n' + yml_text

    return yml_text


def insert_script_to_yml(package_path, script_type, yml_text, dir_name, yml_data):
    script_path = glob.glob(package_path + '*' + script_type)[0]
    with open(script_path, 'r') as script_file:
        script_code = script_file.read()

    script_code = clean_python_code(script_code)

    lines = ['|-']
    lines.extend('    {}'.format(line) for line in script_code.split('\n'))
    script_code = '\n'.join(lines)

    if dir_name == 'Scripts':
        if yml_data.get('script'):
            yml_text = yml_text.replace(yml_data.get('script'), script_code)
        else:
            yml_text = yml_text.replace("script: ''", "script: " + script_code)

    elif dir_name == 'Integrations':
        if yml_data.get('script', {}).get('script'):
            yml_text = yml_text.replace(yml_data.get('script', {}).get('script'), script_code)
        else:
            yml_text = yml_text.replace("script: ''", "script: " + script_code)

    return yml_text


def clean_python_code(script_code):
    script_code = script_code.replace("import demistomock as demisto", "")
    script_code = script_code.replace("from CommonServerPython import *", "")
    script_code = script_code.replace("from CommonServerUserPython import *", "")
    return script_code


def get_package_path():
    parser = argparse.ArgumentParser(description='Utility merging package yml with its code into one yml file')
    parser.add_argument('-p', '--packagePath', help='Path to the package', required=True)
    parser.add_argument('-d', '--destPath', help='Destination direrctory path for the result yml', default="")
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
    merge_script_package_to_yml(package_path, dir_name, dest_path)
