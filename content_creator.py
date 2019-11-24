import os
import sys
import json
import glob
import shutil
import zipfile
import io
import yaml

from Tests.scripts.constants import INTEGRATIONS_DIR, MISC_DIR, PLAYBOOKS_DIR, REPORTS_DIR, DASHBOARDS_DIR, \
    WIDGETS_DIR, SCRIPTS_DIR, INCIDENT_FIELDS_DIR, CLASSIFIERS_DIR, LAYOUTS_DIR, CONNECTIONS_DIR, \
    BETA_INTEGRATIONS_DIR, INDICATOR_FIELDS_DIR, INCIDENT_TYPES_DIR, TEST_PLAYBOOKS_DIR
from Tests.test_utils import print_error
from package_creator import DIR_TO_PREFIX, merge_script_package_to_yml, write_yaml_with_docker

CONTENT_DIRS = [
    BETA_INTEGRATIONS_DIR,
    CLASSIFIERS_DIR,
    CONNECTIONS_DIR,
    DASHBOARDS_DIR,
    INCIDENT_FIELDS_DIR,
    INCIDENT_TYPES_DIR,
    INDICATOR_FIELDS_DIR,
    INTEGRATIONS_DIR,
    LAYOUTS_DIR,
    MISC_DIR,
    PLAYBOOKS_DIR,
    REPORTS_DIR,
    SCRIPTS_DIR,
    WIDGETS_DIR,
]

PACKAGES_TO_SKIP = [
    'HelloWorld',
    'HelloWorldSimple',
    'HelloWorldScript'
]

# temp folder names
BUNDLE_POST = 'bundle_post'
BUNDLE_TEST = 'bundle_test'
# zip files names (the extension will be added later - shutil demands file name without extension)
ZIP_POST = 'content_new'
ZIP_TEST = 'content_test'

# server can't handle long file names
MAX_FILE_NAME = 85
LONG_FILE_NAMES = []


def get_child_directories(directory):
    '''Return a list of paths of immediate child directories of the 'directory' argument'''
    child_directories = [
        os.path.join(directory, path) for
        path in os.listdir(directory) if os.path.isdir(os.path.join(directory, path))
    ]
    return child_directories


def create_unifieds_and_copy(package_dir, dest_dir=BUNDLE_POST, skip_dest_dir=BUNDLE_TEST):
    '''
    For directories that have packages, aka subdirectories for each integration/script
    e.g. "Integrations", "Beta_Integrations", "Scripts". Creates a unified yml and writes
    it to the dest_dir

    Arguments:
        package_dir: (str)
            Path to directory in which there are package subdirectories. e.g. "Integrations",
            "Beta_Integrations", "Scripts"
        dest_dir: (str)
            Path to destination directory to which the unified yml for a package should be written
        skip_dest_dir: (str)
            Path to the directory to which the unified yml for a package should be written in the
            case the package is part of the skipped list
    '''
    scanned_packages = glob.glob(os.path.join(package_dir, '*/'))
    for package in scanned_packages:
        if any(package_to_skip in package for package_to_skip in PACKAGES_TO_SKIP):
            # there are some packages that we don't want to include in the content zip
            # for example HelloWorld integration
            merge_script_package_to_yml(package, package_dir, BUNDLE_TEST)
            print('skipping {}'.format(package))
        else:
            merge_script_package_to_yml(package, package_dir, BUNDLE_POST)


def add_tools_to_bundle(bundle):
    for directory in glob.glob(os.path.join('Tools', '*')):
        zipf = zipfile.ZipFile(os.path.join(bundle, f'tools-{os.path.basename(directory)}.zip'), 'w',
                               zipfile.ZIP_DEFLATED)
        zipf.comment = b'{ "system": true }'
        for root, _, files in os.walk(directory):
            for file in files:
                zipf.write(os.path.join(root, file), file)
        zipf.close()


# modify incident fields file to contain only `incidentFields` field (array)
# from { "incidentFields": [...]} to [...]
def convert_incident_fields_to_array(incident_fields_dir=INCIDENT_FIELDS_DIR):
    scan_files = glob.glob(os.path.join(incident_fields_dir, '*.json'))
    for path in scan_files:
        with open(path, 'r+') as file_:
            data = json.load(file_)
            incident_fields = data.get('incidentFields')
            if incident_fields is not None:
                file_.seek(0)
                json.dump(incident_fields, file_, indent=2)
                file_.truncate()


def copy_yaml_post(path, out_path, yml_info):
    parent_dir_name = os.path.basename(os.path.dirname(path))
    if parent_dir_name in DIR_TO_PREFIX.keys() and not os.path.basename(path).startswith('playbook-'):
        script_obj = yml_info
        if parent_dir_name != 'Scripts':
            script_obj = yml_info['script']
        with io.open(path, mode='r', encoding='utf-8') as file_:
            yml_text = file_.read()
        out_map = write_yaml_with_docker(out_path, yml_text, yml_info, script_obj)
        if len(out_map.keys()) > 1:
            print(" - yaml generated multiple files: {}".format(out_map.keys()))
        return
    # not a script or integration file. Simply copy
    shutil.copyfile(path, out_path)


def copy_dir_yml(dir_path, bundle_post):
    scan_files = glob.glob(os.path.join(dir_path, '*.yml'))
    post_files = 0
    for path in scan_files:
        if len(os.path.basename(path)) >= MAX_FILE_NAME:
            LONG_FILE_NAMES.append(path)

        with open(path, 'r') as file_:
            yml_info = yaml.safe_load(file_)

        ver = yml_info.get('fromversion', '0')
        print(f' - processing: {ver} ({path})')
        copy_yaml_post(path, os.path.join(bundle_post, os.path.basename(path)), yml_info)
        post_files += 1
    print(f' - total files: {post_files}')


def copy_dir_json(dir_path, bundle_post):
    # handle *.json files
    dir_name = os.path.basename(dir_path)
    scan_files = glob.glob(os.path.join(dir_path, '*.json'))
    for path in scan_files:
        dpath = os.path.basename(path)
        # this part is a workaround because server doesn't support indicatorfield-*.json naming
        if dir_name == 'IndicatorFields':
            new_path = dpath.replace('incidentfield-', 'incidentfield-indicatorfield-')
            if os.path.isfile(new_path):
                raise NameError('Failed while trying to create {}. File already exists.'.format(new_path))
            dpath = new_path

        if len(dpath) >= MAX_FILE_NAME:
            LONG_FILE_NAMES.append(os.path.basename(dpath))

        shutil.copyfile(path, os.path.join(bundle_post, dpath))


def copy_dir_files(*args):
    # handle *.json files
    copy_dir_json(*args)
    # handle *.yml files
    copy_dir_yml(*args)


def copy_test_files(bundle_test, test_playbooks_dir=TEST_PLAYBOOKS_DIR):
    print('Copying test files to test bundle')
    scan_files = glob.glob(os.path.join(test_playbooks_dir, '*'))
    for path in scan_files:
        if os.path.isdir(path):
            non_circle_tests = glob.glob(os.path.join(path, '*'))
            for new_path in non_circle_tests:
                print(f'copying path {new_path}')
                shutil.copyfile(new_path, os.path.join(bundle_test, os.path.basename(new_path)))

        else:
            print(f'Copying path {path}')
            shutil.copyfile(path, os.path.join(bundle_test, os.path.basename(path)))


def main(circle_artifacts):
    print('Starting to create content artifact...')

    print('creating dir for bundles...')
    for bundle_dir in [BUNDLE_POST, BUNDLE_TEST]:
        os.mkdir(bundle_dir)

    add_tools_to_bundle(BUNDLE_POST)

    convert_incident_fields_to_array()

    for package_dir in DIR_TO_PREFIX:
        scanned_packages = glob.glob(os.path.join(package_dir, '*/'))
        for package in scanned_packages:
            if any(package_to_skip in package for package_to_skip in PACKAGES_TO_SKIP):
                # there are some packages that we don't want to include in the content zip
                # for example HelloWorld integration
                merge_script_package_to_yml(package, package_dir, BUNDLE_TEST)
                print('skipping {}'.format(package))
            else:
                merge_script_package_to_yml(package, package_dir, BUNDLE_POST)

    for content_dir in CONTENT_DIRS:
        print(f'Copying dir {content_dir} to bundles...')
        copy_dir_files(content_dir, BUNDLE_POST)

    copy_test_files(BUNDLE_TEST)

    print('Copying content descriptor to bundles')
    for bundle_dir in [BUNDLE_POST, BUNDLE_TEST]:
        shutil.copyfile('content-descriptor.json', os.path.join(bundle_dir, 'content-descriptor.json'))

    print('copying common server doc to bundles')
    shutil.copyfile('./Documentation/doc-CommonServer.json', os.path.join(BUNDLE_POST, 'doc-CommonServer.json'))

    print('Compressing bundles...')
    shutil.make_archive(ZIP_POST, 'zip', BUNDLE_POST)
    shutil.make_archive(ZIP_TEST, 'zip', BUNDLE_TEST)
    shutil.copyfile(ZIP_POST + '.zip', os.path.join(circle_artifacts, ZIP_POST + '.zip'))
    shutil.copyfile(ZIP_TEST + '.zip', os.path.join(circle_artifacts, ZIP_TEST + '.zip'))
    shutil.copyfile("./Tests/id_set.json", os.path.join(circle_artifacts, "id_set.json"))

    shutil.copyfile('release-notes.md', os.path.join(circle_artifacts, 'release-notes.md'))

    print(f'finished create content artifact at {circle_artifacts}')


if __name__ == '__main__':
    main(sys.argv[1])
    if LONG_FILE_NAMES:
        print_error(f'The following files exceeded to file name length limit of {MAX_FILE_NAME}:\n'
                    f'{json.dumps(LONG_FILE_NAMES, indent=4)}')
        sys.exit(1)
