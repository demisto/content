import os
import sys
import json
import glob
import shutil
import zipfile
import yaml

from Tests.scripts.constants import INTEGRATIONS_DIR, MISC_DIR, PLAYBOOKS_DIR, REPORTS_DIR, DASHBOARDS_DIR, \
    WIDGETS_DIR, SCRIPTS_DIR, INCIDENT_FIELDS_DIR, CLASSIFIERS_DIR, LAYOUTS_DIR, CONNECTIONS_DIR, \
    BETA_INTEGRATIONS_DIR, INDICATOR_FIELDS_DIR, INCIDENT_TYPES_DIR, TEST_PLAYBOOKS_DIR
from package_creator import DIR_TO_PREFIX, merge_script_package_to_yml

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

# temp folder names
BUNDLE_PRE = 'bundle_pre'
BUNDLE_POST = 'bundle_post'
BUNDLE_TEST = 'bundle_test'
# zip files names (the extension will be added later - shutil demands file name without extension)
ZIP_PRE = 'content_yml'
ZIP_POST = 'content_new'
ZIP_TEST = 'content_test'


def is_ge_version(version1, version2):
    # fix the version to arrays of numbers
    version1 = [int(i) for i in str(version1).split('.')]
    ver2 = [int(i) for i in str(version2).split('.')]

    for ver1, ver2 in zip(version1, version2):
        if ver1 > ver2:
            return False
        if ver2 > ver1:
            return True

    # most significant values are equal
    return len(version1) <= len(version2)


def add_tools_to_bundle(bundle):
    for directory in glob.glob(os.path.join('Tools', '*')):
        zipf = zipfile.ZipFile(os.path.join(bundle, 'tools-%s.zip' % (os.path.basename(directory), )), 'w',
                               zipfile.ZIP_DEFLATED)
        zipf.comment = '{ "system": true }'
        for root, _, files in os.walk(directory):
            for file in files:
                zipf.write(os.path.join(root, file), file)
        zipf.close()


# modify incident fields file to contain only `incidentFields` field (array)
# from { "incidentFields": [...]} to [...]
def convert_incident_fields_to_array():
    scan_files = glob.glob(os.path.join(INCIDENT_FIELDS_DIR, '*.json'))
    for path in scan_files:
        with open(path, 'r+') as file_:
            data = json.load(file_)
            incident_fields = data.get('incidentFields')
            if incident_fields is not None:
                file_.seek(0)
                json.dump(incident_fields, file_, indent=2)
                file_.truncate()


def copy_dir_yml(dir_name, version_num, bundle_pre, bundle_post, bundle_test):
    scan_files = glob.glob(os.path.join(dir_name, '*.yml'))
    post_files = 0
    for path in scan_files:
        with open(path, 'r') as file_:
            yml_info = yaml.safe_load(file_)

        ver = yml_info.get('fromversion', '0')
        if ver == '' or is_ge_version(version_num, ver):
            print(' - marked as post: {} ({})'.format(ver, path))
            shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))
            shutil.copyfile(path, os.path.join(bundle_test, os.path.basename(path)))
            post_files += 1
        else:
            # add the file to both bundles
            print(' - marked as pre: {} ({})'.format(ver, path))
            shutil.copyfile(path, os.path.join(bundle_pre, os.path.basename(path)))
            shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))

    print(' - total post files: {}'.format(post_files))


def copy_dir_json(dir_name, version_num, bundle_pre, bundle_post, bundle_test):
    # handle *.json files
    scan_files = glob.glob(os.path.join(dir_name, '*.json'))
    for path in scan_files:
        dpath = os.path.basename(path)
        shutil.copyfile(path, os.path.join(bundle_pre, os.path.basename(path)))
        # this part is a workaround because server doesn't support indicatorfield-*.json naming
        shutil.copyfile(path, os.path.join(bundle_test, os.path.basename(path)))
        if dir_name == 'IndicatorFields':
            new_path = dpath.replace('incidentfield-', 'incidentfield-indicatorfield-')
            if os.path.isfile(new_path):
                raise NameError('Failed while trying to create {}. File already exists.'.format(new_path))
            dpath = new_path
        shutil.copyfile(path, os.path.join(bundle_post, dpath))
        shutil.copyfile(path, os.path.join(bundle_pre, dpath))
        shutil.copyfile(path, os.path.join(bundle_test, dpath))


def copy_dir_files(*args):
    # handle *.json files
    copy_dir_json(*args)
    # handle *.yml files
    copy_dir_yml(*args)


def copy_test_files(bundle_test):
    print('Copying test files to test bundle')
    scan_files = glob.glob(os.path.join(TEST_PLAYBOOKS_DIR, '*'))
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

    # version that separate post bundle from pre bundle
    # e.i. any yml with "fromversion" of <version_num> or more will be only on post bundle
    version_num = "3.5"

    print('Creating dir for bundles ...')
    for bundle in [BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST]:
        os.mkdir(bundle)
        add_tools_to_bundle(bundle)

    convert_incident_fields_to_array()

    for package_dir in DIR_TO_PREFIX:
        scanned_packages = glob.glob(os.path.join(package_dir, '*/'))
        for package in scanned_packages:
            merge_script_package_to_yml(package, package_dir)

    for content_dir in CONTENT_DIRS:
        print(f'Copying dir {content_dir} to bundles...')
        copy_dir_files(content_dir, version_num, BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST)

    copy_test_files(BUNDLE_TEST)

    print('Copying content descriptor to bundles')
    for bundle_dir in [BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST]:
        shutil.copyfile('content-descriptor.json', os.path.join(bundle_dir, 'content-descriptor.json'))

    print('Copying common server doc to bundles')
    for bundle_dir in [BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST]:
        shutil.copyfile('./Documentation/doc-CommonServer.json', os.path.join(bundle_dir, 'doc-CommonServer.json'))

    print('Compressing bundles...')
    shutil.make_archive(ZIP_POST, 'zip', BUNDLE_POST)
    shutil.make_archive(ZIP_PRE, 'zip', BUNDLE_PRE)
    shutil.make_archive(ZIP_TEST, 'zip', BUNDLE_TEST)
    shutil.copyfile(ZIP_PRE + '.zip', os.path.join(circle_artifacts, ZIP_PRE + '.zip'))
    shutil.copyfile(ZIP_POST + '.zip', os.path.join(circle_artifacts, ZIP_POST + '.zip'))
    shutil.copyfile(ZIP_TEST + '.zip', os.path.join(circle_artifacts, ZIP_TEST + '.zip'))
    shutil.copyfile("./Tests/id_set.json", os.path.join(circle_artifacts, "id_set.json"))

    shutil.copyfile('release-notes.md', os.path.join(circle_artifacts, 'release-notes.md'))

    print(f'finished create content artifact at {circle_artifacts}')


def test_version_compare(version_num):
    versions = ['3.5', '2.0', '2.1', '4.7', '1.1.1', '1.5', '3.10.0',
                '2.7.1', '3', '3.4.9', '3.5.1', '3.6', '4.0.0', '5.0.1']

    lower = []
    greater = []
    for ver in versions:
        if is_ge_version(version_num, ver):
            greater.append(ver)
        else:
            lower.append(ver)

    print(f'lower versions: {lower}')
    print(f'greater versions: {greater}')


if __name__ == '__main__':
    main(sys.argv[1])
