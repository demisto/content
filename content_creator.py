import os
import sys
import yaml
import json
import glob
import shutil
import zipfile
import io

from package_creator import DIR_TO_PREFIX, merge_script_package_to_yml, write_yaml_with_docker

CONTENT_DIRS = ['Integrations', 'Misc', 'Playbooks', 'Reports', 'Dashboards', 'Widgets', 'Scripts', 'IncidentTypes',
                'Classifiers', 'Layouts', 'IncidentFields', 'IndicatorFields', 'Connections', 'Beta_Integrations']

TEST_DIR = 'TestPlaybooks'

# temp folder names
BUNDLE_POST = 'bundle_post'
BUNDLE_TEST = 'bundle_test'
# zip files names (the extension will be added later - shutil demands file name without extension)
ZIP_POST = 'content_new'
ZIP_TEST = 'content_test'


def is_ge_version(ver1, ver2):
    # fix the version to arrays of numbers
    ver1 = [int(i) for i in str(ver1).split('.')]
    ver2 = [int(i) for i in str(ver2).split('.')]

    for v1, v2 in zip(ver1, ver2):
        if v1 > v2:
            return False
        elif v2 > v1:
            return True

    # most significant values are equal
    return len(ver1) <= len(ver2)


def add_tools_to_bundle(bundle):
    for d in glob.glob(os.path.join('Tools', '*')):
        zipf = zipfile.ZipFile(os.path.join(bundle, 'tools-%s.zip' % (os.path.basename(d), )), 'w',
                               zipfile.ZIP_DEFLATED)
        zipf.comment = '{ "system": true }'
        for root, _, files in os.walk(d):
            for file in files:
                zipf.write(os.path.join(root, file), file)
        zipf.close()


# modify incident fields file to contain only `incidentFields` field (array)
# from { "incidentFields": [...]} to [...]
def convert_incident_fields_to_array():
    scan_files = glob.glob(os.path.join('IncidentFields', '*.json'))
    for path in scan_files:
        with open(path, 'r+') as f:
            data = json.load(f)
            incident_fields = data.get('incidentFields')
            if incident_fields is not None:
                f.seek(0)
                json.dump(incident_fields, f, indent=2)
                f.truncate()


def copy_yaml_post(path, out_path, yml_info):
    dirname = os.path.dirname(path)
    if dirname in DIR_TO_PREFIX.keys() and not os.path.basename(path).startswith('playbook-'):
        script_obj = yml_info
        if dirname != 'Scripts':
            script_obj = yml_info['script']
        with io.open(path, mode='r', encoding='utf-8') as f:
            yml_text = f.read()
        out_map = write_yaml_with_docker(out_path, yml_text, yml_info, script_obj)
        if len(out_map.keys()) > 1:
            print(" - yaml generated multiple files: {}".format(out_map.keys()))
        return
    # not a script or integration file. Simply copy
    shutil.copyfile(path, out_path)


def copy_dir_yml(dir_name, bundle_post):
    scan_files = glob.glob(os.path.join(dir_name, '*.yml'))
    post_files = 0
    for path in scan_files:
        with open(path, 'r') as f:
            yml_info = yaml.safe_load(f)

        ver = yml_info.get('fromversion', '0')        
        print ' - processing: %s (%s)' % (ver, path, )
        copy_yaml_post(path, os.path.join(bundle_post, os.path.basename(path)), yml_info)
        post_files += 1     
    print ' - total files: %d' % (post_files, )


def copy_dir_json(dir_name, bundle_post):
    # handle *.json files
    scan_files = glob.glob(os.path.join(dir_name, '*.json'))
    for path in scan_files:
        dpath = os.path.basename(path)
        # this part is a workaround because server doesn't support indicatorfield-*.json naming
        if dir_name == 'IndicatorFields':
            new_path = dpath.replace('incidentfield-', 'incidentfield-indicatorfield-')
            if os.path.isfile(new_path):
                raise NameError('Failed while trying to create {}. File already exists.'.format(new_path))
            dpath = new_path
        shutil.copyfile(path, os.path.join(bundle_post, dpath))        


def copy_dir_files(*args):
    # handle *.json files
    copy_dir_json(*args)
    # handle *.yml files
    copy_dir_yml(*args)


def copy_test_files(bundle_test):
    print 'copying test files to test bundle'
    scan_files = glob.glob(os.path.join(TEST_DIR, '*'))
    for path in scan_files:
        if os.path.isdir(path):
            NonCircleTests = glob.glob(os.path.join(path, '*'))
            for new_path in NonCircleTests:
                print "copying path %s" % (new_path,)
                shutil.copyfile(new_path, os.path.join(bundle_test, os.path.basename(new_path)))

        else:
            print "copying path %s" % (path,)
            shutil.copyfile(path, os.path.join(bundle_test, os.path.basename(path)))


def main(circle_artifacts):
    print 'starting create content artifact ...'

    print 'creating dir for bundles ...'
    for b in [BUNDLE_POST, BUNDLE_TEST]:
        os.mkdir(b)
    
    add_tools_to_bundle(BUNDLE_POST)

    convert_incident_fields_to_array()

    for d in DIR_TO_PREFIX.keys():
        scanned_packages = glob.glob(os.path.join(d, '*/'))
        for package in scanned_packages:
            merge_script_package_to_yml(package, d, BUNDLE_POST)

    for d in CONTENT_DIRS:
        print 'copying dir %s to bundles ...' % (d,)
        copy_dir_files(d, BUNDLE_POST)

    copy_test_files(BUNDLE_TEST)

    print 'copying content descriptor to bundles'
    for b in [BUNDLE_POST, BUNDLE_TEST]:
        shutil.copyfile('content-descriptor.json', os.path.join(b, 'content-descriptor.json'))

    print 'copying common server doc to bundles'
    shutil.copyfile('./Documentation/doc-CommonServer.json', os.path.join(BUNDLE_POST, 'doc-CommonServer.json'))

    print 'compressing bundles ...'
    shutil.make_archive(ZIP_POST, 'zip', BUNDLE_POST)
    shutil.make_archive(ZIP_TEST, 'zip', BUNDLE_TEST)
    shutil.copyfile(ZIP_POST + '.zip', os.path.join(circle_artifacts, ZIP_POST + '.zip'))
    shutil.copyfile(ZIP_TEST + '.zip', os.path.join(circle_artifacts, ZIP_TEST + '.zip'))
    shutil.copyfile("./Tests/id_set.json", os.path.join(circle_artifacts, "id_set.json"))

    shutil.copyfile('release-notes.md', os.path.join(circle_artifacts, 'release-notes.md'))

    print 'finished create content artifact at %s' % (circle_artifacts, )


def test_version_compare(version_num):
    V = ['3.5', '2.0', '2.1', '4.7', '1.1.1', '1.5', '3.10.0', '2.7.1', '3', '3.4.9', '3.5.1', '3.6', '4.0.0', '5.0.1']

    lower = []
    greater = []
    for v in V:
        if is_ge_version(version_num, v):
            greater.append(v)
        else:
            lower.append(v)

    print 'lower versions: %s' % (lower, )
    print 'greater versions: %s' % (greater, )


if __name__ == '__main__':
    main(*sys.argv[1:])
