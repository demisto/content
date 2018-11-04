import os
import sys
import yaml
import json
import glob
import shutil
import zipfile

CONTENT_DIRS = ['Integrations', 'Misc', 'Playbooks', 'Reports', 'Dashboards', 'Widgets', 'Scripts',
                'Classifiers', 'Layouts', 'IncidentFields', 'Connections']

TEST_DIR = 'TestPlaybooks'

# temp folder names
BUNDLE_PRE = 'bundle_pre'
BUNDLE_POST = 'bundle_post'
BUNDLE_TEST = 'bundle_test'
# zip files names (the extension will be added later - shutil demands file name without extension)
ZIP_PRE = 'content_yml'
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
        zipf = zipfile.ZipFile(os.path.join(bundle, 'tools-%s.zip' % (os.path.basename(d), )), 'w', zipfile.ZIP_DEFLATED)
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


def copy_dir_yml(dir_name, version_num, bundle_pre, bundle_post, bundle_test):
    scan_files = glob.glob(os.path.join(dir_name, '*.yml'))
    post_files = 0
    for path in scan_files:
        with open(path, 'r') as f:
            yml_info = yaml.safe_load(f)

        ver = yml_info.get('fromversion', '0')
        if ver == '' or is_ge_version(version_num, ver):
            print ' - marked as post: %s (%s)' % (ver, path, )
            shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))
            shutil.copyfile(path, os.path.join(bundle_test, os.path.basename(path)))
            post_files += 1
        else:
            # add the file to both bundles
            print ' - marked as pre: %s (%s)' % (ver, path, )
            shutil.copyfile(path, os.path.join(bundle_pre, os.path.basename(path)))
            shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))

    print ' - total post files: %d' % (post_files, )


def copy_dir_json(dir_name, version_num, bundle_pre, bundle_post, bundle_test):
    # handle *.json files
    scan_files = glob.glob(os.path.join(dir_name, '*.json'))
    for path in scan_files:
        shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))
        shutil.copyfile(path, os.path.join(bundle_pre, os.path.basename(path)))
        shutil.copyfile(path, os.path.join(bundle_test, os.path.basename(path)))


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

    # version that separate post bundle from pre bundle
    # e.i. any yml with "fromversion" of <version_num> or more will be only on post bundle
    version_num = "3.5"

    print 'creating dir for bundles ...'
    for b in [BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST]:
        os.mkdir(b)
        add_tools_to_bundle(b)

    convert_incident_fields_to_array()

    for d in CONTENT_DIRS:
        print 'copying dir %s to bundles ...' % (d,)
        copy_dir_files(d, version_num, BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST)

    copy_test_files(BUNDLE_TEST)

    print 'copying content descriptor to bundles'
    for b in [BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST]:
        shutil.copyfile('content-descriptor.json', os.path.join(b, 'content-descriptor.json'))

    print 'copying common server doc to bundles'
    for b in [BUNDLE_PRE, BUNDLE_POST, BUNDLE_TEST]:
        shutil.copyfile('./Documentation/doc-CommonServer.json', os.path.join(b, 'doc-CommonServer.json'))

    print 'compressing bundles ...'
    shutil.make_archive(ZIP_POST, 'zip', BUNDLE_POST)
    shutil.make_archive(ZIP_PRE, 'zip', BUNDLE_PRE)
    shutil.make_archive(ZIP_TEST, 'zip', BUNDLE_TEST)
    shutil.copyfile(ZIP_PRE + '.zip', os.path.join(circle_artifacts, ZIP_PRE + '.zip'))
    shutil.copyfile(ZIP_POST + '.zip', os.path.join(circle_artifacts, ZIP_POST + '.zip'))
    shutil.copyfile(ZIP_TEST + '.zip', os.path.join(circle_artifacts, ZIP_TEST + '.zip'))

    shutil.copyfile('release-notes.txt', os.path.join(circle_artifacts, 'release-notes.txt'))

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
