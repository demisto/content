import os
import sys
import yaml
import glob
import shutil

# original commands:
# - mkdir bundle
# - cd Tools/ && for i in */; do zip -jr "../bundle/tools-${i%/}.zip" "$i"; done
# - cp Integrations/* bundle/
# - cp Misc/* bundle/
# - cp Playbooks/* bundle/
# - cp Reports/* bundle/
# - cp Dashboards/* bundle/
# - cp Widgets/* bundle/
# - cp content-descriptor.json bundle/
# - cp $(find Scripts -type f -print) bundle/

# - cd bundle/ && zip ../content.zip *
# - cp content.zip $CIRCLE_ARTIFACTS/content.zip
# - cp release-notes.txt $CIRCLE_ARTIFACTS/

CONTENT_DIRS = ['Integrations', 'Misc', 'Playbooks', 'Reports', 'Dashboards', 'Widgets', 'Scripts']
# temp folder names
BUNDLE_PRE = 'bundle_l'
BUNDLE_POST = 'bundle_g'
# zip files names (the extension will be added later - shutil demands file name without extension)
ZIP_PRE = 'content'
ZIP_POST = 'content_future'

def is_ge_version(ver1, ver2):
    # fix the version to arrays of numbers
    if isinstance(ver1, str): ver1 = [int(i) for i in ver1.split('.')]
    if isinstance(ver2, str): ver2 = [int(i) for i in ver2.split('.')]

    for v1, v2 in zip(ver1, ver2):
        if v1 > v2:
            return False

    # most significant values are equal
    return len(ver1) <= len(ver2)


def add_tools_to_bundle(bundle):
    for d in glob.glob(os.path.join('Tools', '*')):
        print d
        shutil.make_archive(os.path.join(bundle, 'tools-%s' % (os.path.basename(d), )), 'zip', d)


def copy_dir_yml(dir_name, version_num, bundle_pre, bundle_post):
    scan_files = glob.glob(os.path.join(dir_name, '*.yml'))
    post_files = 0
    for path in scan_files:
        with open(path, 'r') as f:
            yml_info = yaml.safe_load(f)

        ver = yml_info.get('fromversion', '0')
        if is_ge_version(version_num, ver):
            print 'marked as post: %s (%s)' % (ver, path, )
            post_files += 1
            shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))
        else:
            print 'marked as pre: %s (%s)' % (ver, path, )
        # add the file to both bundles
        shutil.copyfile(path, os.path.join(bundle_pre, os.path.basename(path)))

    print post_files

def copy_dir_json(dir_name, version_num, bundle_pre, bundle_post):
    # handle *.json files
    scan_files = glob.glob(os.path.join(dir_name, '*.json'))
    for path in scan_files:
        shutil.copyfile(path, os.path.join(bundle_post, os.path.basename(path)))
        shutil.copyfile(path, os.path.join(bundle_pre, os.path.basename(path)))


def copy_dir_files(*args):
    # handle *.json files
    copy_dir_json(*args)
    # handle *.yml files
    copy_dir_yml(*args)


def main(version_num, circle_artifacts):
    for b in [BUNDLE_PRE, BUNDLE_POST]:
        os.mkdir(b)
        add_tools_to_bundle(b)

    for d in CONTENT_DIRS:
        print d
        copy_dir_files(d, version_num, BUNDLE_PRE, BUNDLE_POST)

    for b in [BUNDLE_PRE, BUNDLE_POST]:
        shutil.copyfile('content-descriptor.json', os.path.join(b, 'content-descriptor.json'))

    shutil.make_archive('content_post', 'zip', BUNDLE_POST)
    shutil.make_archive('content_pre', 'zip', BUNDLE_PRE)
    shutil.copyfile(ZIP_PRE + '.zip', os.path.join(circle_artifacts, ZIP_PRE + '.zip'))
    shutil.copyfile(ZIP_POST + '.zip', os.path.join(circle_artifacts, ZIP_POST + '.zip'))
    shutil.copyfile('release-notes.txt', os.path.join(circle_artifacts, 'release-notes.txt'))


def test_version_compare(version_num):
    V = ['3.5', '2.0', '2.1', '4.7', '1.1.1', '1.5', '3.10.0', '2.7.1', '3', '3.4.9', '3.5.1']

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