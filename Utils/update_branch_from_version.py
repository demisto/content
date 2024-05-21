import subprocess
import argparse
import os
import click
import ujson
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import FoldedScalarString
from pkg_resources import parse_version
import shutil

ryaml = YAML()
ryaml.preserve_quotes = True  # type: ignore[assignment]

# make sure long lines will not break (relevant for code section)
ryaml.width = 50000   # type: ignore[assignment]

DOCKERIMAGE_45_TOP_VERSION = '4.5.9'

JSON_FOLDERS = ['IncidentFields', 'IncidentTypes', 'IndicatorFields', 'Layouts', 'Classifiers',
                'Connections', 'Dashboards', 'IndicatorTypes', 'Reports', 'Widgets']

PLAYBOOK_FOLDERS = ['Playbooks', 'TestPlaybooks']

SCRIPT_FOLDERS = ['Scripts', 'Integrations']

ALL_NON_TEST_DIRS = JSON_FOLDERS.copy() + SCRIPT_FOLDERS.copy() + ['Playbooks']


def should_keep_yml_file(yml_content, new_from_version):
    # if the file's toversion is lower than the new from version we should delete it
    if parse_version(yml_content.get('toversion', '99.99.99')) < parse_version(new_from_version):
        return False

    return True


def should_keep_json_file(json_content, new_from_version):
    # if the file's toVersion is lower than the new from version we should delete it
    if parse_version(json_content.get('toVersion', '99.99.99')) < parse_version(new_from_version):
        return False

    return True


def delete_playbook(file_path):
    os.remove(file_path)
    print(f" - Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    readme_file = os.path.join(os.path.splitext(file_path)[0] + '_README.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)

    if os.path.isfile(readme_file):
        os.remove(readme_file)


def delete_script_or_integration(path):
    if os.path.isfile(path):
        os.remove(path)
        changelog_file = os.path.splitext(path)[0] + '_CHANGELOG.md'
        readme_file = os.path.join(os.path.splitext(path)[0] + '_README.md')
        if os.path.isfile(changelog_file):
            os.remove(changelog_file)
        if os.path.isfile(readme_file):
            os.remove(readme_file)

    else:
        shutil.rmtree(path)
    print(f" - Deleting {path}")


def delete_json(file_path):
    os.remove(file_path)
    print(f" - Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)


def rewrite_json(file_path, json_content, new_from_version):
    # if there is no fromVersion in json or the fromVersion is lower than the new from version then update
    if ('fromVersion' in json_content and parse_version(json_content.get('fromVersion')) < parse_version(new_from_version)) \
            or ('fromVersion' not in json_content):
        json_content['fromVersion'] = new_from_version

        with open(file_path, 'w') as f:
            ujson.dump(json_content, f, indent=4, encode_html_chars=True, escape_forward_slashes=False,
                       ensure_ascii=False)

            print(f" - Updating {file_path}")


def rewrite_yml(file_path, yml_content, new_from_version):
    # if there is no fromVersion in json or the fromversion is lower than the new from version then update
    if ('fromversion' in yml_content and parse_version(yml_content.get('fromversion')) < parse_version(new_from_version)) \
            or ('fromversion' not in yml_content):
        yml_content['fromversion'] = new_from_version

        check_dockerimage45(yml_content, new_from_version)

        if 'script' in yml_content:
            if isinstance(yml_content.get('script'), str):
                if yml_content.get('script') not in ('-', ''):
                    yml_content['script'] = FoldedScalarString(yml_content.get('script'))

            elif yml_content.get('script').get('script') not in ('-', ''):
                yml_content['script']['script'] = FoldedScalarString(yml_content.get('script').get('script'))

        with open(file_path, mode='w', encoding='utf-8') as f:
            ryaml.dump(yml_content, f)
            print(f" - Updating {file_path}")


def check_dockerimage45(yml_content, new_from_version):
    # check in scripts
    if 'dockerimage45' in yml_content:
        if parse_version(new_from_version) > parse_version(DOCKERIMAGE_45_TOP_VERSION):
            del yml_content['dockerimage45']

    # check in integrations
    elif 'dockerimage45' in yml_content.get('script', {}):
        if parse_version(new_from_version) > parse_version(DOCKERIMAGE_45_TOP_VERSION):
            del yml_content['script']['dockerimage45']


def edit_json_content_entity_directory(new_from_version, dir_path):
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if os.path.isfile(file_path) and file_name.endswith('.json') and \
                file_path != "Packs/NonSupported/IndicatorTypes/reputations.json":

            with open(file_path, 'r') as f:
                json_content = ujson.load(f)

            if should_keep_json_file(json_content, new_from_version):
                rewrite_json(file_path, json_content, new_from_version)

            else:
                delete_json(file_path)


def edit_scripts_or_integrations_directory(new_from_version, dir_path):
    for script_name in os.listdir(dir_path):
        package_path = os.path.join(dir_path, script_name)
        if package_path.endswith('.md'):
            continue

        if os.path.isfile(package_path):
            yml_file_path = package_path

        else:
            yml_file_path = os.path.join(package_path, script_name + '.yml')

        # prevent going to pipfiles and non yml content
        if yml_file_path.endswith('.yml'):
            with open(yml_file_path, 'r') as yml_file:
                yml_content = ryaml.load(yml_file)

            if should_keep_yml_file(yml_content, new_from_version):
                rewrite_yml(yml_file_path, yml_content, new_from_version)

            else:
                delete_script_or_integration(package_path)


def edit_playbooks_directory(new_from_version, dir_path):
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if file_path.endswith('md'):
            continue

        if os.path.isfile(file_path):
            if file_path.endswith('.yml'):
                with open(file_path, 'r') as yml_file:
                    yml_content = ryaml.load(yml_file)

                if should_keep_yml_file(yml_content, new_from_version):
                    rewrite_yml(file_path, yml_content, new_from_version)

                else:
                    delete_playbook(file_path)

        else:
            # in some cases test-playbooks are located in a directory within the TestPlaybooks directory.
            # this part handles these files.
            inner_dir_path = file_path
            for inner_file_name in os.listdir(inner_dir_path):
                file_path = os.path.join(inner_dir_path, inner_file_name)
                if file_path.endswith('.yml'):
                    with open(file_path, 'r') as yml_file:
                        yml_content = ryaml.load(yml_file)

                    if should_keep_yml_file(yml_content, new_from_version):
                        rewrite_yml(file_path, yml_content, new_from_version)

                    else:
                        delete_playbook(file_path)


def check_clear_pack(pack_path):
    dirs_in_pack = os.listdir(pack_path)
    check = [True for entity in ALL_NON_TEST_DIRS if entity in dirs_in_pack]
    if len(check) == 0:
        click.secho(f"Deleting empty pack {pack_path}\n")
        shutil.rmtree(pack_path)


def edit_pack(new_from_version, pack_name):
    pack_path = os.path.join('Packs', pack_name)
    click.secho(f"Starting process for {pack_path}:")
    for content_dir in os.listdir(pack_path):
        dir_path = os.path.join(pack_path, content_dir)
        if content_dir in PLAYBOOK_FOLDERS:
            edit_playbooks_directory(new_from_version, dir_path)

        elif content_dir in SCRIPT_FOLDERS:
            edit_scripts_or_integrations_directory(new_from_version, dir_path)

        elif content_dir in JSON_FOLDERS:
            edit_json_content_entity_directory(new_from_version, dir_path)

    # clearing empty pack folders
    click.secho("Checking for empty dirs")
    found_dirs = subprocess.check_output(["find", pack_path, "-type", "d", "-empty"])
    if found_dirs:
        click.secho("Found empty dirs: {}".format(found_dirs.decode('utf-8').split('\n')))
        subprocess.call(["find", pack_path, "-type", "d", "-empty", "-delete"])
        check_clear_pack(pack_path)

    click.secho(f"Finished process for {pack_path}\n")


def edit_all_packs(new_from_version):
    for pack_name in os.listdir('Packs'):
        edit_pack(new_from_version, pack_name)


parser = argparse.ArgumentParser("Alter the branch to assign a new fromVersion to all relevant files.")
parser.add_argument('-v', '--new-from-version', help='The new from version to assign.', required=True)


def main():
    new_from_version = parser.parse_args().new_from_version
    if new_from_version.count('.') == 1:
        new_from_version = new_from_version + ".0"

    click.secho("Starting Branch Editing")
    edit_all_packs(new_from_version)

    click.secho("Finished updating branch", fg="green")


if __name__ == "__main__":
    main()
