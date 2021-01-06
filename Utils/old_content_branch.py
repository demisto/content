import subprocess
import argparse
import os
from typing import Dict

import click
import ujson
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import FoldedScalarString
from pkg_resources import parse_version
import shutil

ryaml = YAML()
ryaml.preserve_quotes = True  # type: ignore
# make sure long lines will not break (relevant for code section)
ryaml.width = 50000  # type: ignore

NON_CIRCLE_TEST_PLAYBOOKS_DIRECTORY = 'TestPlaybooks'
DEPRECATED_NON_CIRCLE_TESTS_DIRECTORY = os.path.join('TestPlaybooks', 'NonCircleTests', 'Deprecated')


def should_keep_yml_file(yml_content: Dict, new_to_version: str) -> bool:
    """Check if yml file should stay in the feature branch"""
    if parse_version(yml_content.get('toversion', '99.99.99')) < parse_version(new_to_version) or \
            parse_version(yml_content.get('fromversion', '0.0.0')) >= parse_version(new_to_version):
        return False

    return True


def should_keep_json_file(json_content: Dict, new_to_version: str) -> bool:
    """Check if json file should stay in the feature branch"""
    if parse_version(json_content.get('toVersion', '99.99.99')) < parse_version(new_to_version) or \
            parse_version(json_content.get('fromVersion', '0.0.0')) >= parse_version(new_to_version):
        return False

    return True


def delete_playbook(file_path: str):
    """Delete Playbook from the branch along with any existing CHANGELOG and README files."""
    os.remove(file_path)
    print(f" - Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    readme_file = os.path.join(os.path.splitext(file_path)[0] + '_README.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)

    if os.path.isfile(readme_file):
        os.remove(readme_file)


def delete_script_or_integration(path: str):
    """Delete script or integration from the branch along with any existing CHANGELOG and README,
    also removes the package"""
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


def delete_json(file_path: str):
    """Delete json content entity from the branch along with CHANGELOG if exists"""
    os.remove(file_path)
    print(f" - Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)


def rewrite_json(file_path: str, json_content: Dict, new_to_version: str):
    """Updating json file to new toVersion"""
    json_content['toVersion'] = new_to_version

    with open(file_path, 'w') as f:
        ujson.dump(json_content, f, indent=4, encode_html_chars=True, escape_forward_slashes=False,
                   ensure_ascii=False)

        print(f" - Updating {file_path}")


def rewrite_yml(file_path: str, yml_content: Dict, new_to_version: str):
    """Updating yml file to new toversion"""
    yml_content['toversion'] = new_to_version

    check_dockerimage45(yml_content, new_to_version)

    if 'script' in yml_content:
        if isinstance(yml_content.get('script'), str):
            if yml_content.get('script') not in ('-', ''):
                yml_content['script'] = FoldedScalarString(yml_content.get('script', ''))

        elif yml_content.get('script', {}).get('script', '') not in ('-', ''):
            yml_content['script']['script'] = FoldedScalarString(yml_content.get('script', {}).get('script', ''))

    # resetting the tests associated with each yml
    yml_content['tests'] = ['No test']

    with open(file_path, mode='w', encoding='utf-8') as f:
        ryaml.dump(yml_content, f)
        print(f" - Updating {file_path}")


def check_dockerimage45(yml_content: Dict, new_to_version: str):
    """Changing dockerimage to fit the new toversion"""
    # check in scripts
    if 'dockerimage45' in yml_content:
        if parse_version(new_to_version) <= parse_version('4.5.9'):
            yml_content['dockerimage'] = yml_content['dockerimage45']
        del yml_content['dockerimage45']

    # check in integrations
    elif 'dockerimage45' in yml_content.get('script', {}):
        if parse_version(new_to_version) <= parse_version('4.5.9'):
            yml_content['script']['dockerimage'] = yml_content['script']['dockerimage45']
        del yml_content['script']['dockerimage45']


def edit_json_content_entity_directory(new_to_version: str, dir_path: str):
    """Edit json content entity directory to fit the branch"""
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if os.path.isfile(file_path) and file_name.endswith('.json') and \
                file_path != "Packs/NonSupported/IndicatorTypes/reputations.json":

            with open(file_path, 'r') as f:
                json_content = ujson.load(f)

            if should_keep_json_file(json_content, new_to_version):
                rewrite_json(file_path, json_content, new_to_version)

            else:
                delete_json(file_path)


def edit_scripts_or_integrations_directory(new_to_version: str, dir_path: str):
    """Edit Scripts or Integrations directory to fit the branch"""
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

            if should_keep_yml_file(yml_content, new_to_version):
                rewrite_yml(yml_file_path, yml_content, new_to_version)

            else:
                delete_script_or_integration(package_path)


def edit_playbooks_directory(new_to_version: str, dir_path: str):
    """Edit Playbooks directory to fit the branch"""
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if file_path.endswith('md'):
            continue

        if os.path.isfile(file_path):
            if file_path.endswith('.yml'):
                with open(file_path, 'r') as yml_file:
                    yml_content = ryaml.load(yml_file)

                if should_keep_yml_file(yml_content, new_to_version):
                    rewrite_yml(file_path, yml_content, new_to_version)

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

                    if should_keep_yml_file(yml_content, new_to_version):
                        rewrite_yml(file_path, yml_content, new_to_version)

                    else:
                        delete_playbook(file_path)


def edit_pack(new_to_version: str, pack_name: str):
    """Edit pack to fit the branch"""
    pack_path = os.path.join('Packs', pack_name)
    click.secho(f"Starting process for {pack_path}:")
    for content_dir in os.listdir(pack_path):
        dir_path = os.path.join(pack_path, content_dir)
        if content_dir in ['Playbooks', 'TestPlaybooks']:
            edit_playbooks_directory(new_to_version, dir_path)

        elif content_dir in ['Scripts', 'Integrations']:
            edit_scripts_or_integrations_directory(new_to_version, dir_path)

        elif content_dir in ['IncidentFields', 'IncidentTypes', 'IndicatorFields', 'Layouts', 'Classifiers',
                             'Connections', 'Dashboards', 'IndicatorTypes', 'Reports', 'Widgets']:
            edit_json_content_entity_directory(new_to_version, dir_path)

    click.secho(f"Finished process for {pack_path}\n")


def edit_all_packs(new_to_version: str):
    """Edit all packs to fit the branch"""
    for pack_name in os.listdir('Packs'):
        edit_pack(new_to_version, pack_name)


parser = argparse.ArgumentParser("Alter the branch to assign a new toVersion to all relevant files.")
parser.add_argument('-v', '--new-to-version', help='The new to version to assign.', required=True)


def edit_reputations_json(new_to_version: str):
    """Edit reputations.json file to fit the branch"""
    print("Updating reputations.json\n")
    rep_json_path = "Packs/NonSupported/IndicatorTypes/reputations.json"
    with open(rep_json_path, 'r') as f:
        rep_content = ujson.load(f)

    for reputation in rep_content.get('reputations', []):
        if parse_version(reputation.get('toVersion', "99.99.99")) > parse_version(new_to_version):
            reputation['toVersion'] = new_to_version

    with open(rep_json_path, 'w') as f:
        ujson.dump(rep_content, f, indent=4, encode_html_chars=True, escape_forward_slashes=False,
                   ensure_ascii=False)


def edit_non_circle_tests(new_to_version: str):
    """Edit the non circle test playbooks directory"""
    edit_playbooks_directory(new_to_version, NON_CIRCLE_TEST_PLAYBOOKS_DIRECTORY)
    edit_playbooks_directory(new_to_version, DEPRECATED_NON_CIRCLE_TESTS_DIRECTORY)


def main():
    new_to_version = parser.parse_args().new_to_version
    if new_to_version.count('.') == 1:
        new_to_version = new_to_version + ".9"

    click.secho("Starting Branch Editing")
    edit_all_packs(new_to_version)

    edit_reputations_json(new_to_version)
    edit_non_circle_tests(new_to_version)
    click.secho("Deleting empty directories\n")
    subprocess.call(["find", "Packs", "-type", "d", "-empty", "-delete"])

    click.secho("Finished creating branch", fg="green")


if __name__ == "__main__":
    main()
