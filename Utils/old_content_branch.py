import shutil
import sys
import argparse
import os
import click
import yaml
import io
import json
from pkg_resources import parse_version


def get_file(method, file_path, type_of_file):
    data_dictionary = None
    with open(os.path.expanduser(file_path), mode="r", encoding="utf8") as f:
        if file_path.endswith(type_of_file):
            read_file = f.read()
            replaced = read_file.replace("simple: =", "simple: '='")
            # revert str to stream for loader
            stream = io.StringIO(replaced)
            try:
                data_dictionary = method(stream)
            except Exception as e:
                click.secho("{} has a structure issue of file type{}. Error was: {}".format(file_path, type_of_file, str(e)), fg="red")
                return {}
    if type(data_dictionary) is dict:
        return data_dictionary
    return {}


def get_yaml(file_path):
    return get_file(yaml.safe_load, file_path, ('yml', 'yaml'))


def get_json(file_path):
    return get_file(json.load, file_path, 'json')


def handle_yml_file(file_path, new_to_version):
    yml_content = get_yaml(file_path)
    if parse_version(yml_content.get('toversion', '99.99.99')) < parse_version(new_to_version) or \
            parse_version(yml_content.get('fromversion', '0.0.0')) > parse_version(new_to_version):
        return False

    yml_content['toversion'] = new_to_version
    with open(file_path, 'w') as f:
        yaml.dump(yml_content, f)
        print(f" - Updating {file_path}")

    return True


def handle_json_file(file_path, new_to_version):
    json_content = get_json(file_path)
    if parse_version(json_content.get('toVersion', '99.99.99')) < parse_version(new_to_version) or \
            parse_version(json_content.get('fromVersion', '0.0.0')) > parse_version(new_to_version):
        return False

    json_content['toVersion'] = new_to_version
    with open(file_path, 'w') as f:
        json.dump(json_content, f, indent=4)
        print(f" - Updating {file_path}")

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
        if os.path.isfile(changelog_file):
            os.remove(changelog_file)

    else:
        os.system(f"rm -rf {path}")
    print(f" - Deleting {path}")


def delete_json(file_path):
    os.remove(file_path)
    print(f" - Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)


parser = argparse.ArgumentParser("Alter the branch to assign a new toVersion to all relevant files.")
parser.add_argument('new_to_version', help='The new to version to assign.', required=True)


def main():
    new_to_version = parser.parse_args()['new_to_version']
    if new_to_version.count('.') == 1:
        new_to_version = new_to_version + ".9"

    click.secho("Starting Branch Editing")
    for pack_name in os.listdir('Packs'):
        pack_path = os.path.join('Packs', pack_name)
        click.secho(f"Starting process for {pack_path}:")
        for content_dir in os.listdir(pack_path):
            dir_path = os.path.join(pack_path, content_dir)
            if content_dir in ['Playbooks', 'TestPlaybooks']:
                for file_name in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, file_name)
                    if file_path.endswith('md'):
                        continue

                    if os.path.isfile(file_path):
                        if file_path.endswith('.yml'):
                            if not handle_yml_file(file_path, new_to_version):
                                delete_playbook(file_path)

                    else:
                        # in some cases test-playbooks are located in a directory within the TestPlaybooks directory.
                        # this part handles these files.
                        inner_dir_path = file_path
                        for inner_file_name in os.listdir(inner_dir_path):
                            file_path = os.path.join(inner_dir_path, inner_file_name)
                            if file_path.endswith('.yml'):
                                if not handle_yml_file(file_path, new_to_version):
                                    delete_playbook(file_path)

            if content_dir in ['Scripts', 'Integrations']:
                for script_name in os.listdir(dir_path):
                    path = os.path.join(dir_path, script_name)
                    if path.endswith('.md'):
                        continue

                    if os.path.isfile(path):
                        yml_file_path = path

                    else:
                        yml_file_path = os.path.join(path, script_name + '.yml')
                    if not handle_yml_file(yml_file_path, new_to_version):
                        delete_script_or_integration(path)

            elif content_dir in ['IncidentFields', 'IncidentTypes', 'IndicatorFields', 'Layouts', 'Classifiers',
                                 'Connections', 'Dashboards', 'IndicatorTypes', 'Reports', 'Widgets']:
                for file_name in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, file_name)
                    if os.path.isfile(file_path) and file_name.endswith('.json'):
                        if not handle_json_file(file_path, new_to_version):
                            delete_json(file_path)

        click.secho(f"Finished process for {pack_path}\n")

    click.secho("Deleting empty directories\n")
    os.system("find Packs -type d -empty -delete")

    click.secho("Finished creating branch", fg="green")


main()
