import shutil
import sys
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


def handle_yml_file(file_path, yml_old_version):
    yml_content = get_yaml(file_path)
    if 'toversion' in yml_content:
        if parse_version(str(yml_content['toversion'])) < parse_version(yml_old_version):
            return False

    if 'fromversion' in yml_content:
        if parse_version(str(yml_content['fromversion'])) > parse_version(yml_old_version):
            return False

    yml_content['toversion'] = yml_old_version
    with open(file_path, 'w') as f:
        yaml.dump(yml_content, f)
        print(f" - Updating {file_path}")

    return True

def handle_json_file(file_path, old_version):
    json_content = get_json(file_path)
    if 'toVersion' in json_content:
        if parse_version(str(json_content.get('toVersion'))) < parse_version(old_version):
            return False

    if 'fromVersion' in json_content:
        if parse_version(str(json_content.get('fromVersion'))) > parse_version(old_version):
            return False

    json_content['toVersion'] = old_version
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


def main():
    arguments = sys.argv
    old_version = arguments[1]
    if old_version.count('.') == 1:
        old_version = old_version + ".9"

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
                            if not handle_yml_file(file_path, old_version):
                                delete_playbook(file_path)

                    else:
                        inner_dir_path = file_path
                        for inner_file_name in os.listdir(inner_dir_path):
                            file_path = os.path.join(inner_dir_path, inner_file_name)
                            if file_path.endswith('.yml'):
                                if not handle_yml_file(file_path, old_version):
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
                    if not handle_yml_file(yml_file_path, old_version):
                        delete_script_or_integration(path)

            elif content_dir in ['IncidentFields', 'IncidentTypes', 'IndicatorFields', 'Layouts', 'Classifiers',
                                 'Connections', 'Dashboards', 'IndicatorTypes', 'Reports', 'Widgets']:
                for file_name in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, file_name)
                    if os.path.isfile(file_path) and file_name.endswith('.json'):
                        if not handle_json_file(file_path, old_version):
                            delete_json(file_path)

        click.secho(f"Finished process for {pack_path}\n")

    click.secho("Deleting empty directories\n")
    os.system("find Packs -type d -empty -delete")

    click.secho("Finished creating branch", fg="green")


main()
