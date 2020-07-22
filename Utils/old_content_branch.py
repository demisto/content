import subprocess
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
                click.secho("{} has a structure issue of file type{}. Error was: {}".format(file_path, type_of_file,
                                                                                            str(e)), fg="red")
                return {}
    if type(data_dictionary) is dict:
        return data_dictionary
    return {}


def get_yaml(file_path):
    return get_file(yaml.safe_load, file_path, ('yml', 'yaml'))


def get_json(file_path):
    return get_file(json.load, file_path, 'json')


def should_keep_yml_file(yml_content, new_to_version):
    if parse_version(yml_content.get('toversion', '99.99.99')) < parse_version(new_to_version) or \
            parse_version(yml_content.get('fromversion', '0.0.0')) > parse_version(new_to_version):
        return False

    return True


def should_keep_json_file(json_content, new_to_version):
    if parse_version(json_content.get('toVersion', '99.99.99')) < parse_version(new_to_version) or \
            parse_version(json_content.get('fromVersion', '0.0.0')) > parse_version(new_to_version):
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
        if os.path.isfile(changelog_file):
            os.remove(changelog_file)

    else:
        subprocess.call(["rm", "-rf", path])
    print(f" - Deleting {path}")


def delete_json(file_path):
    os.remove(file_path)
    print(f" - Deleting {file_path}")

    changelog_file = os.path.join(os.path.splitext(file_path)[0] + '_CHANGELOG.md')
    if os.path.isfile(changelog_file):
        os.remove(changelog_file)


def rewrite_json(file_path, json_content, new_to_version):
    json_content['toVersion'] = new_to_version

    with open(file_path, 'w') as f:
        json.dump(json_content, f, indent=4)
        print(f" - Updating {file_path}")


def rewrite_yml(file_path, yml_content, new_to_version):
    yml_content['toversion'] = new_to_version

    with open(file_path, 'w') as f:
        yaml.dump(yml_content, f)
        print(f" - Updating {file_path}")


def edit_json_content_entity_directory(new_to_version, dir_path):
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if os.path.isfile(file_path) and file_name.endswith('.json'):
            json_content = get_json(file_path)
            if should_keep_json_file(json_content, new_to_version):
                rewrite_json(file_path, json_content, new_to_version)

            else:
                delete_json(file_path)


def edit_scripts_or_integrations_directory(new_to_version, dir_path):
    for script_name in os.listdir(dir_path):
        package_path = os.path.join(dir_path, script_name)
        if package_path.endswith('.md'):
            continue

        if os.path.isfile(package_path):
            yml_file_path = package_path

        else:
            yml_file_path = os.path.join(package_path, script_name + '.yml')

        yml_content = get_yaml(yml_file_path)
        if should_keep_yml_file(yml_content, new_to_version):
            rewrite_yml(yml_file_path, yml_content, new_to_version)

        else:
            delete_script_or_integration(package_path)


def edit_playbooks_directory(new_to_version, dir_path):
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if file_path.endswith('md'):
            continue

        if os.path.isfile(file_path):
            if file_path.endswith('.yml'):
                yml_content = get_yaml(file_path)
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
                    yml_content = get_yaml(file_path)
                    if should_keep_yml_file(yml_content, new_to_version):
                        rewrite_yml(file_path, yml_content, new_to_version)

                    else:
                        delete_playbook(file_path)


def edit_pack(new_to_version, pack_name):
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


def edit_all_packs(new_to_version):
    for pack_name in os.listdir('Packs'):
        edit_pack(new_to_version, pack_name)


parser = argparse.ArgumentParser("Alter the branch to assign a new toVersion to all relevant files.")
parser.add_argument('-v', '--new-to-version', help='The new to version to assign.', required=True)


def main():
    new_to_version = parser.parse_args().new_to_version
    if new_to_version.count('.') == 1:
        new_to_version = new_to_version + ".9"

    click.secho("Starting Branch Editing")
    edit_all_packs(new_to_version)

    click.secho("Deleting empty directories\n")
    subprocess.call(["find", "Packs", "-type", "d", "-empty", "-delete"])

    click.secho("Finished creating branch", fg="green")


if __name__ == "__main__":
    main()
