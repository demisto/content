import abc
import datetime
import json
import sys
import yaml
import os
import requests
import argparse

from Tests.test_utils import print_error, print_warning, get_last_release_version, filter_packagify_changes, \
    run_command, server_version_compare, get_release_notes_file_path, get_latest_release_notes_text
from Tests.scripts.validate_files import FilesValidator

contentLibPath = "./"
limitedVersion = False


NEW_RN = "New"
MODIFIED_RN = "Improved"
IGNORE_RN = '-'

CONTENT_FILE_SUFFIXES = [
    ".yml",
    ".yaml",
    ".json"
]

LAYOUT_TYPE_TO_NAME = {
    "details": "Summary",
    "edit": "New/Edit",
    "close": "Close",
    "quickView": "Quick View",
}

INTEGRATIONS_DIR = "Integrations"
SCRIPTS_DIR = "Scripts"
PLAYBOOKS_DIR = "Playbooks"
REPORTS_DIR = "Reports"
DASHBOARDS_DIR = "Dashboards"
WIDGETS_DIR = "Widgets"
INCIDENT_FIELDS_DIR = "IncidentFields"
LAYOUTS_DIR = "Layouts"
CLASSIFIERS_DIR = "Classifiers"
REPUTATIONS_DIR = "Misc"

RELEASE_NOTES_ORDER = [INTEGRATIONS_DIR, SCRIPTS_DIR, PLAYBOOKS_DIR, REPORTS_DIR,
                       DASHBOARDS_DIR, WIDGETS_DIR, INCIDENT_FIELDS_DIR, LAYOUTS_DIR,
                       CLASSIFIERS_DIR, REPUTATIONS_DIR]


def add_dot(text):
    text = text.rstrip()
    if text.endswith('.'):
        return text
    return text + '.'


def release_notes_item(header, body):
    return '- __{}__\n{}\n'.format(header, add_dot(body))


class Content(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self.modified_store = []  # holds modified file paths
        self.added_store = []  # holds added file paths
        self.deleted_store = []  # holds deleted file paths
        self.show_secondary_header = True
        self.is_missing_release_notes = False

    def add(self, change_type, data):
        if change_type == "M":
            self.modified_store.append(data)
        elif change_type == "A":
            self.added_store.append(data)
        elif change_type == "D":
            self.deleted_store.append(data)
        else:
            print("Unknown change type " + change_type)

    @abc.abstractmethod
    def get_header(self):
        return

    def get_release_notes(self, file_path, data):
        """
        Return the release notes relevant to the added yml file.

        :param file_path: yml/json (or package yml)
        :param data: object data
        :return: raw release notes or None in case of an error.
        """
        rn_path = get_release_notes_file_path(file_path)

        return get_latest_release_notes_text(rn_path)

    @abc.abstractmethod
    def added_release_notes(self, file_path, data):
        """
        Return the release notes relevant to the added yml file.

        :param file_path: yml/json added (or package yml)
        :param data: object data
        :return: raw release notes or None in case of an error.
        """
        return self.get_release_notes(file_path, data)

    def modified_release_notes(self, file_path, data):
        """
        Return the release notes relevant to the modified yml/json file (or modified package yml).

        :param file_path: yml/json (or package yml)
        :param data: yml data
        :return: raw release notes or None in case of an error.
        """
        rn = self.get_release_notes(file_path, data)

        if rn and rn.strip() == IGNORE_RN:
            rn = ''

        return rn

    @abc.abstractmethod
    def load_data(self, data):
        return

    # create a release notes section for store (add or modified) - return None if found missing release notes
    def release_notes_section(self, store, title_prefix, current_server_version):
        res = ""
        if len(store) > 0:
            new_str = ""
            new_count = 0
            for path in store:
                with open(path, 'r') as f:
                    print ' - adding release notes ({}) for file - [{}]... '.format(path, title_prefix),
                    raw_content = f.read()
                    cnt = self.load_data(raw_content)

                    from_version = cnt.get("fromversion")
                    if from_version is not None and server_version_compare(current_server_version, from_version) < 0:
                        print("Skipped because of version differences")
                        continue

                    if title_prefix == NEW_RN:
                        ans = self.added_release_notes(path, cnt)
                    elif title_prefix == MODIFIED_RN:
                        ans = self.modified_release_notes(path, cnt)
                    else:
                        # should never get here
                        print_error('Error:\n Unknown release notes type {}'.format(title_prefix))
                        return None

                    if ans is None:
                        print_error("Error:\n[{}] is missing releaseNotes entry, Please add it under {}".format(
                            path, get_release_notes_file_path(path)))
                        self.is_missing_release_notes = True
                    elif ans:
                        new_count += 1
                        new_str += ans
                        print("Success")
                    else:
                        print("Skipped")

            if len(new_str) > 0:
                if self.show_secondary_header:
                    count_str = ""
                    if new_count > 1:
                        count_str = " " + str(new_count)

                    res = "\n#### %s %s %s\n" % (count_str, title_prefix, self.get_header())
                res += new_str

        return res

    def generate_release_notes(self, current_server_version):
        res = ""

        if len(self.modified_store) + len(self.deleted_store) + len(self.added_store) > 0:
            print("starting {} RN".format(self.get_header()))

            # Added files
            add_rn = self.release_notes_section(self.added_store, NEW_RN, current_server_version)

            # Modified files
            modified_rn = self.release_notes_section(self.modified_store, MODIFIED_RN, current_server_version)

            if add_rn is None or modified_rn is None:
                return None

            section_body = add_rn + modified_rn

            # Deleted files
            if len(self.deleted_store) > 0:
                section_body += "\n##### Removed {}\n".format(self.get_header())
                for name in self.deleted_store:
                    print(' - adding release notes (Removed) for - [{}]'.format(name)),
                    section_body += "- __" + name + "__\n"
                    print("Success")

            if len(section_body) > 0:
                res = "### {}\n".format(self.get_header())
                res += section_body

        return res


class ScriptContent(Content):
    def load_data(self, data):
        return yaml.safe_load(data)

    def get_header(self):
        return "Scripts"

    def added_release_notes(self, file_path, cnt):
        return release_notes_item(cnt["name"], cnt["comment"])

    def modified_release_notes(self, file_path, cnt):
        rn = super(ScriptContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return release_notes_item(cnt["name"], rn)
        else:
            # error or ignored rn
            return rn


class PlaybookContent(Content):
    def load_data(self, data):
        return yaml.safe_load(data)

    def get_header(self):
        return "Playbooks"

    def added_release_notes(self, file_path, cnt):
        return release_notes_item(cnt["name"], cnt['description'])

    def modified_release_notes(self, file_path, cnt):
        rn = super(PlaybookContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return release_notes_item(cnt["name"], rn)
        else:
            # error or ignored rn
            return rn


class ReportContent(Content):
    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Reports"

    def added_release_notes(self, file_path, cnt):
        return release_notes_item(cnt["name"], cnt["description"])

    def modified_release_notes(self, file_path, cnt):
        rn = super(ReportContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return release_notes_item(cnt["name"], rn)
        else:
            # error or ignored rn
            return rn


class DashboardContent(Content):
    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Dashboards"

    def added_release_notes(self, file_path, cnt):
        return release_notes_item(cnt["name"], cnt["description"])

    def modified_release_notes(self, file_path, cnt):
        rn = super(DashboardContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return release_notes_item(cnt["name"], rn)
        else:
            # error or ignored rn
            return rn


class WidgetContent(Content):
    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Widgets"

    def added_release_notes(self, file_path, cnt):
        return release_notes_item(cnt["name"], cnt["description"])

    def modified_release_notes(self, file_path, cnt):
        rn = super(WidgetContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return release_notes_item(cnt["name"], rn)
        else:
            # error or ignored rn
            return rn


class IncidentFieldContent(Content):

    def __init__(self):
        super(IncidentFieldContent, self).__init__()
        self.show_secondary_header = False

    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Incident Fields"

    def added_release_notes(self, file_path, cnt):
        rn = super(IncidentFieldContent, self).added_release_notes(file_path, cnt)

        if rn:
            return add_dot(rn) + "\n"
        else:
            # error
            return rn

    def modified_release_notes(self, file_path, cnt):
        rn = super(IncidentFieldContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return add_dot(rn) + "\n"
        else:
            # error or ignored rn
            return rn


class LayoutContent(Content):
    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Incident Layouts"

    def get_release_notes(self, file_path, cnt):
        rn = super(LayoutContent, self).get_release_notes(file_path, cnt)
        if not rn:
            return rn

        layout_kind = LAYOUT_TYPE_TO_NAME.get(cnt.get("kind", ""))
        if not layout_kind:
            print_error('Invalid layout kind {}'.format(cnt.get("kind", "")))
            return None

        layout_type = cnt.get("typeId")
        if not layout_type:
            print_error("Invalid layout kind {}".format(layout_type))
            return None

        return release_notes_item('{} - {}'.format(layout_type, layout_kind), rn)

    def added_release_notes(self, file_path, cnt):
        return self.get_release_notes(file_path, cnt)

    def modified_release_notes(self, file_path, cnt):
        rn = super(LayoutContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return self.get_release_notes(file_path, cnt)
        else:
            # error or ignored rn
            return rn


class ClassifierContent(Content):
    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Classification & Mapping"

    def get_release_notes(self, file_path, cnt):
        rn = super(ClassifierContent, self).get_release_notes(file_path, cnt)
        brand_name = cnt.get("brandName")
        if not brand_name:
            print_error('Invalid classifier brand name {}'.format(brand_name))
            return None

        if rn:
            return release_notes_item(brand_name, rn)
        else:
            return rn

    def added_release_notes(self, file_path, cnt):
        rn = super(ClassifierContent, self).added_release_notes(file_path, cnt)

        if rn:
            return self.get_release_notes(file_path, cnt)
        else:
            # error
            return rn

    def modified_release_notes(self, file_path, cnt):
        rn = super(ClassifierContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return self.get_release_notes(file_path, cnt)
        else:
            # error or ignored rn
            return rn


class ReputationContent(Content):
    def __init__(self):
        super(ReputationContent, self).__init__()
        self.show_secondary_header = False

    def load_data(self, data):
        return json.loads(data)

    def get_header(self):
        return "Reputations"

    def added_release_notes(self, file_path, cnt):
        # This should never happen
        return ""

    def modified_release_notes(self, file_path, cnt):
        rn = super(ReputationContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return add_dot(rn) + "\n"
        else:
            return rn


class IntegrationContent(Content):
    def load_data(self, data):
        return yaml.safe_load(data)

    def get_header(self):
        return "Integrations"

    def added_release_notes(self, file_path, cnt):
        return release_notes_item(cnt["display"], cnt["description"])

    def modified_release_notes(self, file_path, cnt):
        rn = super(IntegrationContent, self).modified_release_notes(file_path, cnt)

        if rn:
            return release_notes_item(cnt["display"], rn)
        else:
            return rn


release_note_generator = {
    INTEGRATIONS_DIR: IntegrationContent(),
    SCRIPTS_DIR: ScriptContent(),
    PLAYBOOKS_DIR: PlaybookContent(),
    REPORTS_DIR: ReportContent(),
    DASHBOARDS_DIR: DashboardContent(),
    WIDGETS_DIR: WidgetContent(),
    INCIDENT_FIELDS_DIR: IncidentFieldContent(),
    LAYOUTS_DIR: LayoutContent(),
    CLASSIFIERS_DIR: ClassifierContent(),
    REPUTATIONS_DIR: ReputationContent()
}


def parse_change_list(file_path):
    with open(file_path, 'r') as f:
        data = f.read()
        return data.split("\n")


def get_deleted_content(full_file_name, data):
    start_index = data.find(full_file_name)
    if start_index > 0:
        name_index = data.find("-name:", start_index)
        if name_index > 0:
            return data[name_index:].split("\n")[0][len("-name:"):].strip()
    return full_file_name


def handle_deleted_file(deleted_data, full_file_name):
    if "/" in full_file_name:
        file_type = full_file_name.split("/")[0]
        file_type_mapping = release_note_generator.get(file_type)
        deleted_content = get_deleted_content(full_file_name, deleted_data)
        if file_type_mapping is not None:
            file_type_mapping.add("D", deleted_content)


def create_file_release_notes(change_type, full_file_name, deleted_data):
    """
    Create release note for changed file.

    :param change_type: git change status (A, M, D, R*)
    :param full_file_name: path to file in repository
    :param deleted_data: all removed files content
    :return: None
    """
    if isinstance(full_file_name, tuple):
        old_file_path, full_file_name = full_file_name

    file_type = full_file_name.split("/")[0]
    base_name = os.path.basename(full_file_name)
    file_suffix = os.path.splitext(base_name)[-1]
    file_type_mapping = release_note_generator.get(file_type)

    if file_type_mapping is None or file_suffix not in CONTENT_FILE_SUFFIXES:
        print_warning("Unsupported file type: {}".format(full_file_name))
        return

    if change_type == "D":
        handle_deleted_file(deleted_data, full_file_name)
    elif change_type != "R100":  # only file name has changed (no actual data was modified
        if 'R' in change_type:
            # handle the same as modified
            change_type = 'M'

        file_type_mapping.add(change_type, contentLibPath + full_file_name)


def get_release_notes_draft(github_token, asset_id):
    """
    if possible, download current release draft from content repository in github.

    :param github_token: github token with push permission (in order to get the draft).
    :param asset_id: content build's asset id.
    :return: draft text (or empty string on error).
    """
    # Disable insecure warnings
    requests.packages.urllib3.disable_warnings()

    try:
        res = requests.get('https://api.github.com/repos/demisto/content/releases', verify=False,
                           headers={'Authorization': 'token {}'.format(github_token)})
    except requests.exceptions.ConnectionError as e:
        print_warning('unable to get release draft, reason:\n{}'.format(str(e)))
        return ''

    if res.status_code != 200:
        print_warning('unable to get release draft ({}), reason:\n{}'.format(res.status_code, res.text))
        return ''

    drafts = [release for release in res.json() if release.get('draft', False)]
    if drafts:
        if len(drafts) == 1:
            return drafts[0]['body'].replace("xxxxx", asset_id)
        else:
            print_warning('Too many drafts to choose from ({}), skipping update.'.format(len(drafts)))

    return ''


def create_content_descriptor(version, asset_id, res, github_token):
    # time format example 2017 - 06 - 11T15:25:57.0 + 00:00
    date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.0+00:00")
    release_notes = '## Demisto Content Release Notes for version {} ({})\n'.format(version, asset_id)
    release_notes += '##### Published on {}\n{}'.format(datetime.datetime.now().strftime("%d %B %Y"), res)
    content_descriptor = {
        "installDate": "0001-01-01T00:00:00Z",
        "assetId": int(asset_id),
        "releaseNotes": release_notes,
        "modified": date,
        "ignoreGit": False,
        "releaseDate": date,
        "version": -1,
        "release": version,
        "id": ""
    }

    draft = get_release_notes_draft(github_token, asset_id)
    if draft:
        content_descriptor['releaseNotes'] = draft

    with open('content-descriptor.json', 'w') as outfile:
        json.dump(content_descriptor, outfile)

    with open('release-notes.md', 'w') as outfile:
        outfile.write(release_notes)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('version', help='Release version')
    arg_parser.add_argument('git_sha1', help='commit sha1 to compare changes with')
    arg_parser.add_argument('asset_id', help='Asset ID')
    arg_parser.add_argument('server_version', help='Server version')
    arg_parser.add_argument('github_token', help='Github token')
    args = arg_parser.parse_args()

    tag = get_last_release_version()
    print('Last release version: {}'.format(tag))

    # get changed yaml/json files (filter only relevant changed files)
    fv = FilesValidator()
    change_log = run_command('git diff --name-status {}'.format(args.git_sha1))
    modified_files, added_files, removed_files, _ = fv.get_modified_files(change_log)
    modified_files, added_files, removed_files = filter_packagify_changes(modified_files, added_files,
                                                                          removed_files, tag=tag)
    deleted_data = run_command('git diff --diff-filter=D {}'.format(args.git_sha1))

    for file_path in added_files:
        create_file_release_notes('A', file_path, deleted_data)

    for file_path in modified_files:
        create_file_release_notes('M', file_path, deleted_data)

    for file_path in removed_files:
        create_file_release_notes('D', file_path, deleted_data)

    # join all release notes
    res = []
    missing_release_notes = False
    for key in RELEASE_NOTES_ORDER:
        value = release_note_generator[key]
        ans = value.generate_release_notes(args.server_version)
        if ans is None or value.is_missing_release_notes:
            missing_release_notes = True
        if ans:
            res.append(ans)

    release_notes = "\n---\n".join(res)
    create_content_descriptor(args.version, args.asset_id, release_notes, args.github_token)

    if missing_release_notes:
        print_error("Error: some release notes are missing. See previous errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
